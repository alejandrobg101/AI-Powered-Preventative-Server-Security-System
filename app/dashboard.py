"""Streamlit UI for local IDS operation.

The dashboard handles local login/register flows, starts and stops the live
capture subprocess, displays SQLite-backed alert data, and manages per-user
threshold calibration sessions.
"""

from datetime import datetime, timezone

import streamlit as st
from streamlit_autorefresh import st_autorefresh

try:
    from .auth import login_user, register_user
    from .db_functions import db_read_history, db_read_metrics, db_read_risk_counts, load_threshold
    from .paths import live_alerts_path, response_logs_dir
    from .schema import create_db
    from . import live_capture_manager
    from .threshold_calibrator import (
        get_calibration_status,
        get_user_latest_calibration,
        start_calibration,
        stop_calibration,
    )
except ImportError:
    from auth import login_user, register_user
    from db_functions import db_read_history, db_read_metrics, db_read_risk_counts, load_threshold
    from paths import live_alerts_path, response_logs_dir
    from schema import create_db
    import live_capture_manager
    from threshold_calibrator import (
        get_calibration_status,
        get_user_latest_calibration,
        start_calibration,
        stop_calibration,
    )

# Ensure all tables exist (idempotent; safe on every startup)
create_db()

# ── Session state defaults ───────────────────────────────────────────────────
for _key, _default in [
    ("logged_in", False),
    ("user_id", None),
    ("username", None),
    ("email", None),
    ("active_session_id", None),
]:
    if _key not in st.session_state:
        st.session_state[_key] = _default


def _refresh_interval() -> int:
    """Use a faster refresh rate while calibration is running."""
    sid = st.session_state.get("active_session_id")
    if sid:
        s = get_calibration_status(sid)
        if s and s["status"] == "running":
            return 3000
    return 10000


st_autorefresh(interval=_refresh_interval(), key="main_refresh")


# ── Helpers ──────────────────────────────────────────────────────────────────
RISK_COLOR = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}


def _badge(risk: str) -> str:
    """Return a small markdown risk badge for historical alert rows."""
    return f"{RISK_COLOR.get(risk, '⚪')} **{risk}**"


def _parse_db_time(ts: str) -> datetime:
    """Parse the UTC timestamp format used by db_functions.py."""
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)


# ── Auth page ────────────────────────────────────────────────────────────────
def _show_auth_page():
    """Render the unauthenticated login/register screen."""
    st.title("AI Security Dashboard")
    st.subheader("Sign in to your account")

    tab_login, tab_register = st.tabs(["Login", "Register"])

    with tab_login:
        with st.form("login_form"):
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign In", type="primary")

        if submitted:
            result = login_user(email, password)
            if result["success"]:
                user = result["user"]
                st.session_state.logged_in = True
                st.session_state.user_id = user["user_id"]
                st.session_state.username = user["username"]
                st.session_state.email = user["email"]
                # Restore any calibration that was running before
                latest = get_user_latest_calibration(user["user_id"])
                if latest and latest["status"] == "running":
                    st.session_state.active_session_id = latest["session_id"]
                st.rerun()
            else:
                st.error(result["error"])

    with tab_register:
        with st.form("register_form"):
            username = st.text_input("Username")
            email_r = st.text_input("Email", key="reg_email")
            pw = st.text_input("Password", type="password", key="reg_pw")
            pw2 = st.text_input("Confirm Password", type="password", key="reg_pw2")
            submitted_r = st.form_submit_button("Create Account", type="primary")

        if submitted_r:
            if pw != pw2:
                st.error("Passwords do not match.")
            else:
                result = register_user(username, email_r, pw)
                if result["success"]:
                    st.success(
                        f"Account created! Welcome, **{result['username']}**. "
                        "Switch to the Login tab to sign in."
                    )
                else:
                    st.error(result["error"])


# ── Threshold Adjuster tab ───────────────────────────────────────────────────
def _show_threshold_adjuster():
    """Render the calibration workflow for the logged-in user."""
    st.subheader("Threshold Adjuster")
    user_id = st.session_state.user_id

    current = load_threshold(user_id)
    st.info(f"**Current threshold for your account:** `{current:.6f}`")

    st.markdown("---")

    # Sync active session from DB in case of page reload
    session_id = st.session_state.get("active_session_id")
    session = get_calibration_status(session_id) if session_id else None

    if session is None:
        latest = get_user_latest_calibration(user_id)
        if latest and latest["status"] == "running":
            # Streamlit reloads the script on interaction. Persisting session id
            # in SQLite lets the progress UI reconnect after a refresh/login.
            st.session_state.active_session_id = latest["session_id"]
            session = latest

    is_running = session is not None and session["status"] == "running"

    # ── Controls ─────────────────────────────────────────────────────────────
    if not is_running:
        st.markdown(
            "Calibration sniffs your live network traffic for **4 minutes**, "
            "runs each flow through the anomaly-detection autoencoder, and sets "
            "your personal threshold at the **99th percentile** of the observed "
            "reconstruction errors. Use your network normally while it runs."
        )

        with st.expander("Advanced options", expanded=False):
            iface_input = st.text_input(
                "Network interface (leave blank for system default)",
                value="",
                help="Windows examples: 'Wi-Fi', 'Ethernet'. "
                     "Leave blank to let Scapy pick the default interface.",
            )

        col_btn, col_note = st.columns([1, 3])
        with col_btn:
            start_clicked = st.button("Run Threshold Adjuster", type="primary")
        with col_note:
            st.caption(
                "Requires administrator privileges for raw packet capture."
            )

        if start_clicked:
            iface = iface_input.strip() or None
            new_id = start_calibration(user_id, iface=iface)
            st.session_state.active_session_id = new_id
            st.rerun()

    else:
        # ── In-progress view ─────────────────────────────────────────────────
        duration = session["duration_seconds"] or 240
        started_at = session["started_at"]
        flow_count = session.get("sample_count") or 0

        try:
            elapsed = (datetime.now(timezone.utc) - _parse_db_time(started_at)).total_seconds()
        except Exception:
            elapsed = 0.0

        elapsed = max(0.0, min(float(elapsed), float(duration)))
        remaining = max(0, int(duration - elapsed))
        progress = elapsed / duration

        st.markdown("### Analyzing traffic...")
        st.progress(progress)

        c1, c2, c3 = st.columns(3)
        c1.metric("Flows Analyzed", flow_count)
        c2.metric("Elapsed", f"{int(elapsed // 60)}m {int(elapsed % 60):02d}s")
        c3.metric("Remaining", f"{remaining // 60}m {remaining % 60:02d}s")

        st.caption(
            f"Session `{session['session_id'][:8]}…`  |  Started: {started_at}"
        )

        if st.button("Stop Calibration", type="secondary"):
            stop_calibration(session["session_id"])
            st.session_state.active_session_id = None
            st.warning("Calibration stopped. No threshold changes were made.")
            st.rerun()

    st.markdown("---")

    # ── Previous result ───────────────────────────────────────────────────────
    if not is_running:
        latest = get_user_latest_calibration(user_id)
        if latest:
            _show_calibration_result(latest)


def _show_calibration_result(session: dict):
    """Render the final status block for the user's most recent calibration."""
    status = session["status"]
    if status == "completed":
        t = session.get("computed_threshold")
        n = session.get("sample_count") or 0
        st.success(
            f"**Last calibration completed successfully.**  "
            f"New threshold: `{t:.6f}` · {n} flows analyzed  "
            f"· Finished: {session.get('stopped_at', 'N/A')}"
        )
        st.caption(
            "This threshold is saved to your account. "
            "Restart live_capture.py to apply it to live detection."
        )
    elif status == "failed":
        err = session.get("error_message") or "Unknown error."
        st.error(f"**Last calibration failed.** {err}")
        if any(kw in err.lower() for kw in ("privilege", "permission", "admin", "access")):
            st.warning(
                "Packet capture requires administrator/root privileges. "
                "Run the dashboard as an administrator and try again."
            )
    elif status == "stopped":
        st.warning(
            f"**Last calibration was stopped early.** "
            f"No threshold changes were made. "
            f"Stopped: {session.get('stopped_at', 'N/A')}"
        )


# ── Main dashboard ───────────────────────────────────────────────────────────
def _show_main_dashboard():
    """Render all authenticated dashboard tabs."""
    st.title("AI Security Dashboard")

    with st.sidebar:
        st.markdown(f"**{st.session_state.username}**")
        st.caption(st.session_state.email)
        st.divider()
        if st.button("Sign Out"):
            st.session_state.logged_in = False
            st.session_state.user_id = None
            st.session_state.username = None
            st.session_state.email = None
            st.session_state.active_session_id = None
            st.rerun()

    (tab_live, tab_risk, tab_history, tab_metrics, tab_threshold) = st.tabs([
        "Live Events",
        "Risk Indicators",
        "Historical Logs",
        "Metrics",
        "Threshold Adjuster",
    ])

    # ── Live Events ───────────────────────────────────────────────────────────
    with tab_live:
        st.subheader("Live Events")

        # ── IDS controls ─────────────────────────────────────────────────────
        running = live_capture_manager.is_running()

        if running:
            st.success(f"IDS is running  ·  PID {live_capture_manager.pid()}")
            col_stop, col_iface = st.columns([1, 3])
            with col_stop:
                if st.button("Stop IDS", type="secondary"):
                    live_capture_manager.stop()
                    st.rerun()
        else:
            st.warning("IDS is not running.")
            with st.expander("Interface options", expanded=False):
                ids_iface = st.text_input(
                    "Network interface (leave blank for system default)",
                    key="ids_iface",
                    help="e.g. 'Wi-Fi' or 'Ethernet'. Leave blank to use the Scapy default.",
                )
            if st.button("Start IDS", type="primary"):
                # live_capture_manager starts live_capture.py with --no-dashboard
                # so the child process does not spawn another Streamlit server.
                live_capture_manager.start(iface=ids_iface.strip() or None)
                st.rerun()

        st.divider()

        # ── Alert feed ───────────────────────────────────────────────────────
        live_file = live_alerts_path()
        if live_file.exists():
            with open(live_file, "r", encoding="utf-8") as f:
                alerts = f.read()
            if alerts.strip():
                # live_capture.py separates alerts with a fixed dashed line.
                # Reverse blocks so the newest alert is shown at the top.
                blocks = [b.strip() for b in alerts.strip().split("----------------------------------------") if b.strip()]
                blocks.reverse()
                st.code("\n\n----------------------------------------\n\n".join(blocks), language="text")
            else:
                st.info("No live events recorded yet.")
        else:
            st.info("No live events file found yet.")

    # ── Risk Indicators ───────────────────────────────────────────────────────
    with tab_risk:
        st.subheader("Risk-Level Indicators")
        risk_counts = db_read_risk_counts()
        c1, c2, c3 = st.columns(3)
        c1.metric("🟡 Medium Alerts", risk_counts["Medium"])
        c2.metric("🟠 High Alerts", risk_counts["High"])
        c3.metric("🔴 Critical Alerts", risk_counts["Critical"])

    # ── Historical Logs ───────────────────────────────────────────────────────
    with tab_history:
        st.subheader("Historical Log Table")
        events_df = db_read_history()
        if events_df.empty:
            st.info("No stored threat events yet.")
        else:
            for _, row in events_df.iterrows():
                risk = row["risk_level"]
                badge = RISK_COLOR.get(risk, "⚪")
                rec = row["suggested_response"] or "No recommendation available."
                with st.expander(
                    f"{badge} [{risk}]  |  {row['timestamp']}  |  {row['IP']}  →  {row['anomaly_type']}",
                    expanded=False,
                ):
                    col_left, col_right = st.columns([1, 1])
                    with col_left:
                        st.markdown("**Event Details**")
                        st.markdown(f"- **ID:** {row['id']}")
                        st.markdown(f"- **Time:** {row['timestamp']}")
                        st.markdown(f"- **Source IP:** `{row['IP']}`")
                        st.markdown(f"- **Type:** {row['anomaly_type']}")
                        st.markdown(f"- **Risk:** {_badge(risk)}")
                        st.markdown(f"- **Reconstruction Error:** `{row['recon_error']:.6f}`")
                    with col_right:
                        st.markdown("**Recommended Action**")
                        st.info(rec)
                    log_path = response_logs_dir() / f"{row['id']}.txt"
                    if log_path.exists():
                        st.markdown("**Full Response Log**")
                        with open(log_path, "r", encoding="utf-8") as f:
                            st.code(f.read(), language="text")

            st.divider()
            with st.expander("View raw table", expanded=False):
                st.dataframe(events_df, width="stretch")

            st.subheader("Response Log Viewer")
            selected_id = st.number_input("Enter event ID to view response log:", min_value=1, step=1)
            log_path = response_logs_dir() / f"{int(selected_id)}.txt"
            if log_path.exists():
                with open(log_path, "r", encoding="utf-8") as f:
                    st.code(f.read(), language="text")
            else:
                st.info("No response log exists for this event.")

    # ── Metrics ───────────────────────────────────────────────────────────────
    with tab_metrics:
        st.subheader("Metrics Display")
        metrics = db_read_metrics()
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Stored Alerts", metrics["total_alerts"])
        c2.metric("Unique Source IPs", metrics["unique_ips"])
        c3.metric("Repeated IP Count", metrics["repeated_ip_count"])
        st.write(f"Latest Detection: {metrics['latest_detection']}")

    # ── Threshold Adjuster ────────────────────────────────────────────────────
    with tab_threshold:
        _show_threshold_adjuster()


# ── Entry point ───────────────────────────────────────────────────────────────
if not st.session_state.logged_in:
    _show_auth_page()
else:
    _show_main_dashboard()
