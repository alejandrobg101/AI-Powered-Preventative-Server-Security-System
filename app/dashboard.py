import streamlit as st
import os
from streamlit_autorefresh import st_autorefresh
from db_functions import db_read_risk_counts, db_read_history, db_read_metrics

# auto refresh every 2 seconds
st_autorefresh(interval=10000, key="live_refresh")

st.title("AI Security Dashboard")

tab_live, tab_risk, tab_history, tab_metrics = st.tabs([
    "Live Events",
    "Risk Indicators",
    "Historical Logs",
    "Metrics"
])

RISK_COLOR = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
}
 
def risk_badge(risk: str) -> str:
    return f"{RISK_COLOR.get(risk, '⚪')} **{risk}**"

with tab_live:
    st.subheader("Live Events")

    live_file = "logs/live_alerts.txt"

    if os.path.exists(live_file):
        with open(live_file, "r", encoding="utf-8") as f:
            alerts = f.read()

        if alerts.strip():

            alert_blocks = alerts.strip().split("----------------------------------------")
            alert_blocks = [block.strip() for block in alert_blocks if block.strip()]
            alert_blocks.reverse()

            recent_first = "\n\n----------------------------------------\n\n".join(alert_blocks)

            st.code(recent_first, language="text")

        else:
            st.info("No live events recorded yet.")
    else:
        st.info("No live events file found yet.")

with tab_risk:
    st.subheader("Risk-Level Indicators")

    risk_counts = db_read_risk_counts()

    col1, col2, col3 = st.columns(3)

    col1.metric("🟡 Medium Alerts", risk_counts["Medium"])
    col2.metric("🟠 High Alerts",   risk_counts["High"])
    col3.metric("🔴 Critical Alerts", risk_counts["Critical"])

with tab_history:
    st.subheader("Historical Log Table")

    events_df = db_read_history()

    if events_df.empty:
        st.info("No stored threat events yet.")
    else:
        # ── NEW: Loop through each alert and render as an expandable card ──
        # Each card shows event details on the left and recommended action on the right
        for _, row in events_df.iterrows():
            risk  = row["risk_level"]
            badge = RISK_COLOR.get(risk, "⚪")
            rec   = row["suggested_response"] or "No recommendation available."

            # Card header shows risk, time, IP and anomaly type at a glance
            with st.expander(
                f"{badge} [{risk}]  |  {row['timestamp']}  |  {row['IP']}  →  {row['anomaly_type']}",
                expanded=False
            ):
                # ── Two columns: details left, recommendation right ──
                col_left, col_right = st.columns([1, 1])

                with col_left:
                    st.markdown("**Event Details**")
                    st.markdown(f"- **ID:** {row['id']}")
                    st.markdown(f"- **Time:** {row['timestamp']}")
                    st.markdown(f"- **Source IP:** `{row['IP']}`")
                    st.markdown(f"- **Type:** {row['anomaly_type']}")
                    st.markdown(f"- **Risk:** {risk_badge(risk)}")
                    st.markdown(f"- **Reconstruction Error:** `{row['recon_error']:.6f}`")

                with col_right:
                    st.markdown("**Recommended Action**")
                    # ── This is the key addition: shows suggested_response from DB ──
                    st.info(rec)

                # ── If a full response log exists for this event show it inline ──
                # Response logs are only created for High and Critical events
                log_path = f"logs/response_logs/{row['id']}.txt"
                if os.path.exists(log_path):
                    st.markdown("**Full Response Log**")
                    with open(log_path, "r", encoding="utf-8") as f:
                        st.code(f.read(), language="text")

        st.divider()

        # ── Raw dataframe still accessible but collapsed by default ──
        with st.expander("View raw table", expanded=False):
            st.dataframe(events_df, width="stretch")

        # ── Manual response log viewer kept for convenience ──
        st.subheader("Response Log Viewer")
        selected_id = st.number_input(
            "Enter event ID to view response log:",
            min_value=1,
            step=1
        )
        log_path = f"logs/response_logs/{int(selected_id)}.txt"
        if os.path.exists(log_path):
            with open(log_path, "r", encoding="utf-8") as f:
                st.code(f.read(), language="text")
        else:
            st.info("No response log exists for this event.")

with tab_metrics:
    st.subheader("Metrics Display")

    metrics = db_read_metrics()

    col1, col2, col3 = st.columns(3)

    col1.metric("Total Stored Alerts", metrics["total_alerts"])
    col2.metric("Unique Source IPs", metrics["unique_ips"])
    col3.metric("Repeated IP Count", metrics["repeated_ip_count"])

    st.write(f"Latest Detection: {metrics['latest_detection']}")