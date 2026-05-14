import os
import json

import streamlit as st
from streamlit_autorefresh import st_autorefresh
from db_functions import db_query_history, db_read_risk_counts, db_read_metrics
from live_alert_feed import read_live_alerts

REFRESH_INTERVAL_MS = 2000
LIVE_FEED_LIMIT = 100

st_autorefresh(interval=REFRESH_INTERVAL_MS, key="live_refresh")

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

def endpoint(ip: str, port: int) -> str:
    return f"{ip}:{port}" if port else ip

def parse_feature_deviations(value):
    if isinstance(value, list):
        return value
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    return parsed if isinstance(parsed, list) else []

def render_feature_deviations(deviations, limit: int = 5) -> None:
    if not deviations:
        st.info("No feature deviation evidence stored for this event.")
        return

    rows = []
    for item in deviations[:limit]:
        rows.append({
            "Feature": item.get("feature", ""),
            "Raw": round(float(item.get("raw_value", 0.0)), 4),
            "Z-score": round(float(item.get("z_score", 0.0)), 4),
            "Direction": item.get("direction", ""),
        })

    st.dataframe(rows, width="stretch", hide_index=True)

def render_live_feed(alerts: list[dict]) -> None:
    if not alerts:
        st.info("No live events recorded yet.")
        return

    latest = alerts[0]
    high_priority_count = sum(1 for alert in alerts if alert["risk"] in ("High", "Critical"))

    col1, col2, col3 = st.columns(3)
    col1.metric("Recent Events", len(alerts))
    col2.metric("High/Critical", high_priority_count)
    col3.metric("Latest Risk", latest["risk"])

    st.caption(f"Latest detection: {latest['timestamp']}")

    rows = []
    for alert in alerts:
        rows.append({
            "Time": alert["timestamp"],
            "Risk": alert["risk"],
            "Source": endpoint(alert["src_ip"], alert["src_port"]),
            "Destination": endpoint(alert["dst_ip"], alert["dst_port"]),
            "Protocol": alert["protocol"],
            "Packets": alert["packets"],
            "Bytes": alert["bytes"],
            "Error": round(alert["error"], 6),
            "Deviation Score": round(alert["deviation_score"], 4),
            "Type": alert["type"],
        })

    st.dataframe(rows, width="stretch", hide_index=True)

    with st.expander("Latest event details", expanded=True):
        col_left, col_right = st.columns([1, 1])

        with col_left:
            st.markdown("**Event Details**")
            st.markdown(f"- **Time:** {latest['timestamp']}")
            st.markdown(f"- **Risk:** {risk_badge(latest['risk'])}")
            st.markdown(f"- **Source:** `{endpoint(latest['src_ip'], latest['src_port'])}`")
            st.markdown(f"- **Destination:** `{endpoint(latest['dst_ip'], latest['dst_port'])}`")
            st.markdown(f"- **Protocol:** {latest['protocol']}")
            st.markdown(f"- **Packets:** {latest['packets']}")
            st.markdown(f"- **Bytes:** {latest['bytes']}")
            st.markdown(f"- **Reconstruction Error:** `{latest['error']:.6f}`")
            st.markdown(f"- **Deviation Score:** `{latest['deviation_score']:.4f}`")

        with col_right:
            st.markdown("**Classification**")
            st.markdown(f"- **Type:** {latest['type']}")
            if latest["explanation_summary"]:
                st.markdown(f"- **Explainability:** {latest['explanation_summary']}")
            if latest["recommendation"]:
                st.info(latest["recommendation"])

        st.markdown("**Top Feature Deviations**")
        render_feature_deviations(latest["feature_deviations"])
 
with tab_live:
    st.subheader("Live Events")
    render_live_feed(read_live_alerts(limit=LIVE_FEED_LIMIT))

with tab_risk:
    st.subheader("Risk-Level Indicators")

    risk_counts = db_read_risk_counts()

    col1, col2, col3 = st.columns(3)

    col1.metric("🟡 Medium Alerts", risk_counts["Medium"])
    col2.metric("🟠 High Alerts",   risk_counts["High"])
    col3.metric("🔴 Critical Alerts", risk_counts["Critical"])

with tab_history:
    st.subheader("Historical Log Table")

    filter_col1, filter_col2, filter_col3, filter_col4 = st.columns([1.2, 1, 1, 0.7])

    with filter_col1:
        selected_risks = st.multiselect(
            "Risk",
            ["Medium", "High", "Critical"],
            default=["Medium", "High", "Critical"],
        )
    with filter_col2:
        source_ip_filter = st.text_input("Source IP")
    with filter_col3:
        anomaly_filter = st.text_input("Anomaly Type")
    with filter_col4:
        row_limit = st.number_input("Rows", min_value=10, max_value=1000, value=250, step=10)

    events_df = db_query_history(
        risk_levels=selected_risks,
        source_ip=source_ip_filter.strip(),
        anomaly_type=anomaly_filter.strip(),
        limit=int(row_limit),
    )

    if events_df.empty:
        st.info("No historical anomaly logs match the current query.")
    else:
        display_df = events_df.copy()
        display_df["risk_level"] = display_df["risk_level"].map(
            lambda risk: f"{RISK_COLOR.get(risk, '⚪')} {risk}"
        )
        display_df["recon_error"] = display_df["recon_error"].map(lambda value: f"{value:.6f}")
        display_df["deviation_score"] = display_df["deviation_score"].map(lambda value: f"{value:.4f}")
        display_df = display_df[[
            "id",
            "timestamp",
            "IP",
            "anomaly_type",
            "risk_level",
            "recon_error",
            "deviation_score",
            "explanation_summary",
            "suggested_response",
        ]]
        display_df = display_df.rename(columns={
            "id": "ID",
            "timestamp": "Time",
            "IP": "Source IP",
            "anomaly_type": "Anomaly Type",
            "recon_error": "Reconstruction Error",
            "deviation_score": "Deviation Score",
            "risk_level": "Risk",
            "explanation_summary": "Explainability",
            "suggested_response": "Recommended Action",
        })

        st.dataframe(display_df, width="stretch", hide_index=True)

        selected_id = st.selectbox("Event ID", events_df["id"].astype(int).tolist())
        selected_event = events_df[events_df["id"] == selected_id].iloc[0]
        selected_risk = selected_event["risk_level"]
        selected_rec = selected_event["suggested_response"] or "No recommendation available."

        detail_col, response_col = st.columns([1, 1])

        with detail_col:
            st.markdown("**Event Details**")
            st.markdown(f"- **ID:** {selected_event['id']}")
            st.markdown(f"- **Time:** {selected_event['timestamp']}")
            st.markdown(f"- **Source IP:** `{selected_event['IP']}`")
            st.markdown(f"- **Type:** {selected_event['anomaly_type']}")
            st.markdown(f"- **Risk:** {risk_badge(selected_risk)}")
            st.markdown(f"- **Reconstruction Error:** `{selected_event['recon_error']:.6f}`")
            st.markdown(f"- **Deviation Score:** `{selected_event['deviation_score']:.4f}`")

        with response_col:
            st.markdown("**Recommended Action**")
            if selected_event["explanation_summary"]:
                st.markdown(f"**Explainability:** {selected_event['explanation_summary']}")
            st.info(selected_rec)

        st.markdown("**Top Feature Deviations**")
        render_feature_deviations(parse_feature_deviations(selected_event["feature_deviations"]))

        log_path = f"logs/response_logs/{int(selected_id)}.txt"
        if os.path.exists(log_path):
            st.markdown("**Full Response Log**")
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
