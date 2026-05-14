import sqlite3
import os
import json
from datetime import datetime, timezone
import pandas as pd
from response_engine import (
    format_response_block,
)
from schema import create_db

# This script is used to test the database connection and verify that the threat_memory table was created successfully.
# It also inserts a mock entry into the table and retrieves all entries to confirm that the data is being stored correctly.
# Run this script after running schema.py to set up the database. You should see the mock entry printed in the output.
# It has a check so that you don't accidentally insert the mock entry multiple times if you run this script more than once.

# Version 2: Insert Function, store response block in log folder if provided

EXPLAINABILITY_COLUMNS = {
    "feature_deviations": "TEXT DEFAULT '[]'",
    "deviation_score": "REAL DEFAULT 0",
    "explanation_summary": "TEXT DEFAULT ''",
}


def _ensure_explainability_columns(conn):
    cursor = conn.execute("PRAGMA table_info(threat_events)")
    existing_columns = {row[1] for row in cursor.fetchall()}

    for column_name, column_def in EXPLAINABILITY_COLUMNS.items():
        if column_name not in existing_columns:
            conn.execute(f"ALTER TABLE threat_events ADD COLUMN {column_name} {column_def}")


def db_insert_events(
    anomaly_type: str,
    ip: str,
    error: float,
    risk,
    recommendation,
    feature_deviations=None,
    deviation_score: float = 0.0,
    explanation_summary: str = "",
):
    entry_id = None
    try:
        if not os.path.exists("threat_memory.db"):
            create_db()

        feature_deviations_json = json.dumps(feature_deviations or [])

        with sqlite3.connect("threat_memory.db") as conn:
            _ensure_explainability_columns(conn)
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO threat_events
                (
                    timestamp, IP, anomaly_type, recon_error, risk_level, suggested_response,
                    feature_deviations, deviation_score, explanation_summary
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    ip,
                    anomaly_type,
                    round(error, 8),
                    risk.name,
                    recommendation.summary,
                    feature_deviations_json,
                    round(float(deviation_score), 8),
                    explanation_summary,
                ),
            )

            entry_id = cursor.lastrowid
    except Exception as exc:
        print(f"[WARN] DB write failed: {exc}")

    if risk.name != "Low" and risk.name != "Medium":

        log_dir = f"logs/response_logs"
        os.makedirs(log_dir, exist_ok=True)

        with open(f"{log_dir}/{entry_id}.txt", "w", encoding="utf-8") as f:
            f.write(format_response_block(recommendation, ip))

# Version 2.1 Read Database: concurrent IP addresses
def db_read():
    with sqlite3.connect("threat_memory.db") as conn:
        cursor = conn.cursor()

        # repeated IPs
        cursor.execute("""
            SELECT IP, COUNT(*)
            FROM threat_events
            GROUP BY IP
            HAVING COUNT(*) > 1
            ORDER BY COUNT(*) DESC
        """)
        repeated_ips = cursor.fetchall()

        # repeated anomaly types per IP
        cursor.execute("""
            SELECT IP, anomaly_type, COUNT(*)
            FROM threat_events
            GROUP BY IP, anomaly_type
            HAVING COUNT(*) >= 3
            ORDER BY COUNT(*) DESC
        """)
        repeated_anomalies = cursor.fetchall()

    return repeated_ips, repeated_anomalies

def write_summary(state):
    repeated_ips, repeated_anomalies = state

    with open("logs/summary.txt", "w", encoding="utf-8") as f:
        f.write("Threat Summary\n\n")

        f.write("Repeated IPs:\n")
        if repeated_ips:
            for ip, count in repeated_ips:
                f.write(f"{ip:<15} | {count} events\n")
        else:
            f.write("None\n")

        f.write("\nRepeated anomaly types:\n")
        if repeated_anomalies:
            for ip, anomaly, count in repeated_anomalies:
                f.write(f"{ip:<15} | {anomaly:<20} | {count} times\n")
        else:
            f.write("None\n")

# Version 2.2 adding insert for threshold table
def save_threshold(threshold: float):

    if not os.path.exists("threat_memory.db"):
        create_db()

    with sqlite3.connect("threat_memory.db") as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO user_thresholds (user_id, threshold)
            VALUES (?, ?)
            """,
            ("current_user", threshold)
        )

def load_threshold():
    with sqlite3.connect("threat_memory.db") as conn:
        cursor = conn.execute(
            "SELECT threshold FROM user_thresholds WHERE user_id = ?",
            ("current_user",)
        )
        row = cursor.fetchone()

    if row:
        return row[0]
    else:
        return 334.522111

# Version 3.0 adding db read for dashboard tabs
def db_read_risk_counts():
    conn = sqlite3.connect("threat_memory.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT risk_level, COUNT(*)
    FROM threat_events
    GROUP BY risk_level
    """)

    results = cursor.fetchall()

    conn.close()

    risk_counts = {
        "Medium": 0,
        "High": 0,
        "Critical": 0
    }

    for risk, count in results:
        if risk in risk_counts:
            risk_counts[risk] = count

    return risk_counts

def db_read_history():
    return db_query_history()

def db_query_history(risk_levels=None, source_ip: str = "", anomaly_type: str = "", limit: int = 250):
    with sqlite3.connect("threat_memory.db") as conn:
        cursor = conn.execute("PRAGMA table_info(threat_events)")
        existing_columns = {row[1] for row in cursor.fetchall()}

        feature_deviations_expr = (
            "feature_deviations"
            if "feature_deviations" in existing_columns
            else "'[]' AS feature_deviations"
        )
        deviation_score_expr = (
            "deviation_score"
            if "deviation_score" in existing_columns
            else "0 AS deviation_score"
        )
        explanation_summary_expr = (
            "explanation_summary"
            if "explanation_summary" in existing_columns
            else "'' AS explanation_summary"
        )

        query = f"""
            SELECT
                id, timestamp, IP, anomaly_type, recon_error, risk_level, suggested_response,
                {feature_deviations_expr}, {deviation_score_expr}, {explanation_summary_expr}
            FROM threat_events
        """
        clauses = []
        params = []

        if risk_levels:
            placeholders = ", ".join("?" for _ in risk_levels)
            clauses.append(f"risk_level IN ({placeholders})")
            params.extend(risk_levels)

        if source_ip:
            clauses.append("IP LIKE ?")
            params.append(f"%{source_ip}%")

        if anomaly_type:
            clauses.append("anomaly_type LIKE ?")
            params.append(f"%{anomaly_type}%")

        if clauses:
            query += " WHERE " + " AND ".join(clauses)

        query += " ORDER BY id DESC LIMIT ?"
        params.append(max(1, int(limit)))

        return pd.read_sql_query(query, conn, params=params)

def db_increment_low_count():
    """Increments a counter for Low-risk events to track the FPR denominator."""
    try:
        with sqlite3.connect("threat_memory.db") as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE general_metrics SET metric_value = metric_value + 1 WHERE metric_name = 'low_risk_events'")
            conn.commit()
    except Exception as exc:
        print(f"[WARN] Failed to increment low count: {exc}")

def db_get_low_count():
    """Retrieves the count of Low-risk events for FPR calculation."""
    try:
        with sqlite3.connect("threat_memory.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT metric_value FROM general_metrics WHERE metric_name = 'low_risk_events'")
            row = cursor.fetchone()
            return row[0] if row else 0
    except:
        return 0

def db_read_metrics():
    with sqlite3.connect("threat_memory.db") as conn:
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM threat_events")
        total_alerts = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT IP) FROM threat_events")
        unique_ips = cursor.fetchone()[0]

        cursor.execute("""
            SELECT COUNT(*)
            FROM (
                SELECT IP
                FROM threat_events
                GROUP BY IP
                HAVING COUNT(*) > 1
            )
        """)
        repeated_ip_count = cursor.fetchone()[0]

        cursor.execute("SELECT MAX(timestamp) FROM threat_events")
        latest_detection = cursor.fetchone()[0]

    return {
        "total_alerts": total_alerts,
        "unique_ips": unique_ips,
        "repeated_ip_count": repeated_ip_count,
        "latest_detection": latest_detection or "None"
    }
