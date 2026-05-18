import sqlite3
import os
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

def db_insert_events(anomaly_type: str, ip: str, error: float, risk, recommendation):
    entry_id = None
    try:
        with sqlite3.connect("threat_memory.db") as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                INSERT INTO threat_events
                (timestamp, IP, anomaly_type, recon_error, risk_level, suggested_response)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
                    ip,
                    anomaly_type,
                    round(error, 8),
                    risk.name,
                    recommendation.summary,
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
def save_threshold(threshold: float, user_id: str = "current_user"):

    if not os.path.exists("threat_memory.db"):
        create_db()

    with sqlite3.connect("threat_memory.db") as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO user_thresholds (user_id, threshold)
            VALUES (?, ?)
            """,
            (user_id, threshold)
        )

def load_threshold(user_id: str = "current_user"):
    with sqlite3.connect("threat_memory.db") as conn:
        cursor = conn.execute(
            "SELECT threshold FROM user_thresholds WHERE user_id = ?",
            (user_id,)
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
    conn = sqlite3.connect("threat_memory.db")
    df = pd.read_sql_query(
        """
        SELECT id, timestamp, IP, anomaly_type, recon_error, risk_level, suggested_response
        FROM threat_events
        ORDER BY id DESC
        """,
        conn
    )
    conn.close()
    return df

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