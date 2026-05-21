"""Database access helpers for the IDS application.

All paths in this module are intentionally relative to the current working
directory. The application is normally launched from app/, so these helpers
read and write app/threat_memory.db and app/logs/.
"""

import sqlite3
from datetime import datetime, timezone
import pandas as pd

try:
    from .paths import db_path, ensure_runtime_dirs, response_logs_dir
    from .response_engine import format_response_block
    from .schema import create_db
except ImportError:
    from paths import db_path, ensure_runtime_dirs, response_logs_dir
    from response_engine import format_response_block
    from schema import create_db


def db_insert_events(anomaly_type: str, ip: str, error: float, risk, recommendation):
    """Persist a non-low alert and write a response log for High/Critical risk.

    live_capture.py only calls this for risk.code > 0, so Low events stay out of
    threat_events. The risk object is the RiskLevel dataclass from
    risk_classifier.py; recommendation is the Recommendation dataclass from
    response_engine.py.
    """
    entry_id = None
    try:
        with sqlite3.connect(db_path()) as conn:
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

    if entry_id is not None and risk.name != "Low" and risk.name != "Medium":
        # High and Critical alerts get an operator-facing response playbook.
        # The file is named after the SQLite row id so the dashboard can find it.
        log_dir = response_logs_dir()
        log_dir.mkdir(parents=True, exist_ok=True)

        with open(log_dir / f"{entry_id}.txt", "w", encoding="utf-8") as f:
            f.write(format_response_block(recommendation, ip))


def db_read():
    """Return repeated IP and repeated anomaly summaries for text reports."""
    with sqlite3.connect(db_path()) as conn:
        cursor = conn.cursor()

        # IPs with more than one stored alert.
        cursor.execute("""
            SELECT IP, COUNT(*)
            FROM threat_events
            GROUP BY IP
            HAVING COUNT(*) > 1
            ORDER BY COUNT(*) DESC
        """)
        repeated_ips = cursor.fetchall()

        # IP/anomaly combinations that repeat often enough to be interesting.
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
    """Write a plain-text rollup used by older CLI workflows."""
    repeated_ips, repeated_anomalies = state

    ensure_runtime_dirs()
    with open(response_logs_dir().parent / "summary.txt", "w", encoding="utf-8") as f:
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


def save_threshold(threshold: float, user_id: str = "current_user"):
    """Save a user-specific reconstruction-error threshold.

    The default user_id mirrors the CLI live-capture workflow, while the
    dashboard passes real user ids from auth.py.
    """
    if not db_path().exists():
        create_db()

    with sqlite3.connect(db_path()) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO user_thresholds (user_id, threshold)
            VALUES (?, ?)
            """,
            (user_id, threshold)
        )


def load_threshold(user_id: str = "current_user"):
    """Load a saved threshold, falling back to the shipped artifact value."""
    with sqlite3.connect(db_path()) as conn:
        cursor = conn.execute(
            "SELECT threshold FROM user_thresholds WHERE user_id = ?",
            (user_id,)
        )
        row = cursor.fetchone()

    if row:
        return row[0]
    else:
        return 334.522111


def db_read_risk_counts():
    """Return dashboard-ready counts for Medium/High/Critical stored alerts."""
    conn = sqlite3.connect(db_path())
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
    """Return the full stored alert table in newest-first order."""
    conn = sqlite3.connect(db_path())
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
        with sqlite3.connect(db_path()) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE general_metrics SET metric_value = metric_value + 1 WHERE metric_name = 'low_risk_events'")
            conn.commit()
    except Exception as exc:
        print(f"[WARN] Failed to increment low count: {exc}")


def db_get_low_count():
    """Retrieves the count of Low-risk events for FPR calculation."""
    try:
        with sqlite3.connect(db_path()) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT metric_value FROM general_metrics WHERE metric_name = 'low_risk_events'")
            row = cursor.fetchone()
            return row[0] if row else 0
    except:
        return 0


def db_read_metrics():
    """Return aggregate metrics used by the dashboard Metrics tab."""
    with sqlite3.connect(db_path()) as conn:
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
