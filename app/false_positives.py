"""Calculate event-level false positives for a known-normal time window.

Edit NORMAL_START_PR and NORMAL_END_PR before running. The database stores UTC
timestamps, so this script converts Puerto Rico local time to UTC first.
"""

import sqlite3
from datetime import datetime
import zoneinfo

try:
    from .db_functions import db_get_low_count
    from .paths import db_path
except ImportError:
    from db_functions import db_get_low_count
    from paths import db_path

# ---------------------------------------------------------
# 1. SET YOUR NORMAL TRAFFIC WINDOW (Puerto Rico Time)
# ---------------------------------------------------------
NORMAL_START_PR = "2026-05-12 18:30:08" 
NORMAL_END_PR   = "2026-05-12 18:33:21"

def pr_to_utc(local_time_str):
    """Converts Puerto Rico time string to UTC string for DB queries."""
    pr_tz = zoneinfo.ZoneInfo("America/Puerto_Rico")
    local_dt = datetime.strptime(local_time_str, "%Y-%m-%d %H:%M:%S")
    local_dt = local_dt.replace(tzinfo=pr_tz)
    utc_dt = local_dt.astimezone(zoneinfo.ZoneInfo("UTC"))
    return utc_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

def get_rows(start, end):
    """Fetch stored alerts between two UTC timestamp strings."""
    with sqlite3.connect(db_path()) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, IP, anomaly_type, recon_error, risk_level
            FROM threat_events
            WHERE timestamp BETWEEN ? AND ?
            ORDER BY timestamp ASC
        """, (start, end))
        return cursor.fetchall()

def summarize(rows):
    """Count false-positive rows by (anomaly_type, risk_level)."""
    counts = {}
    for row in rows:
        anomaly = row[3]
        risk = row[5]
        key = (anomaly, risk)
        counts[key] = counts.get(key, 0) + 1
    return counts

def is_false_positive(row):
    """Return True when a stored alert is a mistake in the normal window."""
    # Medium, High, and Critical alerts are all FPs during normal traffic
    return row[5] in ("Medium", "High", "Critical")

if __name__ == "__main__":
    # Convert window to UTC for the database query
    NORMAL_START_UTC = pr_to_utc(NORMAL_START_PR)
    NORMAL_END_UTC   = pr_to_utc(NORMAL_END_PR)

    print("=" * 75)
    print("FALSE POSITIVE TEST (NORMAL TRAFFIC ANALYSIS)")
    print("=" * 75)
    print(f"Local Window (PR):  {NORMAL_START_PR} -> {NORMAL_END_PR}")
    print(f"Query Window (UTC): {NORMAL_START_UTC} -> {NORMAL_END_UTC}")

    # 1. Get Med/High/Crit "Mistakes" from the main table
    rows = get_rows(NORMAL_START_UTC, NORMAL_END_UTC)
    fp_rows = [row for row in rows if is_false_positive(row)]
    
    # 2. Get "Lows" (Correct Non-Detections) from the metrics table
    # Note: This count represents all Lows recorded by the live capture.
    low_count = db_get_low_count()

    print("\n--- Detection Results ---")
    print(f"Mistakes (Med/High/Crit):     {len(fp_rows)}")
    print(f"Correct (Low-risk recorded):  {low_count}")

    print("\nSummary of False Positives by Type:")
    summary = summarize(fp_rows)
    if summary:
        for (anomaly, risk), count in summary.items():
            print(f"  {anomaly:<28} {risk:<10} {count}")
    else:
        print("  No false positives detected. System is clean!")

    # 3. Calculate FPR
    # Formula: False Positives / (False Positives + True Negatives)
    numerator = len(fp_rows)
    denominator = numerator + low_count

    print("\n" + "=" * 75)
    print("FINAL FALSE POSITIVE METRICS")
    print("=" * 75)
    
    if denominator > 0:
        fp_rate = (numerator / denominator)
        print(f"Total Traffic Events Processed: {denominator}")
        print(f"Event-level False Positive Rate: {fp_rate:.2%}")

    else:
        print("Result: N/A - No traffic data found in DB or Metrics.")

    print("\nNote: This calculation treats Medium alerts as False Positives.")
    print("Ensure you reset the low_count if you want a fresh testing session.")
