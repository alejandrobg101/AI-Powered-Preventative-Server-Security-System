import sqlite3
from datetime import datetime

DB_PATH = "threat_memory.db"

#NORMAL traffic window (converted to UTC) - 5 minutes of normal traffic
# Define scenarios with their respective time windows (in UTC)
# Replace the times with your own scenario windows as needed
# I suggest that each  has a window you set. You can get a start and end from CMD or PowerShell
# The times that PowerShell or CMD give you might be in local time, so convert them to UTC before using here.
NORMAL_START = "2026-05-05 01:50:33 UTC"
NORMAL_END   = "2026-05-05 01:56:08 UTC"


def get_rows(start, end):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, IP, anomaly_type, recon_error, risk_level
            FROM threat_events
            WHERE timestamp BETWEEN ? AND ?
            ORDER BY timestamp ASC
        """, (start, end))
        return cursor.fetchall()


def summarize(rows):
    counts = {}
    for row in rows:
        anomaly = row[3]
        risk = row[5]
        key = (anomaly, risk)
        counts[key] = counts.get(key, 0) + 1
    return counts


def is_false_positive(row):
    return row[5] in ("High", "Critical")


if __name__ == "__main__":
    print("=" * 70)
    print("FALSE POSITIVE TEST (NORMAL TRAFFIC)")
    print("=" * 70)
    print(f"Window: {NORMAL_START} -> {NORMAL_END}")

    rows = get_rows(NORMAL_START, NORMAL_END)

    total_alerts = len(rows)
    fp_rows = [row for row in rows if is_false_positive(row)]

    print("\nTotal alerts during normal traffic:", total_alerts)
    print("High/Critical alerts (False Positives):", len(fp_rows))

    print("\nSummary by anomaly type and risk:")
    summary = summarize(rows)

    if summary:
        for (anomaly, risk), count in summary.items():
            print(f"  {anomaly:<28} {risk:<10} {count}")
    else:
        print("  No alerts found.")

    # Scenario-level FP
    if len(fp_rows) > 0:
        fp_scenario = 1
    else:
        fp_scenario = 0

    print("\n" + "=" * 70)
    print("FALSE POSITIVE RESULT")
    print("=" * 70)
    print(f"Scenario-level False Positive (0 or 1): {fp_scenario}")

    if fp_scenario == 0:
        print("Result: No false positives detected during normal traffic.")
    else:
        print("Result: False positive detected during normal traffic.")
        print("\n" + "=" * 70)
    print("FALSE POSITIVE RESULT")
    print("=" * 70)
    print(f"Scenario-level False Positive (0 or 1): {fp_scenario}")

    if fp_scenario == 0:
        print("Result: No false positives detected during normal traffic.")
    else:
        print("Result: False positive detected during normal traffic.")

   
    if total_alerts > 0:
        fp_rate = len(fp_rows) / total_alerts
        print(f"\nEvent-level False Positive Rate: {fp_rate:.2%}")
    else:
        print("\nEvent-level False Positive Rate: N/A (no alerts recorded)")

    print("\nNote: Medium alerts are ignored as low-confidence signals.")

    print("\nNote: Medium alerts are ignored as low-confidence signals.")