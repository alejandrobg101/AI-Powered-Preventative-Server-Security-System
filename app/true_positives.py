"""Calculate detection rate and latency for known attack time windows.

Edit RAW_ATTACKS with local Puerto Rico timestamps from your test run. The
script converts each window to UTC, reads stored alerts, and treats Medium or
higher risk as a valid detection.
"""

import sqlite3
from datetime import datetime
import zoneinfo

try:
    from .paths import db_path
except ImportError:
    from paths import db_path

# 1. ENTER YOUR LOCAL PUERTO RICO TIMES HERE
# Format: YYYY-MM-DD HH:MM:SS
RAW_ATTACKS = [
    { "name": "Attack 1 - ICMP Flood", "start": "2026-05-12 17:22:19", "end": "2026-05-12 17:31:00"},
    { "name": "Attack 2 - Parallel ICMP Burst", "start": "2026-05-12 17:33:00", "end": "2026-05-12 17:34:00" },
    { "name": "Attack 3 - TCP Port Scan", "start": "2026-05-12 17:34:30", "end": "2026-05-12 17:37:10" },
    { "name": "Attack 4 - UDP Burst", "start": "2026-05-12 17:37:11", "end": "2026-05-12 17:39:15" },
    { "name": "Attack 5 - HTTP Connection Burst", "start": "2026-05-12 17:39:20", "end": "2026-05-12 17:47:20" },
]

def pr_to_utc(local_time_str):
    """Converts Puerto Rico time string to UTC string for DB queries."""
    pr_tz = zoneinfo.ZoneInfo("America/Puerto_Rico")
    local_dt = datetime.strptime(local_time_str, "%Y-%m-%d %H:%M:%S")
    local_dt = local_dt.replace(tzinfo=pr_tz)
    utc_dt = local_dt.astimezone(zoneinfo.ZoneInfo("UTC"))
    return utc_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

def parse_time(t):
    """Parse the UTC timestamp format stored in threat_memory.db."""
    return datetime.strptime(t, "%Y-%m-%d %H:%M:%S UTC")


def get_rows(start, end):
    """Fetch stored alerts between two UTC timestamp strings."""
    with sqlite3.connect(db_path()) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, IP, anomaly_type, recon_error, risk_level, suggested_response
            FROM threat_events
            WHERE timestamp BETWEEN ? AND ?
            ORDER BY timestamp ASC
        """, (start, end))
        return cursor.fetchall()

def summarize(rows):
    """Count rows by (anomaly_type, risk_level) for per-window reporting."""
    counts = {}
    for row in rows:
        anomaly_type = row[3]
        risk_level = row[5]
        key = (anomaly_type, risk_level)
        counts[key] = counts.get(key, 0) + 1
    return counts

def is_positive(row):
    """Return True when an alert is considered a detection."""
    # UPDATED: Now includes Medium alerts as a 'positive' detection
    return row[5] in ("Medium", "High", "Critical")

if __name__ == "__main__":
    ATTACKS = [
        {
            "name": a["name"],
            "start": pr_to_utc(a["start"]),
            "end": pr_to_utc(a["end"])
        }
        for a in RAW_ATTACKS
    ]

    detected_attacks = 0
    missed_attacks = 0
    total_positives_count = 0
    latencies = []

    for attack in ATTACKS:
        rows = get_rows(attack["start"], attack["end"])
        positives = [row for row in rows if is_positive(row)]

        print("\n" + "=" * 75)
        print(attack["name"])
        print(f"Window (UTC): {attack['start']} -> {attack['end']}")
        print("=" * 75)

        print(f"Total alerts in window:       {len(rows)}")
        print(f"Detections (Med/High/Crit):   {len(positives)}")
        print(f"Low/Info alerts ignored:      {len([r for r in rows if r[5] not in ('Medium', 'High', 'Critical')])}")

        print("\nSummary by anomaly type/risk:")
        summary = summarize(rows)
        if summary:
            for (anomaly, risk), count in summary.items():
                print(f"  {anomaly:<28} {risk:<10} {count}")
        else:
            print("  No alerts found.")

        if positives:
            detected_attacks += 1
            total_positives_count += len(positives)

            first = positives[0]
            latency = (parse_time(first[1]) - parse_time(attack["start"])).total_seconds()
            latencies.append(latency)

            print("\nFirst Valid Detection (Min. Medium):")
            print(f"  ID:      {first[0]}")
            print(f"  Time:    {first[1]}")
            print(f"  Type:    {first[3]}")
            print(f"  Risk:    {first[5]}")
            print(f"  Latency: {latency:.0f} seconds")
        else:
            missed_attacks += 1
            print("\nResult: MISSED (No Medium or higher alerts found)")

    total_attacks = len(ATTACKS)
    detection_rate = detected_attacks / total_attacks
    false_negative_rate = missed_attacks / total_attacks

    print("\n" + "=" * 75)
    print("FINAL ATTACK TEST RESULTS (Med/High/Critical Included)")
    print("=" * 75)
    print(f"Total attack scenarios:               {total_attacks}")
    print(f"Detected attack scenarios (TP):       {detected_attacks}")
    print(f"Missed attack scenarios (FN):         {missed_attacks}")
    print(f"Detection rate / TPR:                 {detection_rate:.2%}")
    print(f"False negative rate:                  {false_negative_rate:.2%}")
    print(f"Total valid detection events:         {total_positives_count}")

    if latencies:
        print(f"Average latency:                      {sum(latencies) / len(latencies):.1f} seconds")
        print(f"Best latency:                         {min(latencies):.0f} seconds")
        print(f"Worst latency:                        {max(latencies):.0f} seconds")

    print("\nNote: Analysis now includes Medium-risk alerts as valid detections.")
