import sqlite3
from datetime import datetime

DB_PATH = "threat_memory.db"

# Define attack scenarios with their respective time windows (in UTC)
# Replace the times with your own attack scenario windows as needed
# I suggest that each attack has a window you set. You can get a start and end from CMD or PowerShell
# The times that PowerShell or CMD give you might be in local time, so convert them to UTC before using here.
ATTACKS = [
    {
        "name": "Attack 1 - Continuous ICMP Ping",
        "start": "2026-05-05 00:10:53 UTC",
        "end": "2026-05-05 00:11:30 UTC",
    },
    {
        "name": "Attack 2 - Parallel ICMP Ping Burst",
        "start": "2026-05-05 00:13:06 UTC",
        "end": "2026-05-05 00:14:00 UTC",
    },
    {
        "name": "Attack 3 - UDP Burst",
        "start": "2026-05-05 00:16:54 UTC",
        "end": "2026-05-05 00:17:10 UTC",
    },
    {
        "name": "Attack 4 - TCP Port Scan Simulation",
        "start": "2026-05-05 00:40:59 UTC",
        "end": "2026-05-05 00:45:01 UTC",
    },
    {
        "name": "Attack 5 - TCP Port 80 Connection Burst",
        "start": "2026-05-05 00:50:28 UTC",
        "end": "2026-05-05 00:52:07 UTC",
    },
]


def parse_time(t):
    return datetime.strptime(t, "%Y-%m-%d %H:%M:%S UTC")


def get_rows(start, end):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, timestamp, IP, anomaly_type, recon_error, risk_level, suggested_response
            FROM threat_events
            WHERE timestamp BETWEEN ? AND ?
            ORDER BY timestamp ASC
        """, (start, end))
        return cursor.fetchall()


def summarize(rows):
    counts = {}
    for row in rows:
        anomaly_type = row[3]
        risk_level = row[5]
        key = (anomaly_type, risk_level)
        counts[key] = counts.get(key, 0) + 1
    return counts


def is_positive(row):
    return row[5] in ("High", "Critical")


if __name__ == "__main__":
    detected_attacks = 0
    missed_attacks = 0
    total_high_critical_events = 0
    latencies = []

    for attack in ATTACKS:
        rows = get_rows(attack["start"], attack["end"])
        positives = [row for row in rows if is_positive(row)]

        print("\n" + "=" * 75)
        print(attack["name"])
        print(f"Window: {attack['start']} -> {attack['end']}")
        print("=" * 75)

        print(f"Total alerts in window:       {len(rows)}")
        print(f"High/Critical detections:     {len(positives)}")
        print(f"Medium alerts ignored:        {len([r for r in rows if r[5] == 'Medium'])}")

        print("\nSummary by anomaly type/risk:")
        summary = summarize(rows)
        if summary:
            for (anomaly, risk), count in summary.items():
                print(f"  {anomaly:<28} {risk:<10} {count}")
        else:
            print("  No alerts found.")

        if positives:
            detected_attacks += 1
            total_high_critical_events += len(positives)

            first = positives[0]
            latency = (parse_time(first[1]) - parse_time(attack["start"])).total_seconds()
            latencies.append(latency)

            print("\nFirst High/Critical detection:")
            print(f"  ID:      {first[0]}")
            print(f"  Time:    {first[1]}")
            print(f"  Type:    {first[3]}")
            print(f"  Risk:    {first[5]}")
            print(f"  Error:   {first[4]}")
            print(f"  Latency: {latency:.0f} seconds")
        else:
            missed_attacks += 1
            print("\nResult: MISSED as High/Critical detection")

    total_attacks = len(ATTACKS)
    detection_rate = detected_attacks / total_attacks
    false_negative_rate = missed_attacks / total_attacks

    print("\n" + "=" * 75)
    print("FINAL ATTACK TEST RESULTS")
    print("=" * 75)
    print(f"Total attack scenarios:              {total_attacks}")
    print(f"Detected attack scenarios (TP):       {detected_attacks}")
    print(f"Missed attack scenarios (FN):         {missed_attacks}")
    print(f"Detection rate / TPR:                 {detection_rate:.2%}")
    print(f"False negative rate:                  {false_negative_rate:.2%}")
    print(f"Total High/Critical detection events: {total_high_critical_events}")

    if latencies:
        print(f"Average latency:                      {sum(latencies) / len(latencies):.1f} seconds")
        print(f"Best latency:                         {min(latencies):.0f} seconds")
        print(f"Worst latency:                        {max(latencies):.0f} seconds")
        print(f"All latencies under 60 sec?:          {all(l <= 60 for l in latencies)}")

    print("\nNote: Medium alerts are treated as normal/low-confidence signals.")
    print("FP rate requires a separate normal-only test window.")