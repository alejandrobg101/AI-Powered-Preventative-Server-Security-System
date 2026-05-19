"""
sim_abnormal_process.py
-----------------------
Simulation: Abnormal Process Execution

Models two network-observable behaviours that indicate a rogue or injected
process running on the host:

  Mode A -- C2 beacon (Botnet pattern)
    A compromised process checking in with its command-and-control server
    at precisely regular intervals.  Matches the "Botnet" profile in
    fake_data.py: ~60 s IAT, tiny consistent payloads, very low byte rate.
    Maps to GENERIC_TCP_ANOMALY (low pkt_rate, high regularity).

  Mode B -- URG flag abuse / covert channel
    Some malware uses TCP URG flags or unusual flag combinations to signal
    out-of-band commands to a listener.  The IDS flags flows with elevated
    URG counts as UNKNOWN_ANOMALY (uncommon in benign traffic).

  Mode C -- Abnormal high-frequency DNS queries
    Malicious processes (info-stealers, DNS beacons) generate DNS-over-UDP
    query bursts far above baseline.  Maps to DNS_AMPLIFICATION or
    GENERIC_UDP_ANOMALY depending on query/response ratio.

Run all three modes sequentially or choose one with --mode.

Safety: all traffic targets 127.0.0.1 by default.
"""

import argparse
import random
import time

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, send, conf

BEACON_PAYLOAD  = b"\xc2\xbe\xac\x00" + b"\x00" * 28   # 32-byte beacon (fake C2 check-in)
URG_PAYLOAD     = b"\xde\xad\xc0\xde" + b"\x00" * 12   # 16-byte URG-flagged control packet
DNS_QUERY_NAMES = [
    b"telemetry.internal.corp",
    b"update.sys-monitor.io",
    b"beacon.c2-hidden.net",
    b"data.exfiltraton-pipe.cc",
    b"heartbeat.malware-c2.ru",
]


# ---- Mode A: C2 Beacon ------------------------------------------------------------------------------------------------------------------

def c2_beacon(src: str, dst: str, iface: str, intervals: int, beacon_period: float):
    """Send periodic tiny TCP packets mimicking botnet check-in behaviour."""
    sport = random.randint(49152, 65535)
    seq   = random.randint(10000, 99999)

    print(f"  [Beacon]  {src} -> {dst}:8443  every {beacon_period:.0f}s  ({intervals} check-ins)")

    # Establish a persistent low-volume connection
    send(IP(src=src, dst=dst) / TCP(sport=sport, dport=8443, flags="S",
                                     seq=seq, window=8192),
         iface=iface, verbose=False)
    seq += 1

    for i in range(intervals):
        send(
            IP(src=src, dst=dst) / TCP(sport=sport, dport=8443, flags="PA",
                                        seq=seq, ack=1, window=8192) / Raw(BEACON_PAYLOAD),
            iface=iface, verbose=False,
        )
        seq += len(BEACON_PAYLOAD)
        print(f"    Beacon #{i+1}/{intervals} sent  (next in {beacon_period:.0f}s)")
        time.sleep(beacon_period)

    send(IP(src=src, dst=dst) / TCP(sport=sport, dport=8443, flags="FA",
                                     seq=seq, ack=1, window=8192),
         iface=iface, verbose=False)
    print("  [Beacon]  Session closed.")


# ---- Mode B: URG flag abuse --------------------------------------------------------------------------------------------------------

def urg_covert_channel(src: str, dst: str, iface: str, packets: int, delay: float):
    """Send TCP packets with URG flag set -- unusual flag combination flagged by IDS."""
    sport = random.randint(49152, 65535)
    seq   = random.randint(10000, 99999)

    print(f"  [URG-Chan]  {src} -> {dst}:4444  ({packets} URG-flagged control packets)")

    send(IP(src=src, dst=dst) / TCP(sport=sport, dport=4444, flags="S",
                                     seq=seq, window=1024),
         iface=iface, verbose=False)
    seq += 1
    time.sleep(0.05)

    for i in range(packets):
        # URG + PSH + ACK -- signals out-of-band data, rarely seen in normal traffic
        send(
            IP(src=src, dst=dst) / TCP(sport=sport, dport=4444,
                                        flags="UPA",   # URG + PSH + ACK
                                        urgptr=len(URG_PAYLOAD),
                                        seq=seq, ack=1, window=1024) / Raw(URG_PAYLOAD),
            iface=iface, verbose=False,
        )
        seq += len(URG_PAYLOAD)
        time.sleep(delay)

    send(IP(src=src, dst=dst) / TCP(sport=sport, dport=4444, flags="FA",
                                     seq=seq, ack=1),
         iface=iface, verbose=False)
    print(f"  [URG-Chan]  {packets} URG packets sent.")


# ---- Mode C: Abnormal DNS burst ------------------------------------------------------------------------------------------------

def dns_beacon_burst(src: str, dns_server: str, iface: str, queries: int, delay: float):
    """Send a high-frequency DNS query burst -- rogue process DNS beaconing."""
    print(f"  [DNS-Burst]  {src} -> {dns_server}:53  ({queries} queries, {delay:.2f}s apart)")

    for i in range(queries):
        name = random.choice(DNS_QUERY_NAMES)
        sport = random.randint(1024, 65535)
        send(
            IP(src=src, dst=dns_server) / UDP(sport=sport, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=name)),
            iface=iface, verbose=False,
        )
        time.sleep(delay)

    print(f"  [DNS-Burst]  {queries} DNS queries sent.")


# ---- Main --------------------------------------------------------------------------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="IDS simulation -- abnormal process execution (beacon / URG / DNS burst)")
    parser.add_argument("--src", default="127.0.0.1",
                        help="Simulated process source IP (default: 127.0.0.1)")
    parser.add_argument("--dst", default="127.0.0.1",
                        help="Simulated C2 / DNS destination IP (default: 127.0.0.1)")
    parser.add_argument("--iface", default=conf.iface,
                        help="Network interface to use")
    parser.add_argument("--mode", choices=["beacon", "urg", "dns", "all"],
                        default="all",
                        help="Simulation mode (default: all)")
    # Beacon params
    parser.add_argument("--beacon-intervals", type=int, default=5,
                        help="Number of C2 beacon check-ins (default: 5)")
    parser.add_argument("--beacon-period", type=float, default=3.0,
                        help="Seconds between beacons (default: 3.0, real malware ~60s)")
    # URG params
    parser.add_argument("--urg-packets", type=int, default=20,
                        help="URG-flagged packets to send (default: 20)")
    parser.add_argument("--urg-delay", type=float, default=0.2,
                        help="Delay between URG packets in seconds (default: 0.2)")
    # DNS params
    parser.add_argument("--dns-queries", type=int, default=40,
                        help="DNS queries in burst (default: 40)")
    parser.add_argument("--dns-delay", type=float, default=0.1,
                        help="Delay between DNS queries (default: 0.1)")
    args = parser.parse_args()

    print("[SIM] Abnormal Process Execution -- rogue process network signatures")
    print(f"[SIM] Source: {args.src}  |  Destination: {args.dst}\n")

    run_all   = args.mode == "all"

    if run_all or args.mode == "beacon":
        print("--- Mode A: C2 Beacon (Botnet check-in pattern) ---")
        c2_beacon(args.src, args.dst, args.iface,
                  args.beacon_intervals, args.beacon_period)
        print()

    if run_all or args.mode == "urg":
        print("--- Mode B: URG Flag Abuse (covert control channel) ---")
        urg_covert_channel(args.src, args.dst, args.iface,
                           args.urg_packets, args.urg_delay)
        print()

    if run_all or args.mode == "dns":
        print("--- Mode C: Abnormal DNS Burst (DNS beaconing) ---")
        dns_beacon_burst(args.src, args.dst, args.iface,
                         args.dns_queries, args.dns_delay)
        print()

    print("[SIM] Abnormal process simulation complete.")
    print("      Expect GENERIC_TCP_ANOMALY / UNKNOWN_ANOMALY / GENERIC_UDP_ANOMALY"
          " detections in live_alerts.txt.")


if __name__ == "__main__":
    main()
