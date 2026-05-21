"""
sim_unusual_login.py
--------------------
Simulation: Unusual Login Location

Models rapid SSH authentication attempts arriving from a geographically
diverse pool of spoofed source IPs -- the network-observable signature of
credential-stuffing or a distributed brute-force campaign.

Traffic pattern (maps to SSH_BRUTE_FORCE in response_engine.py):
  - Many short TCP flows to port 22
  - Highly regular inter-arrival timing (bot-driven)
  - SYN + ACK + PSH flags set (login handshake + password exchange)
  - Small, uniform payload sizes (~80 bytes per direction)
  - Down/Up ratio near 1.0 (symmetric auth exchange)

Safety: targets 127.0.0.1 only unless --target is overridden.
        Never sends to external addresses by default.
"""

import argparse
import random
import time

from scapy.all import IP, TCP, Raw, send, conf

# Geo-diverse spoofed source blocks (RFC-5737 documentation ranges used so
# packets cannot route beyond the local network stack).
SIMULATED_LOCATIONS = [
    ("203.0.113.", "AP-EAST"),     # Asia-Pacific
    ("198.51.100.", "EU-WEST"),    # Europe
    ("192.0.2.", "SA-SOUTH"),      # South America
    ("100.64.0.", "AF-NORTH"),     # Africa
    ("172.16.99.", "NA-REMOTE"),   # North America (unexpected subnet)
]

SSH_PORT = 22
PAYLOAD_AUTH = b"\x00" * 76      # Simulated SSH auth payload (~80 B)
PAYLOAD_RESP = b"\x00" * 68      # Simulated server response


def _rand_src(location_block: str) -> str:
    """Pick one source address from a documentation IP block."""
    return location_block + str(random.randint(1, 254))


def simulate_login_attempt(target: str, src_ip: str, sport: int, iface: str):
    """Send a minimal SSH-auth TCP exchange: SYN -> PSH/ACK data -> FIN."""
    base = dict(src=src_ip, dst=target)

    # SYN
    send(IP(**base) / TCP(sport=sport, dport=SSH_PORT, flags="S",
                          seq=1000, window=8192), iface=iface, verbose=False)
    time.sleep(0.02)

    # PSH+ACK (auth data)
    send(IP(**base) / TCP(sport=sport, dport=SSH_PORT, flags="PA",
                          seq=1001, ack=1, window=8192) / Raw(PAYLOAD_AUTH),
         iface=iface, verbose=False)
    time.sleep(0.02)

    # FIN+ACK (close)
    send(IP(**base) / TCP(sport=sport, dport=SSH_PORT, flags="FA",
                          seq=1077, ack=1, window=8192),
         iface=iface, verbose=False)


def main():
    """Parse options and send repeated simulated SSH login attempts."""
    parser = argparse.ArgumentParser(
        description="IDS simulation -- unusual login location (SSH brute-force from geo-diverse IPs)")
    parser.add_argument("--target", default="127.0.0.1",
                        help="Destination IP (default: 127.0.0.1)")
    parser.add_argument("--iface", default=conf.iface,
                        help="Network interface to use")
    parser.add_argument("--attempts", type=int, default=30,
                        help="Number of login attempts to simulate (default: 30)")
    parser.add_argument("--delay", type=float, default=0.3,
                        help="Seconds between attempts (default: 0.3 -- bot-like regularity)")
    args = parser.parse_args()

    print("[SIM] Unusual Login Location -- SSH credential stuffing from geo-diverse sources")
    print(f"[SIM] Target: {args.target}:{SSH_PORT}  |  Attempts: {args.attempts}")
    print("[SIM] Press Ctrl+C to stop early.\n")

    for i in range(args.attempts):
        block, label = random.choice(SIMULATED_LOCATIONS)
        src = _rand_src(block)
        sport = random.randint(49152, 65535)
        print(f"  [{i+1:>3}/{args.attempts}]  {label:<12}  {src:<16} -> {args.target}:22")
        simulate_login_attempt(args.target, src, sport, args.iface)
        time.sleep(args.delay)

    print("\n[SIM] Done -- check live_alerts.txt and dashboard for SSH_BRUTE_FORCE detections.")


if __name__ == "__main__":
    main()
