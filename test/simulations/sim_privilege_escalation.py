"""
sim_privilege_escalation.py
---------------------------
Simulation: Privilege Escalation

Models the post-compromise network behaviour of an attacker who has gained
initial foothold and is now probing privileged internal services to escalate:
Kerberos (88), LDAP (389/636), RPC (135), SMB (445), and the Windows admin
share (139).  Each probe is a short, one-sided TCP SYN that times out -- the
classic PORT_SCAN signature when directed exclusively at auth/admin ports.

Traffic pattern (maps to PORT_SCAN in response_engine.py):
  - Very short flow duration (< 5 s)
  - 1--3 packets per flow, near-zero backward packets
  - SYN flag only (no ACK -- server never completes handshake)
  - Targets exclusively privileged authentication service ports
  - Rapid sequential connections from single source (lateral recon)

Safety: source and destination both default to loopback.
"""

import argparse
import random
import time

from scapy.all import IP, TCP, send, conf

# Privileged service ports probed during privilege escalation reconnaissance
PRIV_PORTS = {
    88:   "Kerberos",
    135:  "MS-RPC",
    139:  "NetBIOS",
    389:  "LDAP",
    445:  "SMB",
    636:  "LDAPS",
    3268: "Global Catalog",
    3269: "Global Catalog SSL",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
}


def probe_port(src: str, dst: str, dport: int, iface: str):
    """Send a single SYN to a privileged port -- simulates escalation probe."""
    sport = random.randint(49152, 65535)
    send(
        IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S",
                                    seq=random.randint(1000, 9999), window=1024),
        iface=iface, verbose=False,
    )


def main():
    parser = argparse.ArgumentParser(
        description="IDS simulation -- privilege escalation (privileged port probing)")
    parser.add_argument("--src", default="127.0.0.1",
                        help="Simulated attacker source IP (default: 127.0.0.1)")
    parser.add_argument("--target", default="127.0.0.1",
                        help="Target host IP (default: 127.0.0.1)")
    parser.add_argument("--iface", default=conf.iface,
                        help="Network interface to use")
    parser.add_argument("--rounds", type=int, default=3,
                        help="Rounds through all privilege ports (default: 3)")
    parser.add_argument("--delay", type=float, default=0.15,
                        help="Seconds between probes (default: 0.15)")
    args = parser.parse_args()

    print("[SIM] Privilege Escalation -- probing privileged authentication services")
    print(f"[SIM] Attacker: {args.src}  ->  Target: {args.target}")
    print(f"[SIM] Rounds: {args.rounds}  |  Ports: {list(PRIV_PORTS.keys())}\n")

    total = 0
    for rnd in range(1, args.rounds + 1):
        print(f"  --- Round {rnd}/{args.rounds} ---")
        for port, service in PRIV_PORTS.items():
            print(f"    Probing {service:<22} port {port}")
            probe_port(args.src, args.target, port, args.iface)
            total += 1
            time.sleep(args.delay)

    print(f"\n[SIM] Done -- {total} probes sent. "
          "Expect PORT_SCAN detections in live_alerts.txt.")


if __name__ == "__main__":
    main()
