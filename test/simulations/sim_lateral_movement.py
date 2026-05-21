"""
sim_lateral_movement.py
-----------------------
Simulation: Lateral Movement

Models a compromised internal host sweeping across a subnet to discover live
peers and open services -- the canonical network-layer signature of lateral
movement.  Two phases are simulated:

  Phase 1 -- Host discovery (ICMP ping sweep across a /24)
    High-rate ICMP echo requests, tiny fixed-size payloads.
    Maps to ICMP_FLOOD / GENERIC_ICMP in the IDS when pkt_rate > 50.

  Phase 2 -- Service enumeration (TCP SYN scan on discovered hosts)
    Rapid SYN-only connections to a common service port list.
    Maps to PORT_SCAN: short duration, 1-3 pkts, zero backward traffic.

Together the two phases produce the multi-hop reconnaissance footprint that
distinguishes lateral movement from a simple external port scan.

Safety: subnet defaults to 127.0.0.x (loopback) -- no traffic leaves the host.
"""

import argparse
import random
import time

from scapy.all import IP, TCP, ICMP, Raw, send, conf

# Common service ports probed during lateral movement
LATERAL_PORTS = [21, 22, 23, 80, 135, 139, 443, 445, 3389, 5985, 8080, 8443]

ICMP_PAYLOAD = b"LATERAL_MOVE_SIM" + b"\x00" * 16   # 32-byte echo payload


def icmp_sweep(src: str, subnet_prefix: str, host_range: range, iface: str, delay: float):
    """Phase 1: rapid ICMP echo sweep across the subnet."""
    print(f"  [Phase 1] ICMP host discovery sweep -- {subnet_prefix}x")
    for host in host_range:
        dst = f"{subnet_prefix}{host}"
        send(
            IP(src=src, dst=dst) / ICMP(type=8, code=0) / Raw(ICMP_PAYLOAD),
            iface=iface, verbose=False,
        )
        time.sleep(delay)
    print(f"  [Phase 1] Sweep complete -- {len(host_range)} hosts pinged.")


def tcp_enumerate(src: str, targets: list[str], ports: list[int],
                  iface: str, delay: float):
    """Phase 2: SYN-only port scan against discovered hosts."""
    print(f"\n  [Phase 2] TCP service enumeration -- {len(targets)} hosts x {len(ports)} ports")
    total = 0
    for dst in targets:
        for port in ports:
            sport = random.randint(49152, 65535)
            send(
                IP(src=src, dst=dst) / TCP(sport=sport, dport=port, flags="S",
                                            seq=random.randint(1000, 65535), window=1024),
                iface=iface, verbose=False,
            )
            total += 1
            time.sleep(delay)
        print(f"    {dst} -- {len(ports)} ports scanned")
    print(f"  [Phase 2] Done -- {total} SYN probes sent.")


def main():
    """Parse options and run the two-phase lateral-movement simulation."""
    parser = argparse.ArgumentParser(
        description="IDS simulation -- lateral movement (ICMP sweep + TCP SYN scan)")
    parser.add_argument("--src", default="127.0.0.1",
                        help="Simulated attacker source IP (default: 127.0.0.1)")
    parser.add_argument("--subnet", default="127.0.0.",
                        help="Subnet prefix to sweep, e.g. '127.0.0.' (default: 127.0.0.)")
    parser.add_argument("--host-start", type=int, default=1,
                        help="First host octet in sweep range (default: 1)")
    parser.add_argument("--host-end", type=int, default=20,
                        help="Last host octet in sweep range (default: 20)")
    parser.add_argument("--iface", default=conf.iface,
                        help="Network interface to use")
    parser.add_argument("--icmp-delay", type=float, default=0.05,
                        help="Delay between ICMP probes in seconds (default: 0.05)")
    parser.add_argument("--tcp-delay", type=float, default=0.1,
                        help="Delay between TCP SYN probes in seconds (default: 0.1)")
    parser.add_argument("--targets", type=int, default=5,
                        help="Number of 'discovered' hosts to enumerate in phase 2 (default: 5)")
    args = parser.parse_args()

    print("[SIM] Lateral Movement -- subnet sweep + service enumeration")
    print(f"[SIM] Attacker: {args.src}  |  Subnet: {args.subnet}0/24\n")

    host_range = range(args.host_start, args.host_end + 1)

    # Phase 1: ICMP discovery
    icmp_sweep(args.src, args.subnet, host_range, args.iface, args.icmp_delay)

    # Simulate 'discovered live hosts' from sweep results
    discovered = [
        f"{args.subnet}{h}"
        for h in random.sample(list(host_range), min(args.targets, len(host_range)))
    ]
    print(f"\n  [SIM] Simulated discovered hosts: {discovered}")

    # Phase 2: TCP enumeration on discovered hosts
    tcp_enumerate(args.src, discovered, LATERAL_PORTS, args.iface, args.tcp_delay)

    print("\n[SIM] Lateral movement simulation complete.")
    print("      Expect ICMP_FLOOD + PORT_SCAN detections in live_alerts.txt.")


if __name__ == "__main__":
    main()
