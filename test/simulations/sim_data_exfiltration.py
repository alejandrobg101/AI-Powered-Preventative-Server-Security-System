"""
sim_data_exfiltration.py
------------------------
Simulation: Data Exfiltration

Models a slow-and-low data theft flow: the attacker's host uploads large
volumes of data outbound (large fwd packets near MTU) while receiving only
tiny acknowledgement responses (minimal bwd traffic).

This precisely matches the "Exfiltration" feature profile in fake_data.py:
  - Fwd Packet Length Mean ~ 1400 B  (at MTU boundary)
  - Bwd Packet Length Mean ~ 200 B   (ACK-only responses)
  - Down/Up Ratio near 0              (almost no download)
  - Many forward packets, few backward packets
  - Flow duration: 10--100 s           (sustained transfer, not a spike)
  - PSH + ACK flags throughout        (stream mode)

Two exfil channels are simulated in parallel:
  - Primary: TCP/443 (HTTPS-disguised -- blends with normal TLS traffic)
  - Secondary: TCP/53 (DNS-over-TCP -- covert channel variant)

Safety: traffic is sent to 127.0.0.1 only by default.
"""

import argparse
import random
import threading
import time

from scapy.all import IP, TCP, Raw, send, conf

# Near-MTU payload -- represents one 1400-byte chunk of stolen data
CHUNK_SIZE = 1400
ACK_SIZE   = 60    # Simulated ACK-only response from C2 server

EXFIL_PORTS = {
    "https-covert": 443,
    "dns-tcp-covert": 53,
}


def _build_chunk(size: int) -> bytes:
    """Build a realistic-looking random data payload of given size."""
    return bytes(random.getrandbits(8) for _ in range(size))


def exfil_stream(src: str, dst: str, dst_port: int, label: str,
                 chunks: int, iface: str, delay: float):
    """Send a sustained stream of near-MTU packets to simulate file upload."""
    sport = random.randint(49152, 65535)
    seq = random.randint(10000, 99999)

    print(f"  [{label}]  {src}:{sport} -> {dst}:{dst_port}  ({chunks} chunks x {CHUNK_SIZE} B)")

    # SYN -- open the connection
    send(IP(src=src, dst=dst) / TCP(sport=sport, dport=dst_port, flags="S",
                                     seq=seq, window=65535),
         iface=iface, verbose=False)
    time.sleep(0.01)

    total_bytes = 0
    for i in range(chunks):
        payload = _build_chunk(CHUNK_SIZE)
        send(
            IP(src=src, dst=dst) / TCP(sport=sport, dport=dst_port, flags="PA",
                                        seq=seq, ack=1, window=65535) / Raw(payload),
            iface=iface, verbose=False,
        )
        seq += CHUNK_SIZE
        total_bytes += CHUNK_SIZE

        # Occasional tiny "ACK" response from C2 (low bwd traffic)
        if i % 10 == 0:
            send(
                IP(src=dst, dst=src) / TCP(sport=dst_port, dport=sport, flags="A",
                                            seq=1, ack=seq, window=8192) / Raw(b"\x00" * 40),
                iface=iface, verbose=False,
            )

        time.sleep(delay)
        if (i + 1) % 20 == 0:
            kb = total_bytes / 1024
            print(f"    [{label}]  {i+1}/{chunks} chunks sent ({kb:.1f} KB)")

    # FIN -- close cleanly
    send(IP(src=src, dst=dst) / TCP(sport=sport, dport=dst_port, flags="FA",
                                     seq=seq, ack=1, window=65535),
         iface=iface, verbose=False)

    print(f"  [{label}]  Complete -- {total_bytes/1024:.1f} KB exfiltrated")


def main():
    """Parse options and run one or both exfiltration channels."""
    parser = argparse.ArgumentParser(
        description="IDS simulation -- data exfiltration (large asymmetric outbound flows)")
    parser.add_argument("--src", default="127.0.0.1",
                        help="Simulated victim source IP (default: 127.0.0.1)")
    parser.add_argument("--dst", default="127.0.0.1",
                        help="Simulated C2 destination IP (default: 127.0.0.1)")
    parser.add_argument("--iface", default=conf.iface,
                        help="Network interface to use")
    parser.add_argument("--chunks", type=int, default=80,
                        help="Number of 1400-byte data chunks per channel (default: 80 ~ 112 KB)")
    parser.add_argument("--delay", type=float, default=0.05,
                        help="Seconds between packets (default: 0.05 -- sustained transfer)")
    parser.add_argument("--parallel", action="store_true",
                        help="Run both channels in parallel threads")
    args = parser.parse_args()

    print("[SIM] Data Exfiltration -- large asymmetric outbound flows to C2")
    print(f"[SIM] Victim: {args.src}  ->  C2: {args.dst}")
    print(f"[SIM] Channels: HTTPS-covert (443) + DNS-TCP-covert (53)")
    print(f"[SIM] Volume per channel: {args.chunks * CHUNK_SIZE / 1024:.1f} KB\n")

    streams = [
        ("https-covert", EXFIL_PORTS["https-covert"]),
        ("dns-tcp-covert", EXFIL_PORTS["dns-tcp-covert"]),
    ]

    if args.parallel:
        threads = []
        for label, port in streams:
            t = threading.Thread(
                target=exfil_stream,
                args=(args.src, args.dst, port, label, args.chunks, args.iface, args.delay),
                daemon=True,
            )
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
    else:
        for label, port in streams:
            exfil_stream(args.src, args.dst, port, label, args.chunks, args.iface, args.delay)

    print("\n[SIM] Data exfiltration simulation complete.")
    print("      Expect GENERIC_TCP_ANOMALY / WEB_ATTACK detections in live_alerts.txt.")


if __name__ == "__main__":
    main()
