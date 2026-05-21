"""
run_all_simulations.py
----------------------
Orchestrator for all 5 zero-day attack simulations.

Runs each simulation in sequence with a configurable gap between them so the
live_capture IDS pipeline has time to flush and score each flow before the
next scenario starts.  Each scenario is clearly labelled in the output so
detections in live_alerts.txt can be correlated back to the specific sim.

Usage (while live_capture.py is running in a separate terminal):
    python run_all_simulations.py
    python run_all_simulations.py --gap 15 --iface lo
    python run_all_simulations.py --scenario unusual_login privilege_escalation
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path

SIM_DIR = Path(__file__).parent

SCENARIOS = {
    "unusual_login": {
        "script": "sim_unusual_login.py",
        "description": "Unusual Login Location -- SSH brute-force from geo-diverse IPs",
        "extra_args": ["--attempts", "20", "--delay", "0.25"],
    },
    "privilege_escalation": {
        "script": "sim_privilege_escalation.py",
        "description": "Privilege Escalation -- probing Kerberos/LDAP/SMB/RPC ports",
        "extra_args": ["--rounds", "2"],
    },
    "lateral_movement": {
        "script": "sim_lateral_movement.py",
        "description": "Lateral Movement -- ICMP sweep + TCP SYN scan across subnet",
        "extra_args": ["--host-end", "15", "--targets", "4"],
    },
    "data_exfiltration": {
        "script": "sim_data_exfiltration.py",
        "description": "Data Exfiltration -- large asymmetric outbound flows (HTTPS + DNS-TCP)",
        "extra_args": ["--chunks", "50"],
    },
    "abnormal_process": {
        "script": "sim_abnormal_process.py",
        "description": "Abnormal Process Execution -- C2 beacon + URG abuse + DNS burst",
        "extra_args": ["--beacon-intervals", "4", "--beacon-period", "2.0",
                       "--urg-packets", "15", "--dns-queries", "25"],
    },
}

SEPARATOR = "=" * 65


def run_scenario(name: str, meta: dict, iface: str, gap: float):
    """Run one simulation script, then pause so live_capture can flush flows."""
    script = SIM_DIR / meta["script"]
    cmd = [sys.executable, str(script), "--iface", iface] + meta["extra_args"]

    print(f"\n{SEPARATOR}")
    print(f"  SCENARIO: {name.upper().replace('_', ' ')}")
    print(f"  {meta['description']}")
    print(SEPARATOR)

    result = subprocess.run(cmd, check=False)

    if result.returncode != 0:
        print(f"[WARN] {name} exited with code {result.returncode}")

    print(f"\n[GAP]  Waiting {gap:.0f}s for IDS to flush and score flows ...")
    time.sleep(gap)


def main():
    """Parse CLI options and run the requested simulation scenarios."""
    parser = argparse.ArgumentParser(
        description="Run all 5 IDS attack simulations in sequence")
    parser.add_argument("--iface", default=r"\Device\NPF_Loopback",
                        help=r"Network interface (default: \Device\NPF_Loopback -- Windows loopback)")
    parser.add_argument("--gap", type=float, default=10.0,
                        help="Seconds between scenarios for IDS flow flush (default: 10)")
    parser.add_argument("--scenario", nargs="+", choices=list(SCENARIOS.keys()),
                        default=list(SCENARIOS.keys()),
                        help="Run specific scenarios only (default: all)")
    args = parser.parse_args()

    print(SEPARATOR)
    print("  IDS ZERO-DAY ATTACK SIMULATION SUITE")
    print(f"  Interface: {args.iface}  |  Inter-scenario gap: {args.gap:.0f}s")
    print(f"  Scenarios: {', '.join(args.scenario)}")
    print(SEPARATOR)
    print("\n[INFO]  Ensure live_capture.py is running before proceeding.")
    print("[INFO]  Detections will appear in app/logs/live_alerts.txt\n")

    for name in args.scenario:
        if name in SCENARIOS:
            run_scenario(name, SCENARIOS[name], args.iface, args.gap)

    print(f"\n{SEPARATOR}")
    print("  ALL SIMULATIONS COMPLETE")
    print("  Review: app/logs/live_alerts.txt  |  IDS dashboard")
    print(SEPARATOR)


if __name__ == "__main__":
    main()
