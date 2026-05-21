"""Recalibrate the anomaly threshold from known-good live traffic.

Run from any working directory. The script sniffs live traffic, scores completed
flows with the production feature/model path, and saves a percentile threshold
to both SQLite and artifacts/threshold.pkl.
"""

from __future__ import annotations

import argparse

import joblib
import numpy as np
from scapy.all import conf, sniff

try:
    from .db_functions import save_threshold
    from .flow_features import FlowTable
    from .model import load_detector_runtime, reconstruction_error
    from .paths import artifacts_dir
except ImportError:
    from db_functions import save_threshold
    from flow_features import FlowTable
    from model import load_detector_runtime, reconstruction_error
    from paths import artifacts_dir


def main() -> None:
    """Collect live flow errors and save a new percentile threshold."""
    parser = argparse.ArgumentParser(description="Live threshold recalibration")
    parser.add_argument("--iface", default=conf.iface)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--minpkts", type=int, default=4)
    parser.add_argument("--percentile", type=float, default=99.0,
                        help="Set threshold at this percentile of live benign errors")
    args = parser.parse_args()

    runtime = load_detector_runtime()
    live_errors: list[float] = []

    print(f"\n{'=' * 60}")
    print("  LIVE THRESHOLD RECALIBRATION")
    print(f"{'=' * 60}")
    print(f"  Current threshold : {runtime.threshold:.6f}")
    print(f"  Features          : {len(runtime.feature_columns)}")
    print(f"  Sniffing          : {args.iface} for {args.timeout}s")
    print(f"  Percentile        : {args.percentile}%")
    print(f"{'=' * 60}")
    print("  Browse normally while this runs so the baseline reflects good traffic.\n")

    def collect_error(key, flow):
        """Score one completed flow and append its reconstruction error."""
        error, _, _ = reconstruction_error(flow.to_feature_vector(), runtime)
        live_errors.append(error)
        proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        print(
            f"  Flow {len(live_errors):>4}: {key[0]}:{key[2]}->{key[1]}:{key[3]} "
            f"proto={proto_map.get(key[4], str(key[4]))} "
            f"pkts={flow.fwd_pkts + flow.bwd_pkts} error={error:.6f}"
        )

    table = FlowTable(flush_cb=collect_error, min_pkts=args.minpkts)

    try:
        sniff(iface=args.iface, filter="ip", prn=table.process, store=False, timeout=args.timeout)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        table.flush_all()

    if not live_errors:
        print("\nNo flows collected. Try a longer --timeout or lower --minpkts.")
        return

    errors = np.array(live_errors)
    new_threshold = float(np.percentile(errors, args.percentile))
    save_threshold(new_threshold)
    joblib.dump(new_threshold, artifacts_dir() / "threshold.pkl")

    print(f"\n{'=' * 60}")
    print(f"  RECALIBRATION RESULTS  ({len(errors)} flows)")
    print(f"{'=' * 60}")
    print(f"  Old threshold : {runtime.threshold:.6f}")
    print(f"  New threshold : {new_threshold:.6f}  ({args.percentile}th pct)")
    print("  New threshold saved to database and artifacts/threshold.pkl.")
    print(
        f"  Error stats   : min={errors.min():.6f}  "
        f"p50={np.percentile(errors, 50):.6f}  "
        f"p95={np.percentile(errors, 95):.6f}  "
        f"p99={np.percentile(errors, 99):.6f}  "
        f"max={errors.max():.6f}"
    )
    print(f"\n  Now restart live_capture.py to apply the new threshold.")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    main()
