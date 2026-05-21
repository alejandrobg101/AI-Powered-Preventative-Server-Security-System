"""Live packet capture, flow feature extraction, anomaly scoring, and logging.

The module is import-safe: it does not prompt, create/reset the database, or
load model artifacts until init_runtime(), score_flow(), or main() is called.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import threading
import time
from datetime import datetime

from scapy.all import conf, sniff, wrpcap

try:
    from .db_functions import db_increment_low_count, db_insert_events, load_threshold
    from .flow_features import FLOW_TIMEOUT, FlowStats, FlowTable
    from .model import DetectorRuntime, load_detector_runtime, reconstruction_error
    from .paths import app_dir, ensure_runtime_dirs, live_alerts_path, live_pcap_path
    from .risk_classifier import classify as classify_risk
    from .response_engine import get_recommendation, infer_anomaly_type
    from .schema import create_db, db_reset
except ImportError:
    from db_functions import db_increment_low_count, db_insert_events, load_threshold
    from flow_features import FLOW_TIMEOUT, FlowStats, FlowTable
    from model import DetectorRuntime, load_detector_runtime, reconstruction_error
    from paths import app_dir, ensure_runtime_dirs, live_alerts_path, live_pcap_path
    from risk_classifier import classify as classify_risk
    from response_engine import get_recommendation, infer_anomaly_type
    from schema import create_db, db_reset

DEBUG = False
_runtime: DetectorRuntime | None = None

# Backward-compatible globals for scripts/tests that inspect live_capture after
# calling init_runtime(). They are intentionally empty before runtime init.
feature_columns: list[str] = []
scaler = None
threshold: float | None = None
risk_thresholds: dict = {}
model = None


def init_runtime(
    *,
    skip_reset: bool = True,
    threshold_override: float | None = None,
    print_summary: bool = True,
) -> DetectorRuntime:
    """Initialize DB state and load model artifacts exactly once per process."""
    global _runtime, scaler, threshold, risk_thresholds, model

    if _runtime is not None and threshold_override is None:
        return _runtime

    if not skip_reset:
        db_reset()
    create_db()
    ensure_runtime_dirs()

    selected_threshold = (
        float(threshold_override)
        if threshold_override is not None
        else float(load_threshold())
    )
    _runtime = load_detector_runtime(threshold=selected_threshold)

    feature_columns.clear()
    feature_columns.extend(_runtime.feature_columns)
    scaler = _runtime.scaler
    threshold = _runtime.threshold
    risk_thresholds.clear()
    risk_thresholds.update(_runtime.risk_thresholds)
    model = _runtime.model

    if print_summary:
        _print_runtime_summary(_runtime)

    return _runtime


def _require_runtime() -> DetectorRuntime:
    """Return the loaded runtime, initializing without reset if needed."""
    return _runtime if _runtime is not None else init_runtime(skip_reset=True)


def _print_runtime_summary(runtime: DetectorRuntime) -> None:
    """Print concise model and scaler information for CLI operators."""
    print(f"[INFO] Model loaded - {len(runtime.feature_columns)} features, threshold={runtime.threshold:.6f}")
    print(
        f"[INFO] Risk thresholds   "
        f"medium={runtime.risk_thresholds['medium']:.6f}  "
        f"high={runtime.risk_thresholds['high']:.6f}  "
        f"critical={runtime.risk_thresholds['critical']:.6f}"
    )

    flag_features = ["ACK Flag Count", "SYN Flag Count", "FIN Flag Count", "PSH Flag Count", "Fwd PSH Flags"]
    print("[INFO] Scaler stats for flag features (mean +/- std from training data):")
    for fname in flag_features:
        if fname in runtime.feature_columns:
            idx = runtime.feature_columns.index(fname)
            print(f"  {fname:<30}  mean={runtime.scaler.mean_[idx]:.4f}  std={runtime.scaler.scale_[idx]:.4f}")


def _format_alert(key: tuple, flow: FlowStats, risk, error: float, anomaly_type: str) -> str:
    """Return the live-alert text block written to logs/live_alerts.txt."""
    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    proto_str = proto_map.get(key[4], str(key[4]))
    return (
        f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        f"[{risk.label}]\n"
        f"Source: {key[0]}:{key[2]}\n"
        f"Destination: {key[1]}:{key[3]}\n"
        f"Protocol: {proto_str}\n"
        f"Packets: {flow.fwd_pkts + flow.bwd_pkts}\n"
        f"Bytes: {sum(flow.fwd_bytes) + sum(flow.bwd_bytes)}\n"
        f"Error: {error:.6f}\n"
        f"Type: {anomaly_type}\n"
        f"{'-' * 40}\n"
    )


def score_flow(key: tuple, flow: FlowStats) -> None:
    """Extract features, score a flow, classify risk, and persist alert data."""
    runtime = _require_runtime()
    error, df_row, x_scaled = reconstruction_error(flow.to_feature_vector(), runtime)

    risk = classify_risk(error, runtime.risk_thresholds)
    anomaly_type = infer_anomaly_type(flow, key)
    recommendation = get_recommendation(anomaly_type, risk.name)
    src_ip = key[0]

    ensure_runtime_dirs()
    with open(live_alerts_path(), "a", encoding="utf-8") as alert_file:
        alert_file.write(_format_alert(key, flow, risk, error, anomaly_type))

    if risk.code > 0:
        db_insert_events(
            anomaly_type=anomaly_type,
            ip=str(src_ip),
            error=error,
            risk=risk,
            recommendation=recommendation,
        )
    else:
        db_increment_low_count()

    if DEBUG:
        scaled_row = x_scaled[0]
        worst = sorted(zip(runtime.feature_columns, scaled_row), key=lambda item: abs(item[1]), reverse=True)[:10]
        print("  Top 10 features by scaled magnitude (raw -> scaled):")
        for fname, scaled_value in worst:
            raw = df_row[fname].iloc[0]
            print(f"    {fname:<40}  raw={raw:>15.4f}  scaled={scaled_value:>10.4f}")


class TimeoutFlusher(threading.Thread):
    """Background thread that evicts inactive flows every interval seconds."""

    def __init__(self, flow_table: FlowTable, interval: float = 10.0):
        super().__init__(daemon=True)
        self._table = flow_table
        self._interval = interval
        self._stop_evt = threading.Event()

    def run(self) -> None:
        while not self._stop_evt.wait(self._interval):
            now = time.time()
            with self._table._lock:
                timed_out = [
                    key for key, flow in self._table._flows.items()
                    if now - flow.last_ts > FLOW_TIMEOUT
                ]
                for key in timed_out:
                    self._table._maybe_flush(key, self._table._flows[key])

    def stop(self) -> None:
        """Signal the flusher loop to exit."""
        self._stop_evt.set()


def main() -> None:
    """Run live packet capture and score flows until timeout or Ctrl+C."""
    parser = argparse.ArgumentParser(description="Live IDS capture with autoencoder scoring")
    parser.add_argument("--iface", default=conf.iface, help="Network interface to sniff on")
    parser.add_argument("--timeout", type=int, default=0, help="Stop after N seconds (0=forever)")
    parser.add_argument("--pcap", action="store_true", help="Save captured packets to app/live.pcap")
    parser.add_argument("--minpkts", type=int, default=4, help="Minimum packets to score a flow (default 4)")
    parser.add_argument("--debug", action="store_true", help="Print top 10 outlier features per flow")
    parser.add_argument("--no-reset", action="store_true", help="Skip database reset prompt")
    parser.add_argument("--no-dashboard", action="store_true", help="Skip auto-launching the dashboard")
    parser.add_argument("--threshold", type=float, default=None, help="Override model threshold")
    args = parser.parse_args()

    global DEBUG
    DEBUG = args.debug
    init_runtime(
        skip_reset=args.no_reset,
        threshold_override=args.threshold,
        print_summary=True,
    )

    print(f"[INFO] Sniffing on interface: {args.iface}")
    print(f"[INFO] Flow timeout: {FLOW_TIMEOUT}s   min packets: {args.minpkts}")
    print("[INFO] Press Ctrl+C to stop.\n")

    captured_pkts = []
    dashboard_process = None
    table = FlowTable(flush_cb=score_flow, min_pkts=args.minpkts)
    flusher = TimeoutFlusher(table, interval=10.0)
    flusher.start()

    def handle(pkt):
        if args.pcap:
            captured_pkts.append(pkt)
        table.process(pkt)

    if not args.no_dashboard:
        dashboard_process = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", "dashboard.py"],
            cwd=app_dir(),
        )

    try:
        sniff(
            iface=args.iface,
            filter="ip",
            prn=handle,
            store=False,
            timeout=args.timeout if args.timeout > 0 else None,
        )
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")
    finally:
        print("[INFO] Flushing remaining flows...")
        flusher.stop()
        table.flush_all()

        if args.pcap and captured_pkts:
            wrpcap(str(live_pcap_path()), captured_pkts)
            print(f"[INFO] Saved {len(captured_pkts):,} packets to {live_pcap_path()}")
        if dashboard_process is not None:
            dashboard_process.terminate()

        if live_alerts_path().exists():
            live_alerts_path().unlink()
        print("[INFO] Done.")


if __name__ == "__main__":
    main()
