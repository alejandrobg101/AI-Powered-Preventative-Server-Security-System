"""Live feature diagnostic tool for investigating noisy anomaly scores.

It sniffs a short window, reuses the production flow-feature extraction path,
and prints the features that are farthest from the training distribution.
"""

from __future__ import annotations

import argparse

import torch
from scapy.all import conf, sniff

try:
    from .flow_features import FlowTable
    from .model import DetectorRuntime, load_detector_runtime, reconstruction_error
    from .risk_classifier import classify as classify_risk
    from .response_engine import format_response_block, get_recommendation, infer_anomaly_type
except ImportError:
    from flow_features import FlowTable
    from model import DetectorRuntime, load_detector_runtime, reconstruction_error
    from risk_classifier import classify as classify_risk
    from response_engine import format_response_block, get_recommendation, infer_anomaly_type


def print_training_distribution(runtime: DetectorRuntime) -> None:
    """Print the scaler mean/std table used as the diagnostic baseline."""
    print("TRAINING DISTRIBUTION (mean +/- std for all features):")
    print(f"  {'Feature':<45} {'Mean':>12} {'Std':>12}")
    print(f"  {'-' * 70}")
    for idx, col in enumerate(runtime.feature_columns):
        print(f"  {col:<45} {runtime.scaler.mean_[idx]:>12.4f} {runtime.scaler.scale_[idx]:>12.4f}")
    print()


def diagnose_flow(key, flow, runtime: DetectorRuntime) -> None:
    """Score one flow and print raw, scaled, and reconstruction diagnostics."""
    error, df_row, x_scaled = reconstruction_error(flow.to_feature_vector(), runtime)

    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    risk = classify_risk(error, runtime.risk_thresholds)
    anomaly_type = infer_anomaly_type(flow, key)
    rec = get_recommendation(anomaly_type, risk.name)

    print(f"\n{'-' * 70}")
    print(
        f"  [{risk.label}]  {key[0]}:{key[2]} -> {key[1]}:{key[3]}  "
        f"proto={proto_map.get(key[4], str(key[4]))}  "
        f"pkts={flow.fwd_pkts + flow.bwd_pkts}  "
        f"error={error:.6f}  type={anomaly_type}"
    )
    if risk.code > 0:
        print(format_response_block(rec, key[0]))
    print(f"{'-' * 70}")

    scaled_vals = x_scaled[0]
    raw_vals = df_row.iloc[0]
    deviations = [
        (
            runtime.feature_columns[i],
            float(raw_vals[runtime.feature_columns[i]]),
            float(scaled_vals[i]),
            float(runtime.scaler.mean_[i]),
            float(runtime.scaler.scale_[i]),
        )
        for i in range(len(runtime.feature_columns))
    ]
    deviations.sort(key=lambda item: abs(item[2]), reverse=True)

    print(f"  {'Feature':<45} {'Raw Value':>15} {'Z-score':>9} {'Train Mean':>12} {'Train Std':>10}")
    print(f"  {'-' * 95}")
    for fname, raw, z_score, train_mean, train_std in deviations[:15]:
        flag = " <- OUTLIER" if abs(z_score) > 3 else ""
        print(f"  {fname:<45} {raw:>15.4f} {z_score:>9.3f} {train_mean:>12.4f} {train_std:>10.4f}{flag}")

    x_tensor = torch.tensor(x_scaled, dtype=torch.float32)
    with torch.no_grad():
        recon = runtime.model(x_tensor)[0]
    per_feature_errors = ((x_tensor[0] - recon) ** 2).detach().numpy()
    worst_recon = sorted(
        zip(runtime.feature_columns, per_feature_errors),
        key=lambda item: item[1],
        reverse=True,
    )[:10]

    print("\n  Top 10 features by RECONSTRUCTION ERROR contribution:")
    print(f"  {'Feature':<45} {'Squared Error':>15}")
    print(f"  {'-' * 62}")
    for fname, ferr in worst_recon:
        print(f"  {fname:<45} {ferr:>15.6f}")


def main() -> None:
    """Run a short live sniff and diagnose the first few completed flows."""
    parser = argparse.ArgumentParser(description="Diagnose feature mismatch in live traffic")
    parser.add_argument("--iface", default=conf.iface)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--minpkts", type=int, default=4)
    parser.add_argument("--maxflows", type=int, default=5, help="Stop after this many diagnosed flows")
    args = parser.parse_args()

    runtime = load_detector_runtime()
    print(f"\n{'=' * 60}")
    print("  FEATURE DIAGNOSTIC TOOL")
    print(f"{'=' * 60}")
    print(f"  Features  : {len(runtime.feature_columns)}")
    print(f"  Threshold : {runtime.threshold:.6f}")
    print(
        f"  Risk tiers: medium={runtime.risk_thresholds['medium']:.6f}  "
        f"high={runtime.risk_thresholds['high']:.6f}  "
        f"critical={runtime.risk_thresholds['critical']:.6f}"
    )
    print(f"{'=' * 60}\n")
    print_training_distribution(runtime)

    print(f"Sniffing on {args.iface} for {args.timeout}s (diagnosing first {args.maxflows} flows)...\n")

    flow_count = [0]

    def flush_cb(key, flow):
        if flow_count[0] >= args.maxflows:
            return
        flow_count[0] += 1
        diagnose_flow(key, flow, runtime)

    table = FlowTable(flush_cb=flush_cb, min_pkts=args.minpkts)

    try:
        sniff(iface=args.iface, filter="ip", prn=table.process, store=False, timeout=args.timeout)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        table.flush_all()

    print(f"\n{'=' * 70}")
    print("  DIAGNOSIS COMPLETE")
    print(f"{'=' * 70}")


if __name__ == "__main__":
    main()
