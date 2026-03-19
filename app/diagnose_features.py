"""
diagnose_features.py
────────────────────
Run this BEFORE live_capture.py to understand why the autoencoder
is flagging everything as an attack.

It sniffs for a short window, extracts features from each flow,
scales them, and reports which features deviate most from the
training distribution — telling you exactly what is broken.

Usage:
    python diagnose_features.py --iface "Intel(R) Wi-Fi 6 AX201 160MHz" --timeout 60
"""

from __future__ import annotations

import argparse
import time
import threading
from collections import deque

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import joblib

from scapy.all import sniff, IP, TCP, UDP, conf

# ─────────────────────────────────────────────────────────────────────────────
# AUTOENCODER  (must match training architecture exactly)
# ─────────────────────────────────────────────────────────────────────────────
class Autoencoder(nn.Module):
    def __init__(self, input_dim: int):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, 32), nn.ReLU(),
            nn.Linear(32, 16),
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32), nn.ReLU(),
            nn.Linear(32, 64), nn.ReLU(), nn.Dropout(0.2),
            nn.Linear(64, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


# ─────────────────────────────────────────────────────────────────────────────
# LOAD ARTIFACTS
# ─────────────────────────────────────────────────────────────────────────────
feature_columns: list = joblib.load("artifacts/feature_columns.pkl")
scaler          = joblib.load("artifacts/scaler.pkl")
threshold       = joblib.load("artifacts/threshold.pkl")

model = Autoencoder(len(feature_columns))
model.load_state_dict(torch.load("artifacts/autoencoder_model.pth", map_location="cpu"))
model.eval()

print(f"\n{'='*60}")
print(f"  FEATURE DIAGNOSTIC TOOL")
print(f"{'='*60}")
print(f"  Features  : {len(feature_columns)}")
print(f"  Threshold : {threshold:.6f}")
print(f"{'='*60}\n")

# Print full training distribution for reference
print("TRAINING DISTRIBUTION (mean ± std for all features):")
print(f"  {'Feature':<45} {'Mean':>12} {'Std':>12}")
print(f"  {'-'*70}")
for i, col in enumerate(feature_columns):
    print(f"  {col:<45} {scaler.mean_[i]:>12.4f} {scaler.scale_[i]:>12.4f}")
print()

FLOW_TIMEOUT = 120.0
IAT_WINDOW   = 100


# ─────────────────────────────────────────────────────────────────────────────
# FLOW KEY
# ─────────────────────────────────────────────────────────────────────────────
def flow_key(pkt) -> tuple | None:
    if not pkt.haslayer(IP):
        return None
    ip    = pkt[IP]
    proto = ip.proto
    if pkt.haslayer(TCP):
        sp, dp = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sp, dp = pkt[UDP].sport, pkt[UDP].dport
    else:
        sp, dp = 0, 0
    if (ip.src, sp) <= (ip.dst, dp):
        return (ip.src, ip.dst, sp, dp, proto)
    return (ip.dst, ip.src, dp, sp, proto)


# ─────────────────────────────────────────────────────────────────────────────
# FLOW STATS  (same as live_capture.py)
# ─────────────────────────────────────────────────────────────────────────────
class FlowStats:
    def __init__(self, key, first_pkt, ts):
        self.key        = key
        self.proto      = key[4]
        self.start_ts   = ts
        self.last_ts    = ts
        self.fwd_last_ts: float | None  = None
        self.bwd_last_ts: float | None  = None
        self.fwd_pkts   = 0
        self.bwd_pkts   = 0
        self.fwd_bytes: list[int]   = []
        self.bwd_bytes: list[int]   = []
        self.fwd_iats:  list[float] = []
        self.bwd_iats:  list[float] = []
        self.flow_iats: list[float] = []
        self._all_ts: deque = deque(maxlen=IAT_WINDOW + 1)
        self._all_ts.append(ts)
        self.fwd_psh = self.fwd_urg = 0
        self.bwd_psh = self.bwd_urg = 0
        self.fin = self.syn = self.rst = self.psh = self.ack = self.urg = 0
        self.fwd_header_lens: list[int] = []
        self.bwd_header_lens: list[int] = []
        self.init_fwd_win = 0
        self.init_bwd_win = 0
        self._init_fwd_set = False
        self._init_bwd_set = False
        self.active_times: list[float] = []
        self.idle_times:   list[float] = []
        self._active_start = ts
        self._last_active  = ts
        self._IDLE_THRESH  = 1.0
        self._add_packet(first_pkt, ts, forward=True)

    @staticmethod
    def _tcp_flags(pkt) -> dict:
        if not pkt.haslayer(TCP):
            return {}
        f = pkt[TCP].flags
        return {
            'FIN': bool(f & 0x01), 'SYN': bool(f & 0x02),
            'RST': bool(f & 0x04), 'PSH': bool(f & 0x08),
            'ACK': bool(f & 0x10), 'URG': bool(f & 0x20),
        }

    @staticmethod
    def _ip_len(pkt) -> int:
        return pkt[IP].len if pkt.haslayer(IP) else 0

    @staticmethod
    def _header_len(pkt) -> int:
        if pkt.haslayer(TCP):
            return pkt[TCP].dataofs * 4 + 20
        if pkt.haslayer(UDP):
            return 8 + 20
        return 20

    def _add_packet(self, pkt, ts, forward):
        plen  = self._ip_len(pkt)
        hlen  = self._header_len(pkt)
        flags = self._tcp_flags(pkt)

        gap = ts - self._last_active
        if gap > self._IDLE_THRESH:
            self.idle_times.append(gap)
            self.active_times.append(self._last_active - self._active_start)
            self._active_start = ts
        self._last_active = ts

        if len(self._all_ts) > 0:
            self.flow_iats.append(ts - self._all_ts[-1])
        self._all_ts.append(ts)

        for name, val in flags.items():
            if val:
                setattr(self, name.lower(), getattr(self, name.lower()) + 1)

        if forward:
            self.fwd_pkts += 1
            self.fwd_bytes.append(plen)
            self.fwd_header_lens.append(hlen)
            if flags.get('PSH'):  self.fwd_psh += 1
            if flags.get('URG'):  self.fwd_urg += 1
            if not self._init_fwd_set and pkt.haslayer(TCP):
                self.init_fwd_win   = pkt[TCP].window
                self._init_fwd_set  = True
            if self.fwd_last_ts is not None:
                self.fwd_iats.append(ts - self.fwd_last_ts)
            self.fwd_last_ts = ts
        else:
            self.bwd_pkts += 1
            self.bwd_bytes.append(plen)
            self.bwd_header_lens.append(hlen)
            if flags.get('PSH'):  self.bwd_psh += 1
            if flags.get('URG'):  self.bwd_urg += 1
            if not self._init_bwd_set and pkt.haslayer(TCP):
                self.init_bwd_win   = pkt[TCP].window
                self._init_bwd_set  = True
            if self.bwd_last_ts is not None:
                self.bwd_iats.append(ts - self.bwd_last_ts)
            self.bwd_last_ts = ts
        self.last_ts = ts

    def update(self, pkt, ts):
        src_ip  = pkt[IP].src if pkt.haslayer(IP) else ""
        forward = (src_ip == self.key[0])
        self._add_packet(pkt, ts, forward)

    @staticmethod
    def _stats(lst) -> dict:
        if not lst:
            return {'mean': 0.0, 'std': 0.0, 'max': 0.0, 'min': 0.0}
        a = np.array(lst, dtype=float)
        return {'mean': float(a.mean()), 'std': float(a.std()),
                'max': float(a.max()),  'min': float(a.min())}

    def to_feature_vector(self) -> dict:
        duration_s  = max(self.last_ts - self.start_ts, 1e-9)
        duration_us = duration_s * 1e6
        total_pkts  = self.fwd_pkts + self.bwd_pkts
        total_bytes = sum(self.fwd_bytes) + sum(self.bwd_bytes)

        fwd_b  = self._stats(self.fwd_bytes)
        bwd_b  = self._stats(self.bwd_bytes)
        fwd_i  = self._stats(self.fwd_iats)
        bwd_i  = self._stats(self.bwd_iats)
        flow_i = self._stats(self.flow_iats)
        act    = self._stats(self.active_times)
        idl    = self._stats(self.idle_times)
        fwd_h  = self._stats(self.fwd_header_lens)
        bwd_h  = self._stats(self.bwd_header_lens)

        flow_pkts_s  = total_pkts  / duration_us
        flow_bytes_s = total_bytes / duration_us
        fwd_pkts_s   = self.fwd_pkts / duration_us
        bwd_pkts_s   = self.bwd_pkts / duration_us
        down_up      = (self.bwd_pkts / self.fwd_pkts) if self.fwd_pkts else 0.0
        fwd_seg_avg  = fwd_b['mean'] - fwd_h['mean'] if self.fwd_pkts else 0.0
        bwd_seg_avg  = bwd_b['mean'] - bwd_h['mean'] if self.bwd_pkts else 0.0
        avg_seg      = (total_bytes / total_pkts) if total_pkts else 0.0
        fwd_bulk_bytes = sum(self.fwd_bytes)
        bwd_bulk_bytes = sum(self.bwd_bytes)

        return {
            "Destination Port": self.key[3],
            "Flow Duration": duration_us,
            "Total Fwd Packets": self.fwd_pkts,
            "Total Backward Packets": self.bwd_pkts,
            "Total Length of Fwd Packets": fwd_bulk_bytes,
            "Total Length of Bwd Packets": bwd_bulk_bytes,
            "Fwd Packet Length Max": fwd_b['max'],
            "Fwd Packet Length Min": fwd_b['min'],
            "Fwd Packet Length Mean": fwd_b['mean'],
            "Fwd Packet Length Std": fwd_b['std'],
            "Bwd Packet Length Max": bwd_b['max'],
            "Bwd Packet Length Min": bwd_b['min'],
            "Bwd Packet Length Mean": bwd_b['mean'],
            "Bwd Packet Length Std": bwd_b['std'],
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": flow_i['mean'] * 1e6,
            "Flow IAT Std":  flow_i['std']  * 1e6,
            "Flow IAT Max":  flow_i['max']  * 1e6,
            "Flow IAT Min":  flow_i['min']  * 1e6,
            "Fwd IAT Total": sum(self.fwd_iats) * 1e6,
            "Fwd IAT Mean":  fwd_i['mean'] * 1e6,
            "Fwd IAT Std":   fwd_i['std']  * 1e6,
            "Fwd IAT Max":   fwd_i['max']  * 1e6,
            "Fwd IAT Min":   fwd_i['min']  * 1e6,
            "Bwd IAT Total": sum(self.bwd_iats) * 1e6,
            "Bwd IAT Mean":  bwd_i['mean'] * 1e6,
            "Bwd IAT Std":   bwd_i['std']  * 1e6,
            "Bwd IAT Max":   bwd_i['max']  * 1e6,
            "Bwd IAT Min":   bwd_i['min']  * 1e6,
            "Fwd PSH Flags": 1 if self.fwd_psh else 0,
            "Bwd PSH Flags": 1 if self.bwd_psh else 0,
            "Fwd URG Flags": 1 if self.fwd_urg else 0,
            "Bwd URG Flags": 1 if self.bwd_urg else 0,
            "FIN Flag Count": 1 if self.fin else 0,
            "SYN Flag Count": 1 if self.syn else 0,
            "RST Flag Count": 1 if self.rst else 0,
            "PSH Flag Count": 1 if self.psh else 0,
            "ACK Flag Count": 1 if self.ack else 0,
            "URG Flag Count": 1 if self.urg else 0,
            "CWE Flag Count": 0,
            "ECE Flag Count": 0,
            "Fwd Header Length": sum(self.fwd_header_lens),
            "Bwd Header Length": sum(self.bwd_header_lens),
            "Fwd Header Length.1": sum(self.fwd_header_lens),
            "Fwd Packets/s": fwd_pkts_s,
            "Bwd Packets/s": bwd_pkts_s,
            "Min Packet Length": min(self.fwd_bytes + self.bwd_bytes) if (self.fwd_bytes or self.bwd_bytes) else 0,
            "Max Packet Length": max(self.fwd_bytes + self.bwd_bytes) if (self.fwd_bytes or self.bwd_bytes) else 0,
            "Packet Length Mean": np.mean(self.fwd_bytes + self.bwd_bytes) if (self.fwd_bytes or self.bwd_bytes) else 0.0,
            "Packet Length Std":  np.std(self.fwd_bytes + self.bwd_bytes)  if (self.fwd_bytes or self.bwd_bytes) else 0.0,
            "Packet Length Variance": np.var(self.fwd_bytes + self.bwd_bytes) if (self.fwd_bytes or self.bwd_bytes) else 0.0,
            "Down/Up Ratio": down_up,
            "Average Packet Size": avg_seg,
            "Avg Fwd Segment Size": fwd_seg_avg,
            "Avg Bwd Segment Size": bwd_seg_avg,
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets":  self.fwd_pkts,
            "Subflow Fwd Bytes":    fwd_bulk_bytes,
            "Subflow Bwd Packets":  self.bwd_pkts,
            "Subflow Bwd Bytes":    bwd_bulk_bytes,
            "Init_Win_bytes_forward":  self.init_fwd_win,
            "Init_Win_bytes_backward": self.init_bwd_win,
            "act_data_pkt_fwd": self.fwd_pkts,
            "min_seg_size_forward": fwd_b['min'],
            "Active Mean": act['mean'] * 1e6,
            "Active Std":  act['std']  * 1e6,
            "Active Max":  act['max']  * 1e6,
            "Active Min":  act['min']  * 1e6,
            "Idle Mean": idl['mean'] * 1e6,
            "Idle Std":  idl['std']  * 1e6,
            "Idle Max":  idl['max']  * 1e6,
            "Idle Min":  idl['min']  * 1e6,
        }


# ─────────────────────────────────────────────────────────────────────────────
# DIAGNOSTIC SCORING
# ─────────────────────────────────────────────────────────────────────────────
def diagnose_flow(key, flow):
    fv   = flow.to_feature_vector()
    row  = {col: fv.get(col, 0.0) for col in feature_columns}
    df_r = pd.DataFrame([row]).replace([np.inf, -np.inf], np.nan).fillna(0)

    x_scaled = scaler.transform(df_r)
    x_tensor = torch.tensor(x_scaled, dtype=torch.float32)

    with torch.no_grad():
        recon = model(x_tensor)
        error = torch.mean((x_tensor - recon) ** 2, dim=1).item()

    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    proto_str = proto_map.get(key[4], str(key[4]))
    verdict   = "ATTACK" if error > threshold else "BENIGN"

    print(f"\n{'─'*70}")
    print(f"  [{verdict}]  {key[0]}:{key[2]} → {key[1]}:{key[3]}  "
          f"proto={proto_str}  pkts={flow.fwd_pkts+flow.bwd_pkts}  "
          f"error={error:.6f}")
    print(f"{'─'*70}")

    # Show the top 15 worst features (largest deviation from training mean)
    scaled_vals  = x_scaled[0]
    raw_vals     = df_r.iloc[0]
    train_means  = scaler.mean_
    train_stds   = scaler.scale_

    deviations = [(
        feature_columns[i],
        float(raw_vals[feature_columns[i]]),
        float(scaled_vals[i]),          # z-score from training distribution
        float(train_means[i]),
        float(train_stds[i]),
    ) for i in range(len(feature_columns))]

    # Sort by absolute z-score (how many standard deviations from training mean)
    deviations.sort(key=lambda x: abs(x[2]), reverse=True)

    print(f"  {'Feature':<45} {'Raw Value':>15} {'Z-score':>9} "
          f"{'Train Mean':>12} {'Train Std':>10}")
    print(f"  {'-'*95}")
    for fname, raw, z, tmean, tstd in deviations[:15]:
        flag = " ← OUTLIER" if abs(z) > 3 else ""
        print(f"  {fname:<45} {raw:>15.4f} {z:>9.3f} {tmean:>12.4f} {tstd:>10.4f}{flag}")

    # Per-feature reconstruction error contribution
    raw_t  = x_tensor[0]
    rec_t  = model(x_tensor)[0]
    per_feature_errors = ((raw_t - rec_t) ** 2).detach().numpy()
    worst_recon = sorted(
        zip(feature_columns, per_feature_errors),
        key=lambda x: x[1], reverse=True
    )[:10]

    print(f"\n  Top 10 features by RECONSTRUCTION ERROR contribution:")
    print(f"  {'Feature':<45} {'Squared Error':>15}")
    print(f"  {'-'*62}")
    for fname, ferr in worst_recon:
        print(f"  {fname:<45} {ferr:>15.6f}")


# ─────────────────────────────────────────────────────────────────────────────
# FLOW TABLE
# ─────────────────────────────────────────────────────────────────────────────
class FlowTable:
    def __init__(self, flush_cb, min_pkts=4):
        self._flows   = {}
        self._lock    = threading.Lock()
        self._flush_cb = flush_cb
        self._min_pkts = min_pkts

    def process(self, pkt):
        if not pkt.haslayer(IP):
            return
        ts  = float(pkt.time)
        key = flow_key(pkt)
        if key is None:
            return
        with self._lock:
            if key not in self._flows:
                self._flows[key] = FlowStats(key, pkt, ts)
            else:
                self._flows[key].update(pkt, ts)
            flow = self._flows[key]
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags & 0x01 or flags & 0x04:
                    self._maybe_flush(key, flow)
                    return
            if ts - flow.last_ts > FLOW_TIMEOUT:
                self._maybe_flush(key, flow)

    def _maybe_flush(self, key, flow):
        if flow.fwd_pkts + flow.bwd_pkts >= self._min_pkts:
            self._flush_cb(key, flow)
        del self._flows[key]

    def flush_all(self):
        with self._lock:
            for key, flow in list(self._flows.items()):
                if flow.fwd_pkts + flow.bwd_pkts >= self._min_pkts:
                    self._flush_cb(key, flow)
            self._flows.clear()


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Diagnose feature mismatch in live traffic")
    parser.add_argument("--iface",   default=conf.iface)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--minpkts", type=int, default=4)
    parser.add_argument("--maxflows", type=int, default=5,
                        help="Stop after diagnosing this many flows (default 5)")
    args = parser.parse_args()

    print(f"Sniffing on {args.iface} for {args.timeout}s "
          f"(will fully diagnose first {args.maxflows} flows)...\n")

    flow_count = [0]

    def flush_cb(key, flow):
        if flow_count[0] >= args.maxflows:
            return
        flow_count[0] += 1
        diagnose_flow(key, flow)

    table = FlowTable(flush_cb=flush_cb, min_pkts=args.minpkts)

    try:
        sniff(
            iface=args.iface,
            filter="ip",
            prn=table.process,
            store=False,
            timeout=args.timeout,
        )
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        table.flush_all()

    print(f"\n{'='*70}")
    print("  DIAGNOSIS COMPLETE")
    print(f"{'='*70}")

if __name__ == "__main__":
    main()