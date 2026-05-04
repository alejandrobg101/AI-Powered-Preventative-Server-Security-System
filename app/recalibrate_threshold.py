"""
recalibrate_threshold.py
------------
Sniffs your live network for a window of KNOWN-GOOD traffic,
computes reconstruction errors on those flows, and saves a new
threshold to artifacts/threshold.pkl.

This solves the "everything looks like an attack" problem when the
training-set threshold doesn't match the live traffic distribution.

Usage:
    python recalibrate_threshold.py --iface "Intel(R) Wi-Fi 6 AX201 160MHz" --timeout 120
    # Browse normally for 2 minutes, then the new threshold is saved.
"""

from __future__ import annotations
from db_functions import save_threshold

import argparse
import threading
from collections import deque

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import joblib

from scapy.all import sniff, IP, TCP, UDP, conf

FLOW_TIMEOUT = 120.0
IAT_WINDOW   = 100


# --------------------------------------─
# AUTOENCODER
# --------------------------------------─
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


# --------------------------------------─
# LOAD ARTIFACTS
# --------------------------------------─
feature_columns: list = joblib.load("artifacts/feature_columns.pkl")
scaler          = joblib.load("artifacts/scaler.pkl")
old_threshold   = joblib.load("artifacts/threshold.pkl")

model = Autoencoder(len(feature_columns))
model.load_state_dict(torch.load("artifacts/autoencoder_model.pth", map_location="cpu"))
model.eval()

print(f"\n{'='*60}")
print(f"  LIVE THRESHOLD RECALIBRATION")
print(f"{'='*60}")
print(f"  Current threshold : {old_threshold:.6f}")
print(f"  Features          : {len(feature_columns)}")
print(f"{'='*60}")
print("  Browse normally while this runs — it will learn what")
print("  YOUR traffic looks like and set a proper threshold.\n")


# --------------------------------------─
# FLOW KEY
# --------------------------------------─
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


# --------------------------------------─
# FLOW STATS
# --------------------------------------─
class FlowStats:
    def __init__(self, key, first_pkt, ts):
        self.key         = key
        self.proto       = key[4]
        self.start_ts    = ts
        self.last_ts     = ts
        self.fwd_last_ts: float | None = None
        self.bwd_last_ts: float | None = None
        self.fwd_pkts    = 0
        self.bwd_pkts    = 0
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
        self.init_fwd_win    = 0
        self.init_bwd_win    = 0
        self._init_fwd_set   = False
        self._init_bwd_set   = False
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
        gap   = ts - self._last_active
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
            if flags.get('PSH'): self.fwd_psh += 1
            if flags.get('URG'): self.fwd_urg += 1
            if not self._init_fwd_set and pkt.haslayer(TCP):
                self.init_fwd_win  = pkt[TCP].window
                self._init_fwd_set = True
            if self.fwd_last_ts is not None:
                self.fwd_iats.append(ts - self.fwd_last_ts)
            self.fwd_last_ts = ts
        else:
            self.bwd_pkts += 1
            self.bwd_bytes.append(plen)
            self.bwd_header_lens.append(hlen)
            if flags.get('PSH'): self.bwd_psh += 1
            if flags.get('URG'): self.bwd_urg += 1
            if not self._init_bwd_set and pkt.haslayer(TCP):
                self.init_bwd_win  = pkt[TCP].window
                self._init_bwd_set = True
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
                'max':  float(a.max()),  'min': float(a.min())}

    def to_feature_vector(self) -> dict:
        duration_s   = max(self.last_ts - self.start_ts, 1e-9)
        duration_us  = duration_s * 1e6
        total_pkts   = self.fwd_pkts + self.bwd_pkts
        total_bytes  = sum(self.fwd_bytes) + sum(self.bwd_bytes)
        fwd_b  = self._stats(self.fwd_bytes)
        bwd_b  = self._stats(self.bwd_bytes)
        fwd_i  = self._stats(self.fwd_iats)
        bwd_i  = self._stats(self.bwd_iats)
        flow_i = self._stats(self.flow_iats)
        act    = self._stats(self.active_times)
        idl    = self._stats(self.idle_times)
        fwd_h  = self._stats(self.fwd_header_lens)
        bwd_h  = self._stats(self.bwd_header_lens)
        fbd    = sum(self.fwd_bytes)
        bbd    = sum(self.bwd_bytes)
        return {
            "Destination Port":            self.key[3],
            "Flow Duration":               duration_us,
            "Total Fwd Packets":           self.fwd_pkts,
            "Total Backward Packets":      self.bwd_pkts,
            "Total Length of Fwd Packets": fbd,
            "Total Length of Bwd Packets": bbd,
            "Fwd Packet Length Max":  fwd_b['max'],  "Fwd Packet Length Min":  fwd_b['min'],
            "Fwd Packet Length Mean": fwd_b['mean'], "Fwd Packet Length Std":  fwd_b['std'],
            "Bwd Packet Length Max":  bwd_b['max'],  "Bwd Packet Length Min":  bwd_b['min'],
            "Bwd Packet Length Mean": bwd_b['mean'], "Bwd Packet Length Std":  bwd_b['std'],
            "Flow Bytes/s":    total_bytes / duration_us,
            "Flow Packets/s":  total_pkts  / duration_us,
            "Flow IAT Mean": flow_i['mean']*1e6, "Flow IAT Std": flow_i['std']*1e6,
            "Flow IAT Max":  flow_i['max']*1e6,  "Flow IAT Min": flow_i['min']*1e6,
            "Fwd IAT Total": sum(self.fwd_iats)*1e6,
            "Fwd IAT Mean":  fwd_i['mean']*1e6, "Fwd IAT Std": fwd_i['std']*1e6,
            "Fwd IAT Max":   fwd_i['max']*1e6,  "Fwd IAT Min": fwd_i['min']*1e6,
            "Bwd IAT Total": sum(self.bwd_iats)*1e6,
            "Bwd IAT Mean":  bwd_i['mean']*1e6, "Bwd IAT Std": bwd_i['std']*1e6,
            "Bwd IAT Max":   bwd_i['max']*1e6,  "Bwd IAT Min": bwd_i['min']*1e6,
            "Fwd PSH Flags": 1 if self.fwd_psh else 0,
            "Bwd PSH Flags": 1 if self.bwd_psh else 0,
            "Fwd URG Flags": 1 if self.fwd_urg else 0,
            "Bwd URG Flags": 1 if self.bwd_urg else 0,
            "FIN Flag Count": 1 if self.fin else 0, "SYN Flag Count": 1 if self.syn else 0,
            "RST Flag Count": 1 if self.rst else 0, "PSH Flag Count": 1 if self.psh else 0,
            "ACK Flag Count": 1 if self.ack else 0, "URG Flag Count": 1 if self.urg else 0,
            "CWE Flag Count": 0, "ECE Flag Count": 0,
            "Fwd Header Length":   sum(self.fwd_header_lens),
            "Bwd Header Length":   sum(self.bwd_header_lens),
            "Fwd Header Length.1": sum(self.fwd_header_lens),
            "Fwd Packets/s": self.fwd_pkts / duration_us,
            "Bwd Packets/s": self.bwd_pkts / duration_us,
            "Min Packet Length": min(self.fwd_bytes+self.bwd_bytes) if (self.fwd_bytes or self.bwd_bytes) else 0,
            "Max Packet Length": max(self.fwd_bytes+self.bwd_bytes) if (self.fwd_bytes or self.bwd_bytes) else 0,
            "Packet Length Mean": np.mean(self.fwd_bytes+self.bwd_bytes) if (self.fwd_bytes or self.bwd_bytes) else 0.0,
            "Packet Length Std":  np.std(self.fwd_bytes+self.bwd_bytes)  if (self.fwd_bytes or self.bwd_bytes) else 0.0,
            "Packet Length Variance": np.var(self.fwd_bytes+self.bwd_bytes) if (self.fwd_bytes or self.bwd_bytes) else 0.0,
            "Down/Up Ratio":        (self.bwd_pkts/self.fwd_pkts) if self.fwd_pkts else 0.0,
            "Average Packet Size":  (total_bytes/total_pkts) if total_pkts else 0.0,
            "Avg Fwd Segment Size": fwd_b['mean']-fwd_h['mean'] if self.fwd_pkts else 0.0,
            "Avg Bwd Segment Size": bwd_b['mean']-bwd_h['mean'] if self.bwd_pkts else 0.0,
            "Fwd Avg Bytes/Bulk": 0.0, "Fwd Avg Packets/Bulk": 0.0, "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0, "Bwd Avg Packets/Bulk": 0.0, "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": self.fwd_pkts, "Subflow Fwd Bytes": fbd,
            "Subflow Bwd Packets": self.bwd_pkts, "Subflow Bwd Bytes": bbd,
            "Init_Win_bytes_forward":  self.init_fwd_win,
            "Init_Win_bytes_backward": self.init_bwd_win,
            "act_data_pkt_fwd":    self.fwd_pkts,
            "min_seg_size_forward": fwd_b['min'],
            "Active Mean": act['mean']*1e6, "Active Std": act['std']*1e6,
            "Active Max":  act['max']*1e6,  "Active Min": act['min']*1e6,
            "Idle Mean": idl['mean']*1e6,   "Idle Std":   idl['std']*1e6,
            "Idle Max":  idl['max']*1e6,    "Idle Min":   idl['min']*1e6,
        }


# --------------------------------------─
# FLOW TABLE
# --------------------------------------─
live_errors: list[float] = []


def collect_error(key, flow):
    fv   = flow.to_feature_vector()
    row  = {col: fv.get(col, 0.0) for col in feature_columns}
    df_r = pd.DataFrame([row]).replace([np.inf, -np.inf], np.nan).fillna(0)
    x_sc = scaler.transform(df_r)
    xt   = torch.tensor(x_sc, dtype=torch.float32)
    with torch.no_grad():
        recon = model(xt)
        error = torch.mean((xt - recon) ** 2, dim=1).item()
    live_errors.append(error)
    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    print(f"  Flow {len(live_errors):>4}: {key[0]}:{key[2]}→{key[1]}:{key[3]} "
          f"proto={proto_map.get(key[4], str(key[4]))} "
          f"pkts={flow.fwd_pkts+flow.bwd_pkts} error={error:.6f}")


class FlowTable:
    def __init__(self, flush_cb, min_pkts=4):
        self._flows    = {}
        self._lock     = threading.Lock()
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


# --------------------------------------─
# MAIN
# --------------------------------------─
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface",      default=conf.iface)
    parser.add_argument("--timeout",    type=int, default=120)
    parser.add_argument("--minpkts",    type=int, default=4)
    parser.add_argument("--percentile", type=float, default=99.0,
                        help="Set threshold at this percentile of live benign errors (default 99.0)")
    args = parser.parse_args()

    print(f"  Sniffing {args.iface} for {args.timeout}s...")
    print(f"  Threshold percentile: {args.percentile}%\n")

    table = FlowTable(flush_cb=collect_error, min_pkts=args.minpkts)

    try:
        sniff(iface=args.iface, filter="ip",
              prn=table.process, store=False, timeout=args.timeout)
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

    print(f"\n{'='*60}")
    print(f"  RECALIBRATION RESULTS  ({len(errors)} flows)")
    print(f"{'='*60}")
    print(f"  Old threshold : {old_threshold:.6f}")
    print(f"  New threshold : {new_threshold:.6f}  ({args.percentile}th pct)")
    print(f"  New threshold saved to database.")
    print(f"  Error stats   : min={errors.min():.6f}  "
          f"p50={np.percentile(errors,50):.6f}  "
          f"p95={np.percentile(errors,95):.6f}  "
          f"p99={np.percentile(errors,99):.6f}  "
          f"max={errors.max():.6f}")

    # Save the new threshold
    joblib.dump(new_threshold, "artifacts/threshold.pkl")
    print(f"\n  ✓ Saved new threshold → artifacts/threshold.pkl")
    print(f"\n  Now run:")
    print(f"    python live_capture.py --iface \"{args.iface}\"")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()