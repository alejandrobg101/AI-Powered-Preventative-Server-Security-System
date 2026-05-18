import argparse
import sqlite3
import time
import subprocess
import math
import string
import sys
import os
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from xml.etree.ElementTree import tostring

from schema import create_db, db_reset
from db_functions import (
    db_insert_events,
    db_read,
    write_summary,
    load_threshold
)

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import joblib

from scapy.all import (
    sniff, IP, TCP, UDP, ICMP,
    wrpcap, conf
)

from risk_classifier import classify as classify_risk, load_thresholds as load_risk_thresholds
from response_engine import (
    infer_anomaly_type,
    get_recommendation,
    format_response_block,
)


# --------------------------------------─
# AUTOENCODER  (must match training architecture exactly)
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

if "--no-reset" not in sys.argv:
    db_reset()
create_db()

# --------------------------------------─
# LOAD ARTIFACTS
# --------------------------------------─
feature_columns: list = joblib.load("artifacts/feature_columns.pkl")
scaler = joblib.load("artifacts/scaler.pkl")
threshold = load_threshold()
risk_thresholds: dict = load_risk_thresholds("artifacts")

model = Autoencoder(len(feature_columns))
model.load_state_dict(torch.load("artifacts/autoencoder_model.pth", map_location="cpu"))
model.eval()

print(f"[INFO] Model loaded - {len(feature_columns)} features, threshold={threshold:.6f}")


# last_state = None

# def update_summary_if_needed():
#     global last_state
#
#     current_state = db_read()
#
#     if current_state != last_state:
#         write_summary(current_state)
#         last_state = current_state

# update_summary_if_needed()
# Show scaler mean/std for flag features so we understand the training distribution
flag_features = ["ACK Flag Count", "SYN Flag Count", "FIN Flag Count", "PSH Flag Count", "Fwd PSH Flags"]
print("[INFO] Scaler stats for flag features (mean ± std from training data):")
for fname in flag_features:
    if fname in feature_columns:
        idx = feature_columns.index(fname)
        print(f"  {fname:<30}  mean={scaler.mean_[idx]:.4f}  std={scaler.scale_[idx]:.4f}")


# --------------------------------------─
# FLOW KEY  (5-tuple, direction-normalised so fwd/bwd are consistent)
# --------------------------------------─
def flow_key(pkt) -> tuple | None:
    """Return a canonical (src_ip, dst_ip, src_port, dst_port, proto) tuple."""
    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    proto = ip.proto  # 6=TCP, 17=UDP, 1=ICMP

    if pkt.haslayer(TCP):
        sp, dp = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sp, dp = pkt[UDP].sport, pkt[UDP].dport
    else:
        sp, dp = 0, 0  # ICMP / other

    # Normalise direction: smaller (ip,port) pair always goes first
    if (ip.src, sp) <= (ip.dst, dp):
        return (ip.src, ip.dst, sp, dp, proto)
    return (ip.dst, ip.src, dp, sp, proto)


# --------------------------------------─
# PER-FLOW STATISTICS ACCUMULATOR
# --------------------------------------─
FLOW_TIMEOUT = 120.0  # seconds of inactivity before a flow is flushed
IAT_WINDOW = 100  # keep last N inter-arrival times


class FlowStats:
    """Accumulates packet-level data and computes CIC-IDS2017-compatible features."""

    def __init__(self, key: tuple, first_pkt, ts: float):
        self.key = key
        self.proto = key[4]

        # --- timing ---
        self.start_ts = ts
        self.last_ts = ts
        self.fwd_last_ts: float | None = None
        self.bwd_last_ts: float | None = None

        # --- packet / byte counts ---
        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.fwd_bytes: list[int] = []
        self.bwd_bytes: list[int] = []

        # --- inter-arrival times ---
        self.fwd_iats: list[float] = []
        self.bwd_iats: list[float] = []
        self.flow_iats: list[float] = []
        self._all_ts: deque = deque(maxlen=IAT_WINDOW + 1)
        self._all_ts.append(ts)

        # --- TCP flags (cumulative OR) ---
        self.fwd_psh = self.fwd_urg = 0
        self.bwd_psh = self.bwd_urg = 0
        self.fin = self.syn = self.rst = self.psh = self.ack = self.urg = 0

        # --- header / window sizes ---
        self.fwd_header_lens: list[int] = []
        self.bwd_header_lens: list[int] = []
        self.init_fwd_win = 0
        self.init_bwd_win = 0
        self._init_fwd_set = False
        self._init_bwd_set = False

        # --- active / idle time ---
        self.active_times: list[float] = []
        self.idle_times: list[float] = []
        self._active_start: float = ts
        self._last_active: float = ts
        self._IDLE_THRESH = 1.0  # seconds gap ⟹ idle period

        self._add_packet(first_pkt, ts, forward=True)

    # - helpers -------------------------------

    @staticmethod
    def _tcp_flags(pkt) -> dict:
        flags = {}
        if pkt.haslayer(TCP):
            f = pkt[TCP].flags
            flags = {
                'FIN': bool(f & 0x01), 'SYN': bool(f & 0x02),
                'RST': bool(f & 0x04), 'PSH': bool(f & 0x08),
                'ACK': bool(f & 0x10), 'URG': bool(f & 0x20),
            }
        return flags

    @staticmethod
    def _payload_len(pkt) -> int:
        if pkt.haslayer(TCP):
            return len(pkt[TCP].payload)
        if pkt.haslayer(UDP):
            return len(pkt[UDP].payload)
        return len(pkt[IP].payload)

    @staticmethod
    def _ip_len(pkt) -> int:
        return pkt[IP].len if pkt.haslayer(IP) else 0

    @staticmethod
    def _header_len(pkt) -> int:
        if pkt.haslayer(TCP):
            return pkt[TCP].dataofs * 4 + 20  # TCP hdr + IP hdr (approx)
        if pkt.haslayer(UDP):
            return 8 + 20
        return 20

    # - packet ingestion --------------------------─

    def _add_packet(self, pkt, ts: float, forward: bool):
        plen = self._ip_len(pkt)
        hlen = self._header_len(pkt)
        flags = self._tcp_flags(pkt)

        # Active / idle tracking
        gap = ts - self._last_active
        if gap > self._IDLE_THRESH:
            self.idle_times.append(gap)
            self.active_times.append(self._last_active - self._active_start)
            self._active_start = ts
        self._last_active = ts

        # Flow IAT
        if len(self._all_ts) > 0:
            self.flow_iats.append(ts - self._all_ts[-1])
        self._all_ts.append(ts)

        # Cumulative TCP flags
        for name, val in flags.items():
            if val:
                setattr(self, name.lower(), getattr(self, name.lower()) + 1)

        if forward:
            self.fwd_pkts += 1
            self.fwd_bytes.append(plen)
            self.fwd_header_lens.append(hlen)
            if flags.get('PSH'):
                self.fwd_psh += 1
            if flags.get('URG'):
                self.fwd_urg += 1
            if not self._init_fwd_set and pkt.haslayer(TCP):
                self.init_fwd_win = pkt[TCP].window
                self._init_fwd_set = True
            if self.fwd_last_ts is not None:
                self.fwd_iats.append(ts - self.fwd_last_ts)
            self.fwd_last_ts = ts
        else:
            self.bwd_pkts += 1
            self.bwd_bytes.append(plen)
            self.bwd_header_lens.append(hlen)
            if flags.get('PSH'):
                self.bwd_psh += 1
            if flags.get('URG'):
                self.bwd_urg += 1
            if not self._init_bwd_set and pkt.haslayer(TCP):
                self.init_bwd_win = pkt[TCP].window
                self._init_bwd_set = True
            if self.bwd_last_ts is not None:
                self.bwd_iats.append(ts - self.bwd_last_ts)
            self.bwd_last_ts = ts

        self.last_ts = ts

    def update(self, pkt, ts: float):
        src_ip = pkt[IP].src if pkt.haslayer(IP) else ""
        forward = (src_ip == self.key[0])
        self._add_packet(pkt, ts, forward)

    # - statistical helpers -------------------------─

    @staticmethod
    def _stats(lst: list) -> dict:
        """Return mean, std, max, min of a list (or zeros if empty)."""
        if not lst:
            return {'mean': 0.0, 'std': 0.0, 'max': 0.0, 'min': 0.0}
        a = np.array(lst, dtype=float)
        return {
            'mean': float(a.mean()),
            'std': float(a.std()),
            'max': float(a.max()),
            'min': float(a.min()),
        }

    # - feature vector ----------------------------

    def to_feature_vector(self) -> dict:
        """
        Build a dict matching the CIC-IDS2017 column names used during training.
        All 78 numeric features are produced; non-applicable ones default to 0.
        """
        duration_s = max(self.last_ts - self.start_ts, 1e-9)  # seconds, avoid div/0
        duration_us = duration_s * 1e6  # microseconds like CIC-IDS2017
        total_pkts = self.fwd_pkts + self.bwd_pkts
        total_bytes = sum(self.fwd_bytes) + sum(self.bwd_bytes)

        fwd_b = self._stats(self.fwd_bytes)
        bwd_b = self._stats(self.bwd_bytes)
        fwd_i = self._stats(self.fwd_iats)
        bwd_i = self._stats(self.bwd_iats)
        flow_i = self._stats(self.flow_iats)
        act = self._stats(self.active_times)
        idl = self._stats(self.idle_times)
        fwd_h = self._stats(self.fwd_header_lens)
        bwd_h = self._stats(self.bwd_header_lens)

        # CIC-IDS2017 stores rates as bytes/µs and packets/µs
        flow_pkts_s = total_pkts / duration_us
        flow_bytes_s = total_bytes / duration_us
        fwd_pkts_s = self.fwd_pkts / duration_us
        bwd_pkts_s = self.bwd_pkts / duration_us

        # down/up ratio
        down_up = (self.bwd_pkts / self.fwd_pkts) if self.fwd_pkts else 0.0

        # segment sizes (payload-level)
        fwd_seg_avg = fwd_b['mean'] - fwd_h['mean'] if self.fwd_pkts else 0.0
        bwd_seg_avg = bwd_b['mean'] - bwd_h['mean'] if self.bwd_pkts else 0.0
        avg_seg = (total_bytes / total_pkts) if total_pkts else 0.0

        # bulk rates also in per-microsecond to match dataset
        fwd_bulk_bytes = sum(self.fwd_bytes)
        bwd_bulk_bytes = sum(self.bwd_bytes)

        fwd_bulk_rate = fwd_bulk_bytes / duration_us
        bwd_bulk_rate = bwd_bulk_bytes / duration_us

        # subflow (treat as 1 subflow = entire flow)
        sf_fwd_pkts = self.fwd_pkts
        sf_bwd_pkts = self.bwd_pkts
        sf_fwd_bytes = fwd_bulk_bytes
        sf_bwd_bytes = bwd_bulk_bytes

        fv = {
            # - basic packet/byte counts -----------------
            "Destination Port": self.key[3],
            "Flow Duration": duration_us,
            "Total Fwd Packets": self.fwd_pkts,
            "Total Backward Packets": self.bwd_pkts,
            "Total Length of Fwd Packets": fwd_bulk_bytes,
            "Total Length of Bwd Packets": bwd_bulk_bytes,

            # - per-direction packet-length stats ------------─
            "Fwd Packet Length Max": fwd_b['max'],
            "Fwd Packet Length Min": fwd_b['min'],
            "Fwd Packet Length Mean": fwd_b['mean'],
            "Fwd Packet Length Std": fwd_b['std'],
            "Bwd Packet Length Max": bwd_b['max'],
            "Bwd Packet Length Min": bwd_b['min'],
            "Bwd Packet Length Mean": bwd_b['mean'],
            "Bwd Packet Length Std": bwd_b['std'],

            # - throughput ------------------------
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,

            # - inter-arrival times (µs like CIC-IDS2017) --------
            "Flow IAT Mean": flow_i['mean'] * 1e6,
            "Flow IAT Std": flow_i['std'] * 1e6,
            "Flow IAT Max": flow_i['max'] * 1e6,
            "Flow IAT Min": flow_i['min'] * 1e6,
            "Fwd IAT Total": sum(self.fwd_iats) * 1e6,
            "Fwd IAT Mean": fwd_i['mean'] * 1e6,
            "Fwd IAT Std": fwd_i['std'] * 1e6,
            "Fwd IAT Max": fwd_i['max'] * 1e6,
            "Fwd IAT Min": fwd_i['min'] * 1e6,
            "Bwd IAT Total": sum(self.bwd_iats) * 1e6,
            "Bwd IAT Mean": bwd_i['mean'] * 1e6,
            "Bwd IAT Std": bwd_i['std'] * 1e6,
            "Bwd IAT Max": bwd_i['max'] * 1e6,
            "Bwd IAT Min": bwd_i['min'] * 1e6,

            # - TCP flags ------------------------─
            # CICFlowMeter records whether a flag was ever seen (0 or 1),
            # not the total count per packet. Binary encoding matches training.
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

            # - header lengths ----------------------
            "Fwd Header Length": sum(self.fwd_header_lens),
            "Bwd Header Length": sum(self.bwd_header_lens),
            "Fwd Header Length.1": sum(self.fwd_header_lens),  # duplicate col in dataset

            # - pkt/s per direction -------------------─
            "Fwd Packets/s": fwd_pkts_s,
            "Bwd Packets/s": bwd_pkts_s,

            # - overall packet-length stats ---------------─
            "Min Packet Length": min(self.fwd_bytes + self.bwd_bytes) if (self.fwd_bytes or self.bwd_bytes) else 0,
            "Max Packet Length": max(self.fwd_bytes + self.bwd_bytes) if (self.fwd_bytes or self.bwd_bytes) else 0,
            "Packet Length Mean": np.mean(self.fwd_bytes + self.bwd_bytes) if (
                        self.fwd_bytes or self.bwd_bytes) else 0.0,
            "Packet Length Std": np.std(self.fwd_bytes + self.bwd_bytes) if (self.fwd_bytes or self.bwd_bytes) else 0.0,
            "Packet Length Variance": np.var(self.fwd_bytes + self.bwd_bytes) if (
                        self.fwd_bytes or self.bwd_bytes) else 0.0,

            # - ratios / misc ----------------------─
            "Down/Up Ratio": down_up,
            "Average Packet Size": avg_seg,
            "Avg Fwd Segment Size": fwd_seg_avg,
            "Avg Bwd Segment Size": bwd_seg_avg,

            # - bulk / subflow ----------------------
            # NOTE: CICFlowMeter bulk detection requires tracking multi-packet
            # bursts with specific thresholds. Zeroing these out is more accurate
            # than a wrong approximation, since the scaler was fit on near-zero values.
            "Fwd Avg Bytes/Bulk": 0.0,
            "Fwd Avg Packets/Bulk": 0.0,
            "Fwd Avg Bulk Rate": 0.0,
            "Bwd Avg Bytes/Bulk": 0.0,
            "Bwd Avg Packets/Bulk": 0.0,
            "Bwd Avg Bulk Rate": 0.0,
            "Subflow Fwd Packets": sf_fwd_pkts,
            "Subflow Fwd Bytes": sf_fwd_bytes,
            "Subflow Bwd Packets": sf_bwd_pkts,
            "Subflow Bwd Bytes": sf_bwd_bytes,

            # - window / segment sizes ------------------
            "Init_Win_bytes_forward": self.init_fwd_win,
            "Init_Win_bytes_backward": self.init_bwd_win,
            "act_data_pkt_fwd": self.fwd_pkts,  # pkts with payload
            "min_seg_size_forward": fwd_b['min'],

            # - active / idle (µs like CIC-IDS2017) -----------
            "Active Mean": act['mean'] * 1e6,
            "Active Std": act['std'] * 1e6,
            "Active Max": act['max'] * 1e6,
            "Active Min": act['min'] * 1e6,
            "Idle Mean": idl['mean'] * 1e6,
            "Idle Std": idl['std'] * 1e6,
            "Idle Max": idl['max'] * 1e6,
            "Idle Min": idl['min'] * 1e6,
        }

        return fv


# --------------------------------------─
# FLOW TABLE
# --------------------------------------─
class FlowTable:
    """Thread-safe dictionary of active FlowStats objects."""

    def __init__(self, flush_cb, min_pkts: int = 4):
        self._flows: dict[tuple, FlowStats] = {}
        self._lock = threading.Lock()
        self._flush_cb = flush_cb  # called with (key, FlowStats) when flushed
        self._min_pkts = min_pkts  # ignore flows with fewer packets

    def process(self, pkt):
        if not pkt.haslayer(IP):
            return
        ts = float(pkt.time)
        key = flow_key(pkt)
        if key is None:
            return

        with self._lock:
            if key not in self._flows:
                self._flows[key] = FlowStats(key, pkt, ts)
            else:
                self._flows[key].update(pkt, ts)

            flow = self._flows[key]

            # TCP FIN/RST ⟹ flush immediately
            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags & 0x01 or flags & 0x04:  # FIN or RST
                    self._maybe_flush(key, flow)
                    return

            # Timeout check
            if ts - flow.last_ts > FLOW_TIMEOUT:
                self._maybe_flush(key, flow)

    def _maybe_flush(self, key: tuple, flow: FlowStats):
        total = flow.fwd_pkts + flow.bwd_pkts
        if total >= self._min_pkts:
            self._flush_cb(key, flow)
        del self._flows[key]

    def flush_all(self):
        with self._lock:
            for key, flow in list(self._flows.items()):
                total = flow.fwd_pkts + flow.bwd_pkts
                if total >= self._min_pkts:
                    self._flush_cb(key, flow)
            self._flows.clear()


# --------------------------------------─
# SCORING
# --------------------------------------─
DEBUG = False  # set via --debug flag; prints per-feature scaled values


def score_flow(key: tuple, flow: FlowStats):
    """Extract features, run autoencoder, classify risk + anomaly type, persist to DB."""
    fv = flow.to_feature_vector()

    # Align to training feature order; fill missing cols with 0
    row = {col: fv.get(col, 0.0) for col in feature_columns}
    df_row = pd.DataFrame([row])
    df_row = df_row.replace([np.inf, -np.inf], np.nan).fillna(0)

    x_scaled = scaler.transform(df_row)
    x_tensor = torch.tensor(x_scaled, dtype=torch.float32)

    with torch.no_grad():
        recon = model(x_tensor)
        error = torch.mean((x_tensor - recon) ** 2, dim=1).item()

    risk          = classify_risk(error, risk_thresholds)
    anomaly_type  = infer_anomaly_type(flow, key)
    rec           = get_recommendation(anomaly_type, risk.name)
    proto_map     = {6: "TCP", 17: "UDP", 1: "ICMP"}
    proto_str     = proto_map.get(key[4], str(key[4]))
    src_ip        = key[0]
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # print(
    #     f"[{risk.label}]  {key[0]}:{key[2]} → {key[1]}:{key[3]}  "
    #     f"proto={proto_str}  pkts={flow.fwd_pkts + flow.bwd_pkts}  "
    #     f"bytes={sum(flow.fwd_bytes) + sum(flow.bwd_bytes)}  "
    #     f"error={error:.6f}  type={anomaly_type}"
    # )

    alert = {
        "timestamp": current_time,
        "risk": risk.label,
        "src_ip": key[0],
        "dst_ip": key[1],
        "src_port": key[2],
        "dst_port": key[3],
        "protocol": proto_str,
        "packets": flow.fwd_pkts + flow.bwd_pkts,
        "bytes": sum(flow.fwd_bytes) + sum(flow.bwd_bytes),
        "error": error,
        "type": anomaly_type,
    }

    alert_text = (
        f"Time: {alert['timestamp']}\n"
        f"[{alert['risk']}]\n"
        f"Source: {alert['src_ip']}:{alert['src_port']}\n"
        f"Destination: {alert['dst_ip']}:{alert['dst_port']}\n"
        f"Protocol: {alert['protocol']}\n"
        f"Packets: {alert['packets']}\n"
        f"Bytes: {alert['bytes']}\n"
        f"Error: {alert['error']:.6f}\n"
        f"Type: {alert['type']}\n"
        f"{'-' * 40}\n"
    )

    with open("logs/live_alerts.txt", "a", encoding="utf-8") as f:
        f.write(alert_text)

    # if risk.code >= 2:  # High or Critical — print full response block
    #     print("Important Risk Detected: Log will be created for recommended response steps.")
    #     print("Log name will correspond to this entry's id in the database.")
    #     print("Example: logs/response_logs/[database id number].txt")
    #     # print(format_response_block(rec, src_ip))
    # elif risk.code == 1:  # Medium — print one-line action
    #     print(f"  Action: {rec.summary}")

    if risk.code > 0:
        # Check if there is anything to read
        db_insert_events(anomaly_type=anomaly_type, ip=str(src_ip), error=error, risk=risk, recommendation=rec)
        # update_summary_if_needed()
    else:
        #Increment the persistent counter for the FPR denominator
        from db_functions import db_increment_low_count
        db_increment_low_count()

    if DEBUG:
        scaled_row = x_scaled[0]
        worst = sorted(zip(feature_columns, scaled_row), key=lambda x: abs(x[1]), reverse=True)[:10]
        print("  Top 10 features by scaled magnitude (raw → scaled):")
        for fname, sval in worst:
            raw = df_row[fname].iloc[0]
            print(f"    {fname:<40}  raw={raw:>15.4f}  scaled={sval:>10.4f}")


# --------------------------------------─
# PERIODIC TIMEOUT FLUSHER
# --------------------------------------─
class TimeoutFlusher(threading.Thread):
    """Background thread that evicts timed-out flows every `interval` seconds."""

    def __init__(self, flow_table: FlowTable, interval: float = 10.0):
        super().__init__(daemon=True)
        self._table = flow_table
        self._interval = interval
        self._stop_evt = threading.Event()

    def run(self):
        while not self._stop_evt.wait(self._interval):
            now = time.time()
            with self._table._lock:
                timed_out = [
                    k for k, f in self._table._flows.items()
                    if now - f.last_ts > FLOW_TIMEOUT
                ]
                for k in timed_out:
                    self._table._maybe_flush(k, self._table._flows[k])

    def stop(self):
        self._stop_evt.set()


# --------------------------------------─
# MAIN
# --------------------------------------─
def main():
    parser = argparse.ArgumentParser(description="Live IDS capture with autoencoder scoring")
    parser.add_argument("--iface", default=conf.iface, help="Network interface to sniff on")
    parser.add_argument("--timeout", type=int, default=0, help="Stop after N seconds (0=forever)")
    parser.add_argument("--pcap", action="store_true", help="Save captured packets to live.pcap")
    parser.add_argument("--minpkts", type=int, default=4, help="Minimum packets to score a flow (default 4)")
    parser.add_argument("--debug", action="store_true", help="Print top 10 outlier features per flow")
    parser.add_argument("--no-reset", action="store_true", help="Skip database reset prompt (used when launched from dashboard)")
    parser.add_argument("--no-dashboard", action="store_true", help="Skip auto-launching the dashboard (used when dashboard is already running)")
    parser.add_argument("--threshold", type=float, default=None,
                        help="Override model threshold (default: use saved value)")
    args = parser.parse_args()

    global DEBUG, threshold
    DEBUG = args.debug
    if args.threshold is not None:
        threshold = args.threshold
        print(f"[INFO] Threshold overridden to {threshold:.6f}")

    print(f"[INFO] Sniffing on interface: {args.iface}")
    print(f"[INFO] Flow timeout: {FLOW_TIMEOUT}s   min packets: {args.minpkts}")
    print("[INFO] Press Ctrl+C to stop.\n")

    captured_pkts = []
    table = FlowTable(flush_cb=score_flow, min_pkts=args.minpkts)
    flusher = TimeoutFlusher(table, interval=10.0)
    flusher.start()

    def handle(pkt):
        if args.pcap:
            captured_pkts.append(pkt)
        table.process(pkt)

    if not args.no_dashboard:
        subprocess.Popen([sys.executable, "-m", "streamlit", "run", "dashboard.py"])

    try:
        sniff(
            iface=args.iface,
            filter="ip",  # BPF: IPv4 only
            prn=handle,
            store=False,
            timeout=args.timeout if args.timeout > 0 else None,
        )
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")
    finally:
        print("[INFO] Flushing remaining flows …")
        flusher.stop()
        table.flush_all()

        if args.pcap and captured_pkts:
            wrpcap("live.pcap", captured_pkts)
            print(f"[INFO] Saved {len(captured_pkts):,} packets to live.pcap")
        dashboard_process.terminate()
        # and
        log_file = "logs/live_alerts.txt"

        if os.path.exists(log_file):
            os.remove(log_file)
        print("[INFO] Done.")


if __name__ == "__main__":
    main()
