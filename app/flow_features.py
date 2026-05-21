"""Packet-to-flow aggregation and CIC-IDS2017-style feature extraction."""

from __future__ import annotations

import threading
from collections import deque

import numpy as np
from scapy.all import IP, TCP, UDP

FLOW_TIMEOUT = 120.0  # seconds of inactivity before a flow is flushed
IAT_WINDOW = 100      # keep the latest timestamps for inter-arrival features


def flow_key(pkt) -> tuple | None:
    """Return a direction-normalized (src, dst, sport, dport, proto) tuple."""
    if not pkt.haslayer(IP):
        return None

    ip = pkt[IP]
    proto = ip.proto
    if pkt.haslayer(TCP):
        sp, dp = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        sp, dp = pkt[UDP].sport, pkt[UDP].dport
    else:
        # ICMP and other IP protocols do not have ports, so keep tuple shape.
        sp, dp = 0, 0

    if (ip.src, sp) <= (ip.dst, dp):
        return (ip.src, ip.dst, sp, dp, proto)
    return (ip.dst, ip.src, dp, sp, proto)


class FlowStats:
    """Accumulate packet-level data and produce model-compatible features."""

    def __init__(self, key: tuple, first_pkt, ts: float):
        self.key = key
        self.proto = key[4]

        self.start_ts = ts
        self.last_ts = ts
        self.fwd_last_ts: float | None = None
        self.bwd_last_ts: float | None = None

        self.fwd_pkts = 0
        self.bwd_pkts = 0
        self.fwd_bytes: list[int] = []
        self.bwd_bytes: list[int] = []

        self.fwd_iats: list[float] = []
        self.bwd_iats: list[float] = []
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
        self.idle_times: list[float] = []
        self._active_start = ts
        self._last_active = ts
        self._idle_threshold = 1.0

        self._add_packet(first_pkt, ts, forward=True)

    @staticmethod
    def _tcp_flags(pkt) -> dict:
        """Return TCP flag booleans, or an empty dict for non-TCP packets."""
        if not pkt.haslayer(TCP):
            return {}
        flags = pkt[TCP].flags
        return {
            "FIN": bool(flags & 0x01),
            "SYN": bool(flags & 0x02),
            "RST": bool(flags & 0x04),
            "PSH": bool(flags & 0x08),
            "ACK": bool(flags & 0x10),
            "URG": bool(flags & 0x20),
        }

    @staticmethod
    def _ip_len(pkt) -> int:
        """Return the packet's IP length field when present."""
        return pkt[IP].len if pkt.haslayer(IP) else 0

    @staticmethod
    def _header_len(pkt) -> int:
        """Approximate IP plus transport header length."""
        if pkt.haslayer(TCP):
            return pkt[TCP].dataofs * 4 + 20
        if pkt.haslayer(UDP):
            return 8 + 20
        return 20

    def _add_packet(self, pkt, ts: float, forward: bool) -> None:
        """Update this flow with one packet in one direction."""
        plen = self._ip_len(pkt)
        hlen = self._header_len(pkt)
        flags = self._tcp_flags(pkt)

        gap = ts - self._last_active
        if gap > self._idle_threshold:
            self.idle_times.append(gap)
            self.active_times.append(self._last_active - self._active_start)
            self._active_start = ts
        self._last_active = ts

        if self._all_ts:
            self.flow_iats.append(ts - self._all_ts[-1])
        self._all_ts.append(ts)

        for name, val in flags.items():
            if val:
                setattr(self, name.lower(), getattr(self, name.lower()) + 1)

        if forward:
            self.fwd_pkts += 1
            self.fwd_bytes.append(plen)
            self.fwd_header_lens.append(hlen)
            if flags.get("PSH"):
                self.fwd_psh += 1
            if flags.get("URG"):
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
            if flags.get("PSH"):
                self.bwd_psh += 1
            if flags.get("URG"):
                self.bwd_urg += 1
            if not self._init_bwd_set and pkt.haslayer(TCP):
                self.init_bwd_win = pkt[TCP].window
                self._init_bwd_set = True
            if self.bwd_last_ts is not None:
                self.bwd_iats.append(ts - self.bwd_last_ts)
            self.bwd_last_ts = ts

        self.last_ts = ts

    def update(self, pkt, ts: float) -> None:
        """Append a packet and infer forward/backward direction from the key."""
        src_ip = pkt[IP].src if pkt.haslayer(IP) else ""
        self._add_packet(pkt, ts, forward=(src_ip == self.key[0]))

    @staticmethod
    def _stats(values: list) -> dict:
        """Return mean/std/max/min for a list, using zeros for empty lists."""
        if not values:
            return {"mean": 0.0, "std": 0.0, "max": 0.0, "min": 0.0}
        arr = np.array(values, dtype=float)
        return {
            "mean": float(arr.mean()),
            "std": float(arr.std()),
            "max": float(arr.max()),
            "min": float(arr.min()),
        }

    def to_feature_vector(self) -> dict:
        """Build the CIC-IDS2017 feature dict expected by the autoencoder."""
        duration_s = max(self.last_ts - self.start_ts, 1e-9)
        duration_us = duration_s * 1e6
        total_pkts = self.fwd_pkts + self.bwd_pkts
        total_bytes = sum(self.fwd_bytes) + sum(self.bwd_bytes)

        fwd_b = self._stats(self.fwd_bytes)
        bwd_b = self._stats(self.bwd_bytes)
        fwd_i = self._stats(self.fwd_iats)
        bwd_i = self._stats(self.bwd_iats)
        flow_i = self._stats(self.flow_iats)
        act = self._stats(self.active_times)
        idle = self._stats(self.idle_times)
        fwd_h = self._stats(self.fwd_header_lens)
        bwd_h = self._stats(self.bwd_header_lens)

        flow_pkts_s = total_pkts / duration_us
        flow_bytes_s = total_bytes / duration_us
        fwd_pkts_s = self.fwd_pkts / duration_us
        bwd_pkts_s = self.bwd_pkts / duration_us

        down_up = (self.bwd_pkts / self.fwd_pkts) if self.fwd_pkts else 0.0
        fwd_seg_avg = fwd_b["mean"] - fwd_h["mean"] if self.fwd_pkts else 0.0
        bwd_seg_avg = bwd_b["mean"] - bwd_h["mean"] if self.bwd_pkts else 0.0
        avg_seg = (total_bytes / total_pkts) if total_pkts else 0.0

        fwd_bulk_bytes = sum(self.fwd_bytes)
        bwd_bulk_bytes = sum(self.bwd_bytes)

        return {
            "Destination Port": self.key[3],
            "Flow Duration": duration_us,
            "Total Fwd Packets": self.fwd_pkts,
            "Total Backward Packets": self.bwd_pkts,
            "Total Length of Fwd Packets": fwd_bulk_bytes,
            "Total Length of Bwd Packets": bwd_bulk_bytes,
            "Fwd Packet Length Max": fwd_b["max"],
            "Fwd Packet Length Min": fwd_b["min"],
            "Fwd Packet Length Mean": fwd_b["mean"],
            "Fwd Packet Length Std": fwd_b["std"],
            "Bwd Packet Length Max": bwd_b["max"],
            "Bwd Packet Length Min": bwd_b["min"],
            "Bwd Packet Length Mean": bwd_b["mean"],
            "Bwd Packet Length Std": bwd_b["std"],
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": flow_i["mean"] * 1e6,
            "Flow IAT Std": flow_i["std"] * 1e6,
            "Flow IAT Max": flow_i["max"] * 1e6,
            "Flow IAT Min": flow_i["min"] * 1e6,
            "Fwd IAT Total": sum(self.fwd_iats) * 1e6,
            "Fwd IAT Mean": fwd_i["mean"] * 1e6,
            "Fwd IAT Std": fwd_i["std"] * 1e6,
            "Fwd IAT Max": fwd_i["max"] * 1e6,
            "Fwd IAT Min": fwd_i["min"] * 1e6,
            "Bwd IAT Total": sum(self.bwd_iats) * 1e6,
            "Bwd IAT Mean": bwd_i["mean"] * 1e6,
            "Bwd IAT Std": bwd_i["std"] * 1e6,
            "Bwd IAT Max": bwd_i["max"] * 1e6,
            "Bwd IAT Min": bwd_i["min"] * 1e6,
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
            "Packet Length Std": np.std(self.fwd_bytes + self.bwd_bytes) if (self.fwd_bytes or self.bwd_bytes) else 0.0,
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
            "Subflow Fwd Packets": self.fwd_pkts,
            "Subflow Fwd Bytes": fwd_bulk_bytes,
            "Subflow Bwd Packets": self.bwd_pkts,
            "Subflow Bwd Bytes": bwd_bulk_bytes,
            "Init_Win_bytes_forward": self.init_fwd_win,
            "Init_Win_bytes_backward": self.init_bwd_win,
            "act_data_pkt_fwd": self.fwd_pkts,
            "min_seg_size_forward": fwd_b["min"],
            "Active Mean": act["mean"] * 1e6,
            "Active Std": act["std"] * 1e6,
            "Active Max": act["max"] * 1e6,
            "Active Min": act["min"] * 1e6,
            "Idle Mean": idle["mean"] * 1e6,
            "Idle Std": idle["std"] * 1e6,
            "Idle Max": idle["max"] * 1e6,
            "Idle Min": idle["min"] * 1e6,
        }


class FlowTable:
    """Thread-safe active-flow table with callback-based flushing."""

    def __init__(
        self,
        flush_cb,
        min_pkts: int = 4,
        flow_timeout: float = FLOW_TIMEOUT,
    ):
        self._flows: dict[tuple, FlowStats] = {}
        self._lock = threading.Lock()
        self._flush_cb = flush_cb
        self._min_pkts = min_pkts
        self._flow_timeout = flow_timeout

    def process(self, pkt) -> None:
        """Add a packet to the correct flow and flush on TCP FIN/RST."""
        if not pkt.haslayer(IP):
            return

        ts = float(pkt.time)
        key = flow_key(pkt)
        if key is None:
            return

        with self._lock:
            flow = self._flows.get(key)
            if flow is not None and ts - flow.last_ts > self._flow_timeout:
                self._maybe_flush(key, flow)
                flow = None

            if flow is None:
                self._flows[key] = FlowStats(key, pkt, ts)
                flow = self._flows[key]
            else:
                flow.update(pkt, ts)

            if pkt.haslayer(TCP):
                flags = pkt[TCP].flags
                if flags & 0x01 or flags & 0x04:
                    self._maybe_flush(key, flow)

    def _maybe_flush(self, key: tuple, flow: FlowStats) -> None:
        """Flush a flow if it has enough packets, then remove it from memory."""
        total = flow.fwd_pkts + flow.bwd_pkts
        if total >= self._min_pkts:
            self._flush_cb(key, flow)
        self._flows.pop(key, None)

    def flush_all(self) -> None:
        """Flush all active flows, usually during shutdown."""
        with self._lock:
            for key, flow in list(self._flows.items()):
                total = flow.fwd_pkts + flow.bwd_pkts
                if total >= self._min_pkts:
                    self._flush_cb(key, flow)
            self._flows.clear()
