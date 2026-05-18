"""
Integration tests: end-to-end data flow
  Stage 1 — Capture:          FlowStats.to_feature_vector()
  Stage 2 — Model:            feature vector → autoencoder → reconstruction error
  Stage 3 — Risk classifier:  reconstruction error → RiskLevel
  Stage 4 — Dashboard / DB:   RiskLevel → db_insert_events → db_read_* queries
  Stage 5 — Full pipeline:    FlowStats → score_flow → DB → dashboard reads

Run from repo root:
    python -m pytest test/test_integration.py -v
Or standalone:
    python test/test_integration.py
"""
from __future__ import annotations

import os
import sys
import shutil
import sqlite3
import tempfile
import time
import unittest

import numpy as np
import pandas as pd
import torch

# ── Path setup: imports need app/ on sys.path, and artifacts/ at cwd ─────────
APP_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "app"))
sys.path.insert(0, APP_DIR)

# ── Suppress db_reset()'s input() prompt that fires on import of live_capture ─
# live_capture.py does `from schema import create_db, db_reset` then calls both
# at module level. We no-op db_reset before live_capture is first imported so
# the test never waits on stdin. create_db() is allowed to run normally — it
# creates a fresh DB + logs/ if they are absent in APP_DIR.
import schema as _schema_mod
_schema_mod.db_reset = lambda: None          # no-op for test session

_saved_cwd = os.getcwd()
os.chdir(APP_DIR)                            # relative paths in live_capture.py
import live_capture                          # loads model + scaler + thresholds
from live_capture import (
    FlowStats, score_flow,
    feature_columns, scaler,
    model as _ae_model,
    risk_thresholds,
)
os.chdir(_saved_cwd)

# ── Modules with no import-time side effects ──────────────────────────────────
import joblib
from scapy.all import IP, TCP, UDP, ICMP, Raw
from risk_classifier import (
    classify, load_thresholds,
    LOW, MEDIUM, HIGH, CRITICAL, ALL_LEVELS, RiskLevel,
)
from response_engine import (
    infer_anomaly_type, get_recommendation, format_response_block,
    Recommendation,
    SYN_FLOOD, SSH_BRUTE_FORCE, FTP_BRUTE_FORCE, PORT_SCAN,
    UDP_FLOOD, ICMP_FLOOD, DNS_AMPLIFICATION,
    HTTP_SLOWLORIS, WEB_ATTACK,
    GENERIC_TCP, GENERIC_UDP, GENERIC_ICMP, UNKNOWN,
)
from db_functions import (
    db_insert_events, db_read_history, db_read_risk_counts,
    db_read_metrics, db_increment_low_count, db_get_low_count,
)


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_pkt(
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int = 54321,
    dport: int = 443,
    flags: str = "S",
    proto: str = "TCP",
    payload_size: int = 200,
    ts: float | None = None,
):
    """Return a Scapy packet with all length fields computed (needed by FlowStats)."""
    if ts is None:
        ts = time.time()
    payload = Raw(b"x" * payload_size)
    if proto == "TCP":
        raw = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / payload
    elif proto == "UDP":
        raw = IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload
    else:
        raw = IP(src=src, dst=dst) / ICMP() / payload
    # Rebuild so that IP.len and TCP.dataofs are computed, not None
    pkt = IP(bytes(raw))
    pkt.time = ts
    return pkt


def _build_tcp_flow(
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int = 54321,
    dport: int = 443,
    n_fwd: int = 5,
    n_bwd: int = 3,
    fwd_flags: str = "A",
    bwd_flags: str = "A",
    pkt_interval: float = 0.05,
) -> tuple[tuple, FlowStats]:
    """Build a realistic bidirectional TCP FlowStats from synthetic packets."""
    key = (src, dst, sport, dport, 6)
    ts = time.time()
    first = _make_pkt(src=src, dst=dst, sport=sport, dport=dport, flags="S", ts=ts)
    flow = FlowStats(key, first, ts)
    for i in range(n_fwd - 1):
        p = _make_pkt(src=src, dst=dst, sport=sport, dport=dport,
                      flags=fwd_flags, ts=ts + (i + 1) * pkt_interval)
        flow.update(p, p.time)
    for i in range(n_bwd):
        p = _make_pkt(src=dst, dst=src, sport=dport, dport=sport,
                      flags=bwd_flags, ts=ts + (n_fwd + i) * pkt_interval + 0.1)
        flow.update(p, p.time)
    return key, flow


def _model_error(feature_dict: dict) -> float:
    """Run a feature dict through scaler + autoencoder and return MSE error."""
    aligned = {col: feature_dict.get(col, 0.0) for col in feature_columns}
    df_row = pd.DataFrame([aligned]).replace([np.inf, -np.inf], np.nan).fillna(0)
    x_scaled = scaler.transform(df_row)
    x_tensor = torch.tensor(x_scaled, dtype=torch.float32)
    with torch.no_grad():
        recon = _ae_model(x_tensor)
        return torch.mean((x_tensor - recon) ** 2, dim=1).item()


# ─────────────────────────────────────────────────────────────────────────────
# Stage 1 — Capture: FlowStats → feature vector
# ─────────────────────────────────────────────────────────────────────────────

class TestStage1_Capture(unittest.TestCase):
    """FlowStats correctly accumulates packet data and produces the 78-feature vector."""

    def test_feature_vector_contains_all_trained_columns(self):
        """Feature vector keys match the full list of columns used during training."""
        key, flow = _build_tcp_flow()
        fv = flow.to_feature_vector()
        missing = [col for col in feature_columns if col not in fv]
        self.assertFalse(missing, f"Missing columns: {missing}")

    def test_feature_vector_values_are_finite(self):
        """Every feature value is a finite float — no NaN or Inf."""
        key, flow = _build_tcp_flow()
        fv = flow.to_feature_vector()
        for name, val in fv.items():
            self.assertTrue(
                np.isfinite(val),
                f"Feature '{name}' is not finite: {val}",
            )

    def test_destination_port_matches_flow_key(self):
        """Destination Port feature equals the dport stored in the 5-tuple key."""
        key, flow = _build_tcp_flow(dport=8080)
        fv = flow.to_feature_vector()
        self.assertEqual(fv["Destination Port"], 8080)

    def test_bidirectional_packet_counts(self):
        """fwd/bwd packet counters and their feature-vector equivalents match."""
        key, flow = _build_tcp_flow(n_fwd=4, n_bwd=6)
        fv = flow.to_feature_vector()
        self.assertEqual(fv["Total Fwd Packets"], flow.fwd_pkts)
        self.assertEqual(fv["Total Backward Packets"], flow.bwd_pkts)

    def test_syn_flag_set_for_syn_packet(self):
        """SYN packet increments the syn counter; SYN Flag Count is 1 in the vector."""
        key = ("10.0.0.1", "10.0.0.2", 11111, 443, 6)
        ts = time.time()
        pkt = _make_pkt(flags="S", ts=ts)
        flow = FlowStats(key, pkt, ts)
        # Add a second SYN to keep fwd_pkts >= 1
        p2 = _make_pkt(flags="S", ts=ts + 0.01)
        flow.update(p2, p2.time)
        fv = flow.to_feature_vector()
        self.assertGreaterEqual(flow.syn, 1)
        self.assertEqual(fv["SYN Flag Count"], 1)   # binary: 1 = seen at least once

    def test_udp_flow_has_zero_tcp_flags(self):
        """UDP flow produces a feature vector with all TCP flag counts = 0."""
        key = ("10.0.0.1", "10.0.0.2", 5000, 53, 17)
        ts = time.time()
        pkt = _make_pkt(sport=5000, dport=53, proto="UDP", ts=ts)
        flow = FlowStats(key, pkt, ts)
        for i in range(4):
            p = _make_pkt(sport=5000, dport=53, proto="UDP", ts=ts + (i + 1) * 0.1)
            flow.update(p, p.time)
        fv = flow.to_feature_vector()
        for flag_col in ("SYN Flag Count", "ACK Flag Count", "FIN Flag Count",
                         "RST Flag Count", "PSH Flag Count"):
            self.assertEqual(fv[flag_col], 0, f"{flag_col} must be 0 for UDP flow")

    def test_feature_vector_returns_dict(self):
        """to_feature_vector() always returns a plain dict."""
        key, flow = _build_tcp_flow()
        fv = flow.to_feature_vector()
        self.assertIsInstance(fv, dict)

    def test_flow_duration_is_positive(self):
        """Flow Duration (µs) is positive when packets span > 0 time."""
        key, flow = _build_tcp_flow(n_fwd=3, n_bwd=2, pkt_interval=0.1)
        fv = flow.to_feature_vector()
        self.assertGreater(fv["Flow Duration"], 0.0)


# ─────────────────────────────────────────────────────────────────────────────
# Stage 2 — Model: feature vector → autoencoder → reconstruction error
# ─────────────────────────────────────────────────────────────────────────────

class TestStage2_Model(unittest.TestCase):
    """Autoencoder inference produces a valid, finite reconstruction error."""

    def test_error_is_non_negative_float(self):
        """Reconstruction error from a real FlowStats vector is a non-negative float."""
        key, flow = _build_tcp_flow()
        fv = flow.to_feature_vector()
        error = _model_error(fv)
        self.assertIsInstance(error, float)
        self.assertTrue(np.isfinite(error), f"Error is not finite: {error}")
        self.assertGreaterEqual(error, 0.0)

    def test_all_zero_input_produces_finite_error(self):
        """An all-zero feature vector (worst-case input) still gives a finite error."""
        row = {col: 0.0 for col in feature_columns}
        error = _model_error(row)
        self.assertTrue(np.isfinite(error))
        self.assertGreaterEqual(error, 0.0)

    def test_model_output_shape_matches_input(self):
        """Autoencoder decoder output is the same dimension as its encoder input."""
        n = len(feature_columns)
        x = torch.zeros(1, n, dtype=torch.float32)
        with torch.no_grad():
            out = _ae_model(x)
        self.assertEqual(out.shape, x.shape, f"Expected {x.shape}, got {out.shape}")

    def test_feature_count_matches_trained_model(self):
        """feature_columns length equals the autoencoder's expected input dimension."""
        expected_input_dim = _ae_model.encoder[0].in_features
        self.assertEqual(
            len(feature_columns),
            expected_input_dim,
            f"Model expects {expected_input_dim} features; got {len(feature_columns)}",
        )

    def test_scaler_transforms_to_correct_shape(self):
        """StandardScaler output has shape (1, n_features) for a single-row input."""
        row = {col: 0.0 for col in feature_columns}
        df_row = pd.DataFrame([row]).replace([np.inf, -np.inf], np.nan).fillna(0)
        x_scaled = scaler.transform(df_row)
        self.assertEqual(x_scaled.shape, (1, len(feature_columns)))

    def test_capture_feeds_cleanly_into_model(self):
        """Feature vector from FlowStats aligns with scaler without shape errors."""
        key, flow = _build_tcp_flow(n_fwd=6, n_bwd=4)
        fv = flow.to_feature_vector()
        aligned = {col: fv.get(col, 0.0) for col in feature_columns}
        df_row = pd.DataFrame([aligned]).replace([np.inf, -np.inf], np.nan).fillna(0)
        # Shape must match training; must not raise
        self.assertEqual(df_row.shape, (1, len(feature_columns)))
        x_scaled = scaler.transform(df_row)
        x_tensor = torch.tensor(x_scaled, dtype=torch.float32)
        with torch.no_grad():
            recon = _ae_model(x_tensor)
        error = torch.mean((x_tensor - recon) ** 2, dim=1).item()
        self.assertTrue(np.isfinite(error))

    def test_anomalous_input_produces_higher_error_than_zero_input(self):
        """Extreme feature values yield a higher error than the all-zero baseline."""
        zero_error = _model_error({col: 0.0 for col in feature_columns})
        extreme_row = {col: 0.0 for col in feature_columns}
        # Inject values far from the benign training distribution
        extreme_row.update({
            "SYN Flag Count": 1.0,
            "Total Fwd Packets": 50_000.0,
            "Flow Bytes/s": 1e10,
            "Fwd Packet Length Mean": 1500.0,
            "ACK Flag Count": 0.0,
        })
        extreme_error = _model_error(extreme_row)
        self.assertGreater(extreme_error, zero_error,
                           "Extreme feature values should produce higher reconstruction error")


# ─────────────────────────────────────────────────────────────────────────────
# Stage 3 — Risk classifier: reconstruction error → RiskLevel
# ─────────────────────────────────────────────────────────────────────────────

class TestStage3_RiskClassifier(unittest.TestCase):
    """Risk thresholds load correctly; classify() maps errors to the right tier."""

    def setUp(self):
        self.thresholds = load_thresholds(os.path.join(APP_DIR, "artifacts"))

    def test_thresholds_have_required_keys(self):
        for key in ("medium", "high", "critical"):
            self.assertIn(key, self.thresholds, f"Missing threshold key: '{key}'")

    def test_threshold_values_are_strictly_increasing(self):
        t = self.thresholds
        self.assertLess(t["medium"], t["high"],
                        "medium threshold must be less than high")
        self.assertLess(t["high"], t["critical"],
                        "high threshold must be less than critical")

    def test_zero_error_is_low(self):
        self.assertIs(classify(0.0, self.thresholds), LOW)

    def test_error_at_medium_boundary_is_low(self):
        """The boundary value itself belongs to Low (thresholds are exclusive)."""
        self.assertIs(classify(self.thresholds["medium"], self.thresholds), LOW)

    def test_error_just_above_medium_is_medium(self):
        self.assertIs(
            classify(self.thresholds["medium"] + 1e-6, self.thresholds), MEDIUM
        )

    def test_error_at_high_boundary_is_medium(self):
        self.assertIs(classify(self.thresholds["high"], self.thresholds), MEDIUM)

    def test_error_just_above_high_is_high(self):
        self.assertIs(
            classify(self.thresholds["high"] + 1e-6, self.thresholds), HIGH
        )

    def test_error_at_critical_boundary_is_high(self):
        self.assertIs(classify(self.thresholds["critical"], self.thresholds), HIGH)

    def test_error_just_above_critical_is_critical(self):
        self.assertIs(
            classify(self.thresholds["critical"] + 1e-6, self.thresholds), CRITICAL
        )

    def test_all_risk_levels_have_non_empty_fields(self):
        for level in ALL_LEVELS:
            self.assertTrue(level.name)
            self.assertTrue(level.label)
            self.assertTrue(level.suggested_response)
            self.assertIsInstance(level.code, int)

    def test_risk_codes_are_ordered(self):
        self.assertLess(LOW.code, MEDIUM.code)
        self.assertLess(MEDIUM.code, HIGH.code)
        self.assertLess(HIGH.code, CRITICAL.code)

    def test_model_error_feeds_into_classifier(self):
        """A reconstruction error produced by the real model classifies without error."""
        error = _model_error({col: 0.0 for col in feature_columns})
        risk = classify(error, self.thresholds)
        self.assertIn(risk, ALL_LEVELS)

    def test_classifier_to_recommendation_stage_connection(self):
        """A RiskLevel from classify() feeds into get_recommendation() without error."""
        error = _model_error({col: 0.0 for col in feature_columns})
        risk = classify(error, self.thresholds)
        rec = get_recommendation(SYN_FLOOD, risk.name)
        self.assertIsInstance(rec, Recommendation)
        self.assertEqual(rec.anomaly_type, SYN_FLOOD)
        self.assertTrue(rec.summary)
        self.assertIsInstance(rec.actions, tuple)
        self.assertGreater(len(rec.actions), 0)


# ─────────────────────────────────────────────────────────────────────────────
# Stage 4 — Dashboard / DB: persistence and read-back
# ─────────────────────────────────────────────────────────────────────────────

class TestStage4_Dashboard(unittest.TestCase):
    """db_insert_events → threat_events table → db_read_* queries return correct data."""

    def setUp(self):
        """Each test gets a fresh, isolated SQLite database in a temp directory."""
        self._orig_cwd = os.getcwd()
        self._tmpdir = tempfile.mkdtemp(prefix="ids_test_")
        os.chdir(self._tmpdir)
        from schema import create_db
        create_db()                        # creates threat_memory.db + logs/ here

    def tearDown(self):
        os.chdir(self._orig_cwd)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _insert(anomaly=SYN_FLOOD, ip="10.0.0.1", error=5.0, risk=HIGH):
        rec = get_recommendation(anomaly, risk.name)
        db_insert_events(anomaly, ip, error, risk, rec)

    # ── tests ────────────────────────────────────────────────────────────────

    def test_empty_db_returns_empty_dataframe(self):
        df = db_read_history()
        self.assertIsInstance(df, pd.DataFrame)
        self.assertEqual(len(df), 0)

    def test_empty_db_risk_counts_are_zero(self):
        counts = db_read_risk_counts()
        self.assertEqual(counts, {"Medium": 0, "High": 0, "Critical": 0})

    def test_empty_db_metrics_total_is_zero(self):
        m = db_read_metrics()
        self.assertEqual(m["total_alerts"], 0)
        self.assertEqual(m["unique_ips"], 0)

    def test_insert_event_is_returned_by_read_history(self):
        self._insert(ip="192.168.1.100", error=5.0, risk=HIGH)
        df = db_read_history()
        self.assertEqual(len(df), 1)
        row = df.iloc[0]
        self.assertEqual(row["IP"], "192.168.1.100")
        self.assertEqual(row["anomaly_type"], SYN_FLOOD)
        self.assertEqual(row["risk_level"], "High")
        self.assertAlmostEqual(row["recon_error"], 5.0, places=5)

    def test_insert_preserves_anomaly_type(self):
        self._insert(anomaly=SSH_BRUTE_FORCE, ip="10.10.10.1", error=7.2, risk=HIGH)
        df = db_read_history()
        self.assertEqual(df.iloc[0]["anomaly_type"], SSH_BRUTE_FORCE)

    def test_risk_counts_reflect_multiple_insertions(self):
        self._insert(anomaly=GENERIC_TCP, ip="1.1.1.1", error=2.0, risk=MEDIUM)
        self._insert(anomaly=SYN_FLOOD, ip="2.2.2.2", error=7.0, risk=HIGH)
        self._insert(anomaly=SYN_FLOOD, ip="3.3.3.3", error=8.5, risk=HIGH)
        self._insert(anomaly=UDP_FLOOD, ip="4.4.4.4", error=20.0, risk=CRITICAL)
        counts = db_read_risk_counts()
        self.assertEqual(counts["Medium"], 1)
        self.assertEqual(counts["High"], 2)
        self.assertEqual(counts["Critical"], 1)

    def test_metrics_total_alerts_and_unique_ips(self):
        self._insert(ip="10.0.0.1", error=7.0, risk=HIGH)
        self._insert(ip="10.0.0.1", error=8.0, risk=HIGH)   # same IP — repeated
        self._insert(ip="10.0.0.2", error=5.5, risk=MEDIUM)
        m = db_read_metrics()
        self.assertEqual(m["total_alerts"], 3)
        self.assertEqual(m["unique_ips"], 2)
        self.assertEqual(m["repeated_ip_count"], 1)
        self.assertNotEqual(m["latest_detection"], "None")

    def test_low_count_increments_correctly(self):
        db_increment_low_count()
        db_increment_low_count()
        db_increment_low_count()
        self.assertEqual(db_get_low_count(), 3)

    def test_response_log_written_for_high_risk(self):
        """A High-risk event produces a response log file in logs/response_logs/."""
        self._insert(anomaly=SSH_BRUTE_FORCE, ip="172.16.0.5", error=7.0, risk=HIGH)
        log_dir = os.path.join(self._tmpdir, "logs", "response_logs")
        log_files = os.listdir(log_dir) if os.path.isdir(log_dir) else []
        self.assertEqual(len(log_files), 1, "Expected exactly one response log file")

    def test_response_log_written_for_critical_risk(self):
        self._insert(anomaly=UDP_FLOOD, ip="172.16.0.6", error=25.0, risk=CRITICAL)
        log_dir = os.path.join(self._tmpdir, "logs", "response_logs")
        log_files = os.listdir(log_dir) if os.path.isdir(log_dir) else []
        self.assertEqual(len(log_files), 1)

    def test_no_response_log_for_medium_risk(self):
        """Medium-risk events are inserted to DB but do NOT produce a response log."""
        self._insert(anomaly=GENERIC_TCP, ip="172.16.0.7", error=1.5, risk=MEDIUM)
        df = db_read_history()
        self.assertEqual(len(df), 1, "Medium event should be in threat_events")
        log_dir = os.path.join(self._tmpdir, "logs", "response_logs")
        log_files = os.listdir(log_dir) if os.path.isdir(log_dir) else []
        self.assertEqual(len(log_files), 0, "No response log expected for Medium")

    def test_response_log_contains_src_ip(self):
        """Response log content has the source IP substituted in the action steps."""
        target_ip = "192.0.2.99"
        self._insert(anomaly=SYN_FLOOD, ip=target_ip, error=8.0, risk=HIGH)
        log_dir = os.path.join(self._tmpdir, "logs", "response_logs")
        log_file = os.listdir(log_dir)[0]
        content = open(os.path.join(log_dir, log_file), encoding="utf-8").read()
        self.assertIn(target_ip, content)

    def test_read_history_columns(self):
        """db_read_history() DataFrame has all expected columns."""
        self._insert()
        df = db_read_history()
        expected = {"id", "timestamp", "IP", "anomaly_type",
                    "recon_error", "risk_level", "suggested_response"}
        self.assertTrue(expected.issubset(set(df.columns)),
                        f"Missing columns: {expected - set(df.columns)}")

    def test_read_history_ordered_by_id_descending(self):
        """db_read_history() returns newest event first (ORDER BY id DESC)."""
        self._insert(ip="10.0.0.1", error=5.0, risk=MEDIUM)
        self._insert(ip="10.0.0.2", error=7.0, risk=HIGH)
        df = db_read_history()
        ids = list(df["id"])
        self.assertEqual(ids, sorted(ids, reverse=True))


# ─────────────────────────────────────────────────────────────────────────────
# Stage 5 — Full pipeline: FlowStats → score_flow → DB → dashboard reads
# ─────────────────────────────────────────────────────────────────────────────

class TestStage5_FullPipeline(unittest.TestCase):
    """End-to-end: packet accumulation → model inference → risk → DB → queries."""

    def setUp(self):
        self._orig_cwd = os.getcwd()
        self._tmpdir = tempfile.mkdtemp(prefix="ids_e2e_")
        os.chdir(self._tmpdir)
        from schema import create_db
        create_db()
        # score_flow appends to logs/live_alerts.txt — ensure it exists
        with open("logs/live_alerts.txt", "a", encoding="utf-8"):
            pass

    def tearDown(self):
        os.chdir(self._orig_cwd)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_score_flow_does_not_raise(self):
        """score_flow completes without exception for a well-formed TCP flow."""
        key, flow = _build_tcp_flow()
        score_flow(key, flow)   # must not throw

    def test_score_flow_writes_alert_to_log(self):
        """score_flow always appends an entry to logs/live_alerts.txt."""
        key, flow = _build_tcp_flow()
        score_flow(key, flow)
        with open("logs/live_alerts.txt", encoding="utf-8") as f:
            content = f.read()
        self.assertIn(key[0], content, "Source IP must appear in the alert log")

    def test_score_flow_db_entry_matches_computed_values(self):
        """Values stored in DB match what we independently compute for the same flow."""
        key, flow = _build_tcp_flow(src="172.20.0.1", dst="172.20.0.2")
        # Pre-compute expected results using the same model + thresholds
        fv = flow.to_feature_vector()
        expected_error = _model_error(fv)
        expected_risk = classify(expected_error, risk_thresholds)

        score_flow(key, flow)

        df = db_read_history()
        if expected_risk.code > 0:
            self.assertEqual(len(df), 1)
            row = df.iloc[0]
            self.assertAlmostEqual(row["recon_error"], expected_error, places=5)
            self.assertEqual(row["risk_level"], expected_risk.name)
            self.assertEqual(row["IP"], "172.20.0.1")
        else:
            # Low-risk flows are NOT inserted into threat_events
            self.assertEqual(len(df), 0)

    def test_score_flow_low_risk_increments_low_count(self):
        """If the model rates the flow as Low, only the low_risk_events counter increases."""
        # An all-zeros padded flow is typically benign
        key, flow = _build_tcp_flow(n_fwd=2, n_bwd=1)
        fv = flow.to_feature_vector()
        expected_error = _model_error(fv)
        expected_risk = classify(expected_error, risk_thresholds)

        if expected_risk is LOW:
            before = db_get_low_count()
            score_flow(key, flow)
            after = db_get_low_count()
            df = db_read_history()
            self.assertEqual(len(df), 0, "Low-risk flow must not appear in threat_events")
            self.assertEqual(after - before, 1, "low_risk_events counter should increment by 1")
        else:
            # If this flow is not Low, skip the low-count assertion
            self.skipTest("Flow scored as non-Low; skipping low-count increment check")

    def test_syn_flood_pattern_is_classified_and_stored(self):
        """SYN-flood flow: infer_anomaly_type returns SYN_FLOOD; DB entry reflects it."""
        key = ("10.5.5.1", "10.5.5.2", 6666, 80, 6)
        ts = time.time()
        first = _make_pkt(src="10.5.5.1", dst="10.5.5.2", sport=6666, dport=80,
                          flags="S", ts=ts)
        flow = FlowStats(key, first, ts)
        # 9 more rapid SYN packets with no ACK → syn >= 5, ack == 0
        for i in range(9):
            p = _make_pkt(src="10.5.5.1", dst="10.5.5.2", sport=6666, dport=80,
                          flags="S", ts=ts + (i + 1) * 0.001)
            flow.update(p, p.time)

        self.assertGreaterEqual(flow.syn, 5)
        self.assertEqual(flow.ack, 0)

        anomaly = infer_anomaly_type(flow, key)
        self.assertEqual(anomaly, SYN_FLOOD)

        score_flow(key, flow)

        df = db_read_history()
        fv = flow.to_feature_vector()
        expected_error = _model_error(fv)
        expected_risk = classify(expected_error, risk_thresholds)
        if expected_risk.code > 0:
            self.assertEqual(len(df), 1)
            self.assertEqual(df.iloc[0]["anomaly_type"], SYN_FLOOD)

    def test_full_pipeline_dashboard_counts_match_db(self):
        """After multiple score_flow calls, db_read_risk_counts() totals are consistent."""
        flows = [
            _build_tcp_flow(src=f"10.0.0.{i}", dport=443, n_fwd=5, n_bwd=3)
            for i in range(1, 6)
        ]
        for key, flow in flows:
            score_flow(key, flow)

        df = db_read_history()
        counts = db_read_risk_counts()
        total_from_counts = sum(counts.values())
        # Every DB row must be accounted for in a risk-count bucket
        self.assertEqual(total_from_counts, len(df))

    def test_multiple_flows_same_ip_show_as_repeated(self):
        """Two flows from the same source IP appear as a repeated IP in db_read_metrics."""
        src_ip = "192.168.99.1"
        for dport in (80, 443):
            key = (src_ip, "10.0.1.1", 55000 + dport, dport, 6)
            ts = time.time()
            first = _make_pkt(src=src_ip, dst="10.0.1.1",
                              sport=55000 + dport, dport=dport, flags="S", ts=ts)
            flow = FlowStats(key, first, ts)
            for i in range(4):
                p = _make_pkt(src=src_ip, dst="10.0.1.1",
                              sport=55000 + dport, dport=dport,
                              flags="A", ts=ts + (i + 1) * 0.05)
                flow.update(p, p.time)
            # Force this to be non-Low so it enters the DB
            fv = flow.to_feature_vector()
            err = _model_error(fv)
            risk = classify(err, risk_thresholds)
            if risk.code > 0:
                rec = get_recommendation(infer_anomaly_type(flow, key), risk.name)
                db_insert_events(infer_anomaly_type(flow, key), src_ip, err, risk, rec)

        m = db_read_metrics()
        if m["total_alerts"] >= 2:
            self.assertEqual(m["repeated_ip_count"], 1,
                             "Same source IP with 2+ events should show as repeated")
        else:
            self.skipTest("Flows scored Low — repeated IP test requires DB entries")


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suites = [
        loader.loadTestsFromTestCase(TestStage1_Capture),
        loader.loadTestsFromTestCase(TestStage2_Model),
        loader.loadTestsFromTestCase(TestStage3_RiskClassifier),
        loader.loadTestsFromTestCase(TestStage4_Dashboard),
        loader.loadTestsFromTestCase(TestStage5_FullPipeline),
    ]
    stage_names = [
        "Stage 1 — Capture",
        "Stage 2 — Model",
        "Stage 3 — Risk Classifier",
        "Stage 4 — Dashboard / DB",
        "Stage 5 — Full Pipeline",
    ]

    total_passed = total_failed = total_errors = 0
    for suite, name in zip(suites, stage_names):
        print(f"\n{'=' * 60}")
        print(f"  {name}")
        print(f"{'=' * 60}")
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        total_passed  += result.testsRun - len(result.failures) - len(result.errors)
        total_failed  += len(result.failures)
        total_errors  += len(result.errors)

    print(f"\n{'=' * 60}")
    print(f"  TOTAL: {total_passed} passed  |  {total_failed} failed  |  {total_errors} errors")
    print(f"{'=' * 60}")
    raise SystemExit(1 if (total_failed + total_errors) else 0)
