"""Unit tests for risk classification plus SQLite read/write behavior."""

import os
import sys
import json
import tempfile
from contextlib import contextmanager

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from db_functions import (
    db_get_low_count,
    db_increment_low_count,
    db_insert_events,
    db_query_history,
    db_read,
    db_read_history,
    db_read_metrics,
    db_read_risk_counts,
    load_threshold,
    save_threshold,
)
from response_engine import SSH_BRUTE_FORCE, SYN_FLOOD, get_recommendation
from risk_classifier import CRITICAL, HIGH, LOW, MEDIUM, classify
from schema import create_db


THRESHOLDS = {"medium": 1.0, "high": 2.5, "critical": 6.0}

SYNTHETIC_ANOMALIES = (
    {
        "ip": "198.51.100.1",
        "anomaly_type": SYN_FLOOD,
        "error": 0.25,
        "expected_risk": LOW,
    },
    {
        "ip": "198.51.100.10",
        "anomaly_type": SYN_FLOOD,
        "error": 1.75,
        "expected_risk": MEDIUM,
    },
    {
        "ip": "203.0.113.20",
        "anomaly_type": SSH_BRUTE_FORCE,
        "error": 3.10,
        "expected_risk": HIGH,
    },
    {
        "ip": "203.0.113.20",
        "anomaly_type": SSH_BRUTE_FORCE,
        "error": 3.95,
        "expected_risk": HIGH,
    },
    {
        "ip": "203.0.113.20",
        "anomaly_type": SSH_BRUTE_FORCE,
        "error": 8.00,
        "expected_risk": CRITICAL,
    },
)


@contextmanager
def isolated_app_cwd():
    original_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        os.chdir(tmpdir)
        try:
            create_db()
            yield tmpdir
        finally:
            os.chdir(original_cwd)


def _insert_non_low_synthetic_events():
    inserted = []

    for anomaly in SYNTHETIC_ANOMALIES:
        risk = classify(anomaly["error"], THRESHOLDS)
        if risk is LOW:
            db_increment_low_count()
            continue

        recommendation = get_recommendation(anomaly["anomaly_type"], risk.name)
        db_insert_events(
            anomaly_type=anomaly["anomaly_type"],
            ip=anomaly["ip"],
            error=anomaly["error"],
            risk=risk,
            recommendation=recommendation,
            feature_deviations=_synthetic_feature_deviations(anomaly["anomaly_type"]),
            deviation_score=2.75,
            explanation_summary="feature deviations support anomaly type",
        )
        inserted.append({**anomaly, "risk": risk, "recommendation": recommendation})

    return inserted


def _synthetic_feature_deviations(anomaly_type):
    feature = "SYN Flag Count" if anomaly_type == SYN_FLOOD else "Flow IAT Std"
    return [{
        "feature": feature,
        "raw_value": 1.0,
        "baseline_mean": 0.0,
        "baseline_std": 0.5,
        "z_score": 2.0,
        "abs_z_score": 2.0,
        "direction": "above_baseline",
    }]


def test_synthetic_anomaly_risk_classification():
    for anomaly in SYNTHETIC_ANOMALIES:
        assert classify(anomaly["error"], THRESHOLDS) is anomaly["expected_risk"]


def test_sqlite_insert_and_history_reads_synthetic_anomalies():
    with isolated_app_cwd():
        inserted = _insert_non_low_synthetic_events()

        history = db_read_history()

        assert len(history) == len(inserted)
        assert list(history["id"]) == [4, 3, 2, 1]
        assert set(history["risk_level"]) == {"Medium", "High", "Critical"}

        by_error = {round(row.recon_error, 2): row for row in history.itertuples()}
        for anomaly in inserted:
            row = by_error[round(anomaly["error"], 2)]
            assert row.IP == anomaly["ip"]
            assert row.anomaly_type == anomaly["anomaly_type"]
            assert row.risk_level == anomaly["risk"].name
            assert row.suggested_response == anomaly["recommendation"].summary
            assert row.deviation_score == 2.75
            assert json.loads(row.feature_deviations)[0]["feature"]
            assert row.explanation_summary == "feature deviations support anomaly type"


def test_sqlite_history_query_filters_synthetic_anomalies():
    with isolated_app_cwd():
        _insert_non_low_synthetic_events()

        high_rows = db_query_history(risk_levels=["High"])
        source_rows = db_query_history(source_ip="203.0.113")
        anomaly_rows = db_query_history(anomaly_type="BRUTE")
        limited_rows = db_query_history(limit=2)

        assert len(high_rows) == 2
        assert set(high_rows["risk_level"]) == {"High"}
        assert len(source_rows) == 3
        assert set(source_rows["IP"]) == {"203.0.113.20"}
        assert len(anomaly_rows) == 3
        assert set(anomaly_rows["anomaly_type"]) == {SSH_BRUTE_FORCE}
        assert list(limited_rows["id"]) == [4, 3]


def test_sqlite_dashboard_count_and_metric_reads():
    with isolated_app_cwd():
        _insert_non_low_synthetic_events()

        risk_counts = db_read_risk_counts()
        metrics = db_read_metrics()

        assert risk_counts == {"Medium": 1, "High": 2, "Critical": 1}
        assert metrics["total_alerts"] == 4
        assert metrics["unique_ips"] == 2
        assert metrics["repeated_ip_count"] == 1
        assert metrics["latest_detection"] != "None"
        assert db_get_low_count() == 1


def test_sqlite_repeated_ip_and_anomaly_reads():
    with isolated_app_cwd():
        _insert_non_low_synthetic_events()

        repeated_ips, repeated_anomalies = db_read()

        assert repeated_ips == [("203.0.113.20", 3)]
        assert repeated_anomalies == [("203.0.113.20", SSH_BRUTE_FORCE, 3)]


def test_sqlite_threshold_write_and_read():
    with isolated_app_cwd():
        assert load_threshold() == 334.522111

        save_threshold(42.75)

        assert load_threshold() == 42.75


def test_high_and_critical_events_write_response_logs():
    with isolated_app_cwd() as tmpdir:
        _insert_non_low_synthetic_events()

        response_log_dir = os.path.join(tmpdir, "logs", "response_logs")
        response_logs = sorted(os.listdir(response_log_dir))

        assert response_logs == ["2.txt", "3.txt", "4.txt"]
        with open(os.path.join(response_log_dir, "4.txt"), "r", encoding="utf-8") as f:
            response_log = f.read()

        assert "203.0.113.20" in response_log
        assert "SSH_BRUTE_FORCE" in response_log


if __name__ == "__main__":
    tests = [v for k, v in list(globals().items()) if k.startswith("test_")]
    passed = failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS  {test.__name__}")
            passed += 1
        except Exception as exc:
            print(f"  FAIL  {test.__name__}: {type(exc).__name__}: {exc}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
    sys.exit(failed)
