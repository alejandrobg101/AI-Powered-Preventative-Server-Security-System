"""Unit tests for feature-deviation explainability and validation."""

import os
import sys

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from explainability import (
    compute_feature_deviations,
    explain_alert,
    validate_interpretability,
)
from response_engine import PORT_SCAN, SSH_BRUTE_FORCE, SYN_FLOOD, UDP_FLOOD


class _Scaler:
    def __init__(self, mean, scale):
        self.mean_ = np.array(mean, dtype=float)
        self.scale_ = np.array(scale, dtype=float)


FEATURE_COLUMNS = [
    "SYN Flag Count",
    "ACK Flag Count",
    "Flow Packets/s",
    "Total Fwd Packets",
    "Destination Port",
    "Flow Duration",
    "Flow IAT Std",
]
SCALER = _Scaler(
    mean=[0.2, 0.8, 25.0, 8.0, 443.0, 1_000_000.0, 50_000.0],
    scale=[0.1, 0.1, 10.0, 2.0, 50.0, 250_000.0, 10_000.0],
)


def test_compute_feature_deviations_returns_sorted_z_scores_and_score():
    row = {
        "SYN Flag Count": 1.0,
        "ACK Flag Count": 0.0,
        "Flow Packets/s": 225.0,
        "Total Fwd Packets": 28.0,
        "Destination Port": 443.0,
        "Flow Duration": 1_000_000.0,
        "Flow IAT Std": 50_000.0,
    }

    deviations, score = compute_feature_deviations(row, FEATURE_COLUMNS, SCALER, top_n=3)

    assert [item["feature"] for item in deviations] == [
        "Flow Packets/s",
        "Total Fwd Packets",
        "SYN Flag Count",
    ]
    assert deviations[0]["z_score"] == 20.0
    assert score > 8.0


def test_explain_alert_links_expected_feature_deviation_to_anomaly_type():
    row = {
        "SYN Flag Count": 1.0,
        "ACK Flag Count": 0.0,
        "Flow Packets/s": 225.0,
        "Total Fwd Packets": 28.0,
        "Destination Port": 443.0,
        "Flow Duration": 1_000_000.0,
        "Flow IAT Std": 50_000.0,
    }

    explanation = explain_alert(row, FEATURE_COLUMNS, SCALER, SYN_FLOOD, top_n=5)
    review = explanation["interpretability_review"]

    assert explanation["deviation_score"] > 0
    assert review["passed"] is True
    assert "SYN Flag Count" in review["matched_expected_features"]


def test_validate_interpretability_reviews_all_alerts_and_meets_target():
    alerts = [
        {
            "id": 1,
            "type": SYN_FLOOD,
            "deviation_score": 3.0,
            "feature_deviations": [{"feature": "SYN Flag Count"}],
        },
        {
            "id": 2,
            "type": UDP_FLOOD,
            "deviation_score": 2.5,
            "feature_deviations": [{"feature": "Flow Packets/s"}],
        },
        {
            "id": 3,
            "type": PORT_SCAN,
            "deviation_score": 2.0,
            "feature_deviations": [{"feature": "Destination Port"}],
        },
        {
            "id": 4,
            "type": SSH_BRUTE_FORCE,
            "deviation_score": 1.8,
            "feature_deviations": [{"feature": "Flow IAT Std"}],
        },
    ]

    result = validate_interpretability(alerts, target_accuracy=0.90)

    assert result["reviewed_alerts"] == len(alerts)
    assert result["interpretability_accuracy"] == 1.0
    assert result["meets_target"] is True


def test_validate_interpretability_flags_unsupported_anomaly_type_evidence():
    alerts = [
        {
            "id": 1,
            "type": SYN_FLOOD,
            "deviation_score": 3.0,
            "feature_deviations": [{"feature": "Destination Port"}],
        },
    ]

    result = validate_interpretability(alerts, target_accuracy=0.90)

    assert result["reviewed_alerts"] == 1
    assert result["failed_alerts"] == 1
    assert result["meets_target"] is False


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
