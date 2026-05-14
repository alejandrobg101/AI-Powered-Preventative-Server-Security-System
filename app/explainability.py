from __future__ import annotations

import math
from typing import Any

import numpy as np

from response_engine import (
    DNS_AMPLIFICATION,
    FTP_BRUTE_FORCE,
    GENERIC_ICMP,
    GENERIC_TCP,
    GENERIC_UDP,
    HTTP_SLOWLORIS,
    ICMP_FLOOD,
    PORT_SCAN,
    SSH_BRUTE_FORCE,
    SYN_FLOOD,
    UDP_FLOOD,
    UNKNOWN,
    WEB_ATTACK,
)


DEFAULT_TOP_N = 10
MIN_REVIEW_DEVIATION_SCORE = 0.25

EXPECTED_FEATURES_BY_ANOMALY: dict[str, set[str]] = {
    SYN_FLOOD: {
        "SYN Flag Count",
        "ACK Flag Count",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Packets/s",
        "Fwd Packets/s",
        "Down/Up Ratio",
    },
    UDP_FLOOD: {
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Packets/s",
        "Fwd Packets/s",
        "Flow Bytes/s",
        "Down/Up Ratio",
    },
    ICMP_FLOOD: {
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Packets/s",
        "Fwd Packets/s",
        "Flow Bytes/s",
    },
    PORT_SCAN: {
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "SYN Flag Count",
        "RST Flag Count",
        "Fwd Packet Length Mean",
    },
    SSH_BRUTE_FORCE: {
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Fwd Packet Length Mean",
        "ACK Flag Count",
    },
    FTP_BRUTE_FORCE: {
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow IAT Mean",
        "Flow IAT Std",
        "Fwd Packet Length Mean",
        "ACK Flag Count",
    },
    HTTP_SLOWLORIS: {
        "Destination Port",
        "Flow Duration",
        "Flow Packets/s",
        "Fwd Packets/s",
        "Bwd Packets/s",
        "Total Fwd Packets",
    },
    WEB_ATTACK: {
        "Destination Port",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Packet Length Mean",
    },
    DNS_AMPLIFICATION: {
        "Destination Port",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Bwd Packet Length Mean",
        "Down/Up Ratio",
        "Flow Bytes/s",
    },
    GENERIC_TCP: {
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Packet Length Mean",
    },
    GENERIC_UDP: {
        "Destination Port",
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
    },
    GENERIC_ICMP: {
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Flow Bytes/s",
        "Flow Packets/s",
    },
    UNKNOWN: set(),
}


def _raw_value(row: Any, feature: str) -> float:
    if isinstance(row, dict):
        value = row.get(feature, 0.0)
    else:
        value = row[feature] if feature in row else 0.0

    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def compute_feature_deviations(
    row: Any,
    feature_columns: list[str],
    scaler: Any,
    top_n: int = DEFAULT_TOP_N,
) -> tuple[list[dict[str, float | str]], float]:
    means = np.asarray(scaler.mean_, dtype=float)
    scales = np.asarray(scaler.scale_, dtype=float)
    safe_scales = np.where(scales == 0, 1.0, scales)
    raw_values = np.asarray([_raw_value(row, feature) for feature in feature_columns], dtype=float)
    z_scores = (raw_values - means) / safe_scales
    abs_z_scores = np.abs(z_scores)

    deviations: list[dict[str, float | str]] = []
    for idx, feature in enumerate(feature_columns):
        z_score = float(z_scores[idx])
        direction = "above_baseline" if z_score > 0 else "below_baseline" if z_score < 0 else "at_baseline"
        deviations.append({
            "feature": feature,
            "raw_value": float(raw_values[idx]),
            "baseline_mean": float(means[idx]),
            "baseline_std": float(scales[idx]),
            "z_score": z_score,
            "abs_z_score": float(abs_z_scores[idx]),
            "direction": direction,
        })

    deviations.sort(key=lambda item: item["abs_z_score"], reverse=True)
    deviation_score = float(math.sqrt(float(np.mean(np.square(z_scores))))) if len(z_scores) else 0.0
    return deviations[:top_n], deviation_score


def review_alert_interpretability(
    anomaly_type: str,
    feature_deviations: list[dict[str, Any]],
    deviation_score: float,
) -> dict[str, Any]:
    top_features = [str(item.get("feature", "")) for item in feature_deviations]
    expected_features = EXPECTED_FEATURES_BY_ANOMALY.get(anomaly_type, set())
    matched_features = [feature for feature in top_features if feature in expected_features]

    has_feature_deviation = bool(top_features)
    has_deviation_score = deviation_score >= MIN_REVIEW_DEVIATION_SCORE
    has_type_support = bool(matched_features) if expected_features else has_feature_deviation
    passed = has_feature_deviation and has_deviation_score and has_type_support

    if not has_feature_deviation:
        reason = "missing feature deviation evidence"
    elif not has_deviation_score:
        reason = "deviation score below review threshold"
    elif not has_type_support:
        reason = "top feature deviations do not support anomaly type"
    else:
        reason = "feature deviations support anomaly type"

    return {
        "anomaly_type": anomaly_type,
        "passed": passed,
        "reason": reason,
        "deviation_score": float(deviation_score),
        "top_features": top_features,
        "matched_expected_features": matched_features,
        "expected_features": sorted(expected_features),
    }


def explain_alert(
    row: Any,
    feature_columns: list[str],
    scaler: Any,
    anomaly_type: str,
    top_n: int = DEFAULT_TOP_N,
) -> dict[str, Any]:
    feature_deviations, deviation_score = compute_feature_deviations(
        row=row,
        feature_columns=feature_columns,
        scaler=scaler,
        top_n=top_n,
    )
    review = review_alert_interpretability(
        anomaly_type=anomaly_type,
        feature_deviations=feature_deviations,
        deviation_score=deviation_score,
    )

    return {
        "anomaly_type": anomaly_type,
        "feature_deviations": feature_deviations,
        "deviation_score": deviation_score,
        "interpretability_review": review,
    }


def validate_interpretability(
    alerts: list[dict[str, Any]],
    target_accuracy: float = 0.90,
) -> dict[str, Any]:
    reviews = []

    for alert in alerts:
        anomaly_type = str(alert.get("anomaly_type") or alert.get("type") or UNKNOWN)
        feature_deviations = alert.get("feature_deviations") or []
        deviation_score = float(alert.get("deviation_score") or 0.0)
        alert_id = alert.get("id")
        review = review_alert_interpretability(anomaly_type, feature_deviations, deviation_score)
        review["id"] = alert_id
        reviews.append(review)

    total = len(reviews)
    passed = sum(1 for review in reviews if review["passed"])
    accuracy = passed / total if total else 0.0

    return {
        "total_alerts": total,
        "reviewed_alerts": total,
        "passed_alerts": passed,
        "failed_alerts": total - passed,
        "interpretability_accuracy": accuracy,
        "target_accuracy": target_accuracy,
        "meets_target": accuracy >= target_accuracy if total else False,
        "reviews": reviews,
    }
