from __future__ import annotations

import json
import os
from collections import deque
from datetime import datetime
from typing import Any


LIVE_ALERTS_FILE = os.path.join("logs", "live_alerts.jsonl")
DEFAULT_LIMIT = 100


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def normalize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Return the stable alert shape shared by live_capture and dashboard."""
    return {
        "timestamp": str(alert.get("timestamp") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "risk": str(alert.get("risk") or "Unknown"),
        "risk_label": str(alert.get("risk_label") or alert.get("risk") or "Unknown"),
        "src_ip": str(alert.get("src_ip") or ""),
        "src_port": _as_int(alert.get("src_port")),
        "dst_ip": str(alert.get("dst_ip") or ""),
        "dst_port": _as_int(alert.get("dst_port")),
        "protocol": str(alert.get("protocol") or "Unknown"),
        "packets": _as_int(alert.get("packets")),
        "bytes": _as_int(alert.get("bytes")),
        "error": _as_float(alert.get("error")),
        "type": str(alert.get("type") or "Unknown"),
        "recommendation": str(alert.get("recommendation") or ""),
        "feature_deviations": alert.get("feature_deviations") or [],
        "deviation_score": _as_float(alert.get("deviation_score")),
        "explanation_summary": str(alert.get("explanation_summary") or ""),
    }


def append_live_alert(alert: dict[str, Any], path: str = LIVE_ALERTS_FILE) -> dict[str, Any]:
    record = normalize_alert(alert)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")
        f.flush()

    return record


def read_live_alerts(limit: int | None = DEFAULT_LIMIT, path: str = LIVE_ALERTS_FILE) -> list[dict[str, Any]]:
    if not os.path.exists(path):
        return []

    maxlen = limit if limit and limit > 0 else None
    records: deque[dict[str, Any]] = deque(maxlen=maxlen)

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue

            if isinstance(parsed, dict):
                records.append(normalize_alert(parsed))

    return list(reversed(records))


def clear_live_alerts(path: str = LIVE_ALERTS_FILE) -> None:
    if os.path.exists(path):
        os.remove(path)
