"""Centralized filesystem paths for the IDS application.

Every helper returns an absolute Path. Environment variable overrides are kept
for tests and automation, while normal app runs use paths under app/.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
REPO_ROOT = APP_DIR.parent


def _override(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser().resolve() if value else default


def app_dir() -> Path:
    """Return the absolute app/ directory."""
    return APP_DIR


def repo_root() -> Path:
    """Return the absolute repository root directory."""
    return REPO_ROOT


def artifacts_dir() -> Path:
    """Return the artifact directory containing model/scaler/threshold files."""
    return _override("IDS_ARTIFACTS_DIR", APP_DIR / "artifacts")


def data_dir() -> Path:
    """Return the default training-data directory used by autoencoder.py."""
    return _override("IDS_DATA_DIR", APP_DIR / "data")


def diagrams_dir() -> Path:
    """Return the directory where training/evaluation plots are written."""
    return _override("IDS_DIAGRAMS_DIR", APP_DIR / "diagrams")


def db_path() -> Path:
    """Return the SQLite database path."""
    return _override("IDS_DB_PATH", APP_DIR / "threat_memory.db")


def logs_dir() -> Path:
    """Return the directory for generated log files."""
    return _override("IDS_LOGS_DIR", APP_DIR / "logs")


def response_logs_dir() -> Path:
    """Return the High/Critical response-log directory."""
    return logs_dir() / "response_logs"


def live_alerts_path() -> Path:
    """Return the live alert feed file path."""
    return logs_dir() / "live_alerts.txt"


def live_pcap_path() -> Path:
    """Return the default packet-capture output path."""
    return APP_DIR / "live.pcap"


def ensure_runtime_dirs() -> None:
    """Create runtime directories expected by DB and logging helpers."""
    logs_dir().mkdir(parents=True, exist_ok=True)
