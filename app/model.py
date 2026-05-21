"""Shared autoencoder model loading and scoring utilities."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import torch
import torch.nn as nn

try:
    from .paths import artifacts_dir
    from .risk_classifier import load_thresholds
except ImportError:  # Supports running scripts directly from app/.
    from paths import artifacts_dir
    from risk_classifier import load_thresholds

DEFAULT_THRESHOLD = 334.522111


class Autoencoder(nn.Module):
    """Autoencoder architecture used by all training and inference paths."""

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


@dataclass
class DetectorRuntime:
    """Loaded model artifacts needed to score live or stored feature rows."""

    feature_columns: list[str]
    scaler: object
    threshold: float
    risk_thresholds: dict
    model: Autoencoder


def _thresholds_for_base(threshold: float, risk_thresholds: dict) -> dict:
    """Apply calibrated-threshold multipliers when the base threshold changed."""
    if abs(float(threshold) - DEFAULT_THRESHOLD) <= 1e-6:
        return risk_thresholds
    return {
        "medium": float(threshold),
        "high": float(threshold) * 6.0,
        "critical": float(threshold) * 36.7,
    }


def load_detector_runtime(
    artifact_dir: str | Path | None = None,
    threshold: float | None = None,
) -> DetectorRuntime:
    """Load feature columns, scaler, threshold, risk tiers, and model weights."""
    artifact_dir = Path(artifact_dir) if artifact_dir is not None else artifacts_dir()

    feature_columns = joblib.load(artifact_dir / "feature_columns.pkl")
    scaler = joblib.load(artifact_dir / "scaler.pkl")
    base_threshold = (
        float(threshold)
        if threshold is not None
        else float(joblib.load(artifact_dir / "threshold.pkl"))
    )
    risk_thresholds = _thresholds_for_base(
        base_threshold,
        load_thresholds(str(artifact_dir)),
    )

    model = Autoencoder(len(feature_columns))
    model.load_state_dict(torch.load(
        artifact_dir / "autoencoder_model.pth",
        map_location="cpu",
    ))
    model.eval()

    return DetectorRuntime(
        feature_columns=list(feature_columns),
        scaler=scaler,
        threshold=base_threshold,
        risk_thresholds=risk_thresholds,
        model=model,
    )


def align_feature_row(feature_vector: dict, feature_columns: list[str]) -> pd.DataFrame:
    """Return a one-row DataFrame aligned to the trained feature order."""
    row = {col: feature_vector.get(col, 0.0) for col in feature_columns}
    return pd.DataFrame([row]).replace([np.inf, -np.inf], np.nan).fillna(0)


def reconstruction_error(feature_vector: dict, runtime: DetectorRuntime) -> tuple[float, pd.DataFrame, np.ndarray]:
    """Score one feature dict and return error, aligned raw row, and scaled row."""
    df_row = align_feature_row(feature_vector, runtime.feature_columns)
    x_scaled = runtime.scaler.transform(df_row)
    x_tensor = torch.tensor(x_scaled, dtype=torch.float32)

    with torch.no_grad():
        recon = runtime.model(x_tensor)
        error = torch.mean((x_tensor - recon) ** 2, dim=1).item()

    return float(error), df_row, x_scaled
