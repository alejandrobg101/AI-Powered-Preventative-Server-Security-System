"""Print the exact feature order expected by the trained autoencoder.

Run after training or when debugging feature mismatch problems:
    python check_features.py
"""

import joblib

try:
    from .paths import artifacts_dir
except ImportError:
    from paths import artifacts_dir

# feature_columns.pkl is the contract between training, live capture,
# diagnostics, recalibration, and integration tests.
feature_columns = joblib.load(artifacts_dir() / "feature_columns.pkl")

print("Number of features:", len(feature_columns))
print("\nFeature columns:\n")

for col in feature_columns:
    print(col)
