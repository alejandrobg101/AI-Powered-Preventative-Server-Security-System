import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix, roc_curve
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns
import time
import numpy as np

TARGET_BENIGN_FPR = 0.10
SEED = 42

np.random.seed(SEED)
torch.manual_seed(SEED)
# ────────────────────────────────────────────
# 1. LOAD DATASET
# ────────────────────────────────────────────
# file_path = "./data/synthetic_security_dataset.csv"
dataset_files = [
    "./data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "./data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    "./data/Tuesday-WorkingHours.pcap_ISCX.csv",       # FTP-Patator, SSH-Patator
    "./data/Wednesday-workingHours.pcap_ISCX.csv",     # DoS Hulk, Slowloris, etc.
    "./data/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "./data/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "./data/Friday-WorkingHours-Morning.pcap_ISCX.csv", # PortScan
    "./data/Monday-WorkingHours.pcap_ISCX.csv",         # Benign only
]
file_path = "./data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

print(f"Full dataset: {len(df):,} rows")
print(f"Class distribution:\n{df['Label'].value_counts()}\n")

# ────────────────────────────────────────────
# 2. SMART SAMPLING — balanced per class
#    Prevents dominant classes from skewing results
#    Keeps runtime manageable on large files
# ────────────────────────────────────────────
# df.columns = df.columns.str.strip()
#
sample_df = df
# print(sample_df.columns)
# print(sample_df.index.names)
# print(f"After balanced sampling: {len(sample_df):,} rows")
# print(f"Sampled class distribution:\n{sample_df['Label'].value_counts()}\n")

# ────────────────────────────────────────────
# 3. SEPARATE FEATURES AND LABELS
# ────────────────────────────────────────────
# X = sample_df.drop("Label", axis=1)
# y = sample_df["Label"]
X = df.drop("Label", axis=1)
y = df["Label"]
# Binary labels: 0 = BENIGN, 1 = ANY attack
y_binary = (y != "BENIGN").astype(int)

print("Binary label distribution:")
print(f"  Benign (0): {(y_binary == 0).sum():,}")
print(f"  Attack (1): {(y_binary == 1).sum():,}")
attack_ratio = y_binary.mean()
print(f"  Attack ratio: {attack_ratio:.2%}\n")

# ────────────────────────────────────────────
# 4. CLEAN INFINITIES AND NaNs
# ────────────────────────────────────────────
X = X.replace([np.inf, -np.inf], np.nan)
nan_counts = X.isnull().sum()
if nan_counts.any():
    print("Columns with NaN/Inf — filling with median:")
    print(nan_counts[nan_counts > 0])
X = X.fillna(X.median(numeric_only=True))
print()

# ────────────────────────────────────────────
# 5. STANDARDIZE FEATURES
# ────────────────────────────────────────────
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ────────────────────────────────────────────
# 6. TRAIN/TEST SPLIT (supervised RF only)
# ────────────────────────────────────────────
X_train_rf, X_test_rf, y_train_rf, y_test_rf = train_test_split(
    X_scaled, y_binary, test_size=0.2, random_state=42
)

# ────────────────────────────────────────────
# 7. AUTOENCODER SETUP
#    Train on BENIGN traffic only
#    Uses validation split + early stopping
#    to prevent overfitting
# ────────────────────────────────────────────
normal_mask = (y_binary == 0).values
X_normal = X_scaled[normal_mask]

# Cap training samples for efficiency
MAX_TRAINING_SAMPLES = 20_000
if X_normal.shape[0] > MAX_TRAINING_SAMPLES:
    idx = np.random.choice(X_normal.shape[0], MAX_TRAINING_SAMPLES, replace=False)
    X_normal_capped = X_normal[idx]
    print(f"  Capped AE training to {MAX_TRAINING_SAMPLES:,} normal samples")
else:
    X_normal_capped = X_normal

# Train/validation split on normal traffic only
X_normal_train, X_normal_val = train_test_split(
    X_normal_capped, test_size=0.15, random_state=42
)

X_tensor_train = torch.tensor(X_normal_train, dtype=torch.float32)
X_tensor_val = torch.tensor(X_normal_val, dtype=torch.float32)

dataset = TensorDataset(X_tensor_train)
dataloader = DataLoader(dataset, batch_size=64, shuffle=True)


class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super(Autoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 16)  # tight bottleneck
        )
        self.decoder = nn.Sequential(
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, input_dim)
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


input_dim = X_scaled.shape[1]
model = Autoencoder(input_dim)
optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
criterion = nn.MSELoss()
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
    optimizer, mode='min', factor=0.5, patience=3
)


def reconstruction_errors(model, features):
    tensor = torch.tensor(features, dtype=torch.float32)
    with torch.no_grad():
        reconstructed = model(tensor)
        return torch.mean((tensor - reconstructed) ** 2, dim=1).cpu().numpy()


def calibrate_threshold_for_max_fpr(benign_errors, max_false_positive_rate):
    if not 0 <= max_false_positive_rate < 1:
        raise ValueError("max_false_positive_rate must be in [0, 1).")

    benign_errors = np.sort(np.asarray(benign_errors, dtype=float))
    if benign_errors.size == 0:
        raise ValueError("Need at least one benign reconstruction error to calibrate.")

    allowed_false_positives = int(np.floor(max_false_positive_rate * benign_errors.size))
    if allowed_false_positives == 0:
        threshold = float(np.nextafter(benign_errors[-1], np.inf))
    else:
        threshold_index = max(0, benign_errors.size - allowed_false_positives - 1)
        threshold = float(benign_errors[threshold_index])

    achieved_fpr = float(np.mean(benign_errors > threshold))
    return threshold, achieved_fpr

num_epochs = 100
best_val_loss = float('inf')
patience = 8
patience_counter = 0
best_model_state = None
train_losses = []
val_losses = []

print("Training Autoencoder...")
start_time = time.time()

for epoch in range(num_epochs):

    # ── Training pass ──
    model.train()
    epoch_loss = 0
    for batch in dataloader:
        inputs = batch[0]
        outputs = model(inputs)
        loss = criterion(outputs, inputs)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        epoch_loss += loss.item()

    avg_train_loss = epoch_loss / len(dataloader)
    train_losses.append(avg_train_loss)

    # ── Validation pass ──
    model.eval()
    with torch.no_grad():
        val_out = model(X_tensor_val)
        val_loss = criterion(val_out, X_tensor_val).item()
    val_losses.append(val_loss)

    # ── LR scheduler step ──
    scheduler.step(val_loss)

    # ── Early stopping check ──
    if val_loss < best_val_loss:
        best_val_loss = val_loss
        best_model_state = {k: v.clone() for k, v in model.state_dict().items()}
        patience_counter = 0
    else:
        patience_counter += 1

    if (epoch + 1) % 10 == 0:
        print(f"  Epoch {epoch + 1:>3}/{num_epochs} | "
              f"Train: {avg_train_loss:.6f} | "
              f"Val: {val_loss:.6f} | "
              f"Best Val: {best_val_loss:.6f} | "
              f"Patience: {patience_counter}/{patience}")

    if patience_counter >= patience:
        print(f"\n  Early stopping triggered at epoch {epoch + 1}")
        break

# Load best weights before inference
model.load_state_dict(best_model_state)
ae_training_time = time.time() - start_time
print(f"Autoencoder training time: {ae_training_time:.2f}s\n")

# ── Reconstruction errors on full dataset ──
model.eval()
val_errors = reconstruction_errors(model, X_normal_val)
ae_threshold, ae_calibration_fpr = calibrate_threshold_for_max_fpr(
    val_errors,
    TARGET_BENIGN_FPR,
)

errors = reconstruction_errors(model, X_scaled)
ae_preds = (errors > ae_threshold).astype(int)
ae_full_benign_fpr = float(np.mean(errors[y_binary == 0] > ae_threshold))

# ────────────────────────────────────────────
# 8. ISOLATION FOREST
#    Train on BENIGN traffic only
# ────────────────────────────────────────────
print("Training Isolation Forest...")
iso = IsolationForest(
    n_estimators=100,
    contamination=min(float(attack_ratio), 0.5),  # sklearn caps at 0.5
    random_state=42,
    n_jobs=-1
)
start_time = time.time()
iso.fit(X_scaled[normal_mask])
print(f"Isolation Forest training time: {time.time() - start_time:.2f}s\n")

iso_raw = iso.predict(X_scaled)
iso_preds = np.where(iso_raw == 1, 0, 1)  # 1=normal→0, -1=anomaly→1
iso_scores = -iso.decision_function(X_scaled)  # higher = more anomalous

# ────────────────────────────────────────────
# 9. RANDOM FOREST — supervised benchmark
# ────────────────────────────────────────────
print("Training Random Forest...")
rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
start_time = time.time()
rf.fit(X_train_rf, y_train_rf)
print(f"Random Forest training time: {time.time() - start_time:.2f}s\n")

rf_preds = rf.predict(X_test_rf)
rf_probs = rf.predict_proba(X_test_rf)[:, 1]

# ────────────────────────────────────────────
# 10. ENSEMBLE — parallel voting
#     Strict: both must agree = fewer false positives
#     Loose:  either flags   = fewer missed attacks
# ────────────────────────────────────────────
iso_threshold = np.percentile(iso_scores, (1 - attack_ratio) * 100)
iso_vote = (iso_scores > iso_threshold).astype(int)
ae_vote = ae_preds

ensemble_strict = ((ae_vote + iso_vote) == 2).astype(int)
ensemble_loose = ((ae_vote + iso_vote) >= 1).astype(int)

# ────────────────────────────────────────────
# 11. EVALUATION
# ────────────────────────────────────────────
TARGET_NAMES = ["Benign", "Attack"]


def print_results(name, y_true, y_pred, y_score):
    print("=" * 52)
    print(f" {name}")
    print("=" * 52)
    print(classification_report(
        y_true, y_pred,
        target_names=TARGET_NAMES,
        zero_division=0
    ))
    try:
        auc = roc_auc_score(y_true, y_score)
        print(f"ROC AUC: {auc:.4f}\n")
        return auc
    except Exception as e:
        print(f"ROC AUC: N/A ({e})\n")
        return None


ae_auc = print_results("AUTOENCODER (Unsupervised)", y_binary, ae_preds, errors)
print(
    f"Autoencoder threshold: {ae_threshold:.6f} "
    f"(target benign FPR <= {TARGET_BENIGN_FPR:.0%}; "
    f"validation FPR={ae_calibration_fpr:.2%}; "
    f"full benign FPR={ae_full_benign_fpr:.2%})\n"
)
iso_auc = print_results("ISOLATION FOREST (Unsupervised)", y_binary, iso_preds, iso_scores)
rf_auc = print_results("RANDOM FOREST (Supervised)", y_test_rf, rf_preds, rf_probs)

print_results("ENSEMBLE STRICT (Both Must Agree)", y_binary, ensemble_strict, (ae_vote + iso_vote).astype(float))
print_results("ENSEMBLE LOOSE  (Either Flags It)", y_binary, ensemble_loose, (ae_vote + iso_vote).astype(float))

# ────────────────────────────────────────────
# 12. PER-ATTACK-TYPE BREAKDOWN
# ────────────────────────────────────────────
print("=" * 64)
print("DETECTION RATE BY ATTACK TYPE")
print("=" * 64)
print(f"{'Attack Type':<20} {'Autoencoder':>12} {'IsoForest':>12} "
      f"{'RandForest':>12} {'Ensemble':>12}")
print("-" * 64)

attack_types = sample_df[sample_df["Label"] != "BENIGN"]["Label"].unique()

for attack in sorted(attack_types):
    mask = (sample_df["Label"].values == attack)
    if mask.sum() == 0:
        continue

    X_attack = X_scaled[mask]

    # Autoencoder detection rate
    attack_tensor = torch.tensor(X_attack, dtype=torch.float32)
    model.eval()
    with torch.no_grad():
        recon = model(attack_tensor)
        attack_errors = torch.mean((attack_tensor - recon) ** 2, dim=1).numpy()
    ae_recall = (attack_errors > ae_threshold).mean()

    # Isolation Forest detection rate
    iso_recall = (iso.predict(X_attack) == -1).mean()

    # Random Forest detection rate
    rf_recall = rf.predict(X_attack).mean()

    # Ensemble strict detection rate
    ae_v = (attack_errors > ae_threshold).astype(int)
    iso_v = (-iso.decision_function(X_attack) > iso_threshold).astype(int)
    ens_recall = ((ae_v + iso_v) == 2).mean()

    print(f"{attack:<20} {ae_recall:>11.1%} {iso_recall:>11.1%} "
          f"{rf_recall:>11.1%} {ens_recall:>11.1%}")

print("-" * 64)

# ────────────────────────────────────────────
# 14. VISUALIZATIONS
# ────────────────────────────────────────────

# ── A. Training Loss Curve ──
plt.figure(figsize=(8, 4))
plt.plot(train_losses, label="Train Loss", color="blue", lw=2)
plt.plot(val_losses, label="Val Loss", color="orange", lw=2)
plt.axvline(len(val_losses) - patience - 1, color="red",
            linestyle="--", label="Early Stop Point")
plt.xlabel("Epoch")
plt.ylabel("MSE Loss")
plt.title("Autoencoder Training vs Validation Loss")
plt.legend()
plt.tight_layout()
plt.savefig("ae_loss_curve.png", dpi=150)
plt.show()
print("Saved: ae_loss_curve.png")


# ── B. Confusion Matrices ──
def plot_confusion(y_true, y_pred, title, filename):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(5, 4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=TARGET_NAMES,
                yticklabels=TARGET_NAMES)
    plt.title(title)
    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig(filename, dpi=150)
    plt.show()
    print(f"Saved: {filename}")


plot_confusion(y_binary, ae_preds, "Autoencoder", "cm_autoencoder.png")
plot_confusion(y_binary, iso_preds, "Isolation Forest", "cm_isolation_forest.png")
plot_confusion(y_test_rf, rf_preds, "Random Forest", "cm_random_forest.png")
plot_confusion(y_binary, ensemble_strict, "Ensemble Strict", "cm_ensemble_strict.png")
plot_confusion(y_binary, ensemble_loose, "Ensemble Loose", "cm_ensemble_loose.png")

# ── C. ROC Curve Comparison ──
plt.figure(figsize=(8, 6))

fpr, tpr, _ = roc_curve(y_binary, errors)
plt.plot(fpr, tpr, label=f"Autoencoder      (AUC={ae_auc:.4f})", color="blue", lw=2)

fpr, tpr, _ = roc_curve(y_binary, iso_scores)
plt.plot(fpr, tpr, label=f"Isolation Forest (AUC={iso_auc:.4f})", color="orange", lw=2)

fpr, tpr, _ = roc_curve(y_test_rf, rf_probs)
plt.plot(fpr, tpr, label=f"Random Forest    (AUC={rf_auc:.4f})", color="green", lw=2)

fpr, tpr, _ = roc_curve(y_binary, (ae_vote + iso_vote).astype(float))
plt.plot(fpr, tpr, label="Ensemble Strict", color="red", lw=2, linestyle="--")

plt.plot([0, 1], [0, 1], 'k--', label="Random Baseline", lw=1)
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate (Recall)")
plt.title("ROC Curve Comparison — All Models")
plt.legend(loc="lower right")
plt.tight_layout()
plt.savefig("roc_comparison.png", dpi=150)
plt.show()
print("Saved: roc_comparison.png")

# ── D. Reconstruction Error Distribution ──
plt.figure(figsize=(8, 4))
plt.hist(errors[y_binary == 0], bins=80, alpha=0.6,
         label="Benign", color="blue", density=True)
plt.hist(errors[y_binary == 1], bins=80, alpha=0.6,
         label="Attack", color="red", density=True)
plt.axvline(ae_threshold, color="black", linestyle="--",
            linewidth=2, label=f"Threshold = {ae_threshold:.4f}")
plt.xlabel("Reconstruction Error")
plt.ylabel("Density")
plt.title("Autoencoder Reconstruction Error Distribution")
plt.legend()
plt.tight_layout()
plt.savefig("ae_error_distribution.png", dpi=150)
plt.show()
print("Saved: ae_error_distribution.png")

print("\nDone.")
