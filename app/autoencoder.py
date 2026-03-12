import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import TensorDataset, DataLoader
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix, roc_curve
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import time
import os
import joblib
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# ────────────────────────────────────────────
# 1. LOAD DATASET
# ────────────────────────────────────────────
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
file_path = "../test/data/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"

df = pd.read_csv(file_path)
df.columns = df.columns.str.strip()

print(f"Full dataset: {len(df):,} rows")
print(f"Class distribution:\n{df['Label'].value_counts()}\n")

# ────────────────────────────────────────────
# 2. SEPARATE FEATURES AND LABELS
# ────────────────────────────────────────────
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
# 3. CLEAN INFINITIES AND NaNs
# ────────────────────────────────────────────
X = X.replace([np.inf, -np.inf], np.nan)
nan_counts = X.isnull().sum()
if nan_counts.any():
    print("Columns with NaN/Inf — filling with median:")
    print(nan_counts[nan_counts > 0])
X = X.fillna(X.median(numeric_only=True))
print()

# ────────────────────────────────────────────
# 4. STANDARDIZE FEATURES
# ────────────────────────────────────────────
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ────────────────────────────────────────────
# 5. AUTOENCODER SETUP
#    Train on BENIGN traffic only
#    Uses validation split + early stopping
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
X_tensor_val   = torch.tensor(X_normal_val,   dtype=torch.float32)

dataset    = TensorDataset(X_tensor_train)
dataloader = DataLoader(dataset, batch_size=64, shuffle=True)


# ────────────────────────────────────────────
# 6. MODEL DEFINITION
# ────────────────────────────────────────────
class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super(Autoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 16)   # tight bottleneck
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
model     = Autoencoder(input_dim)
optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
criterion = nn.MSELoss()
scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
    optimizer, mode='min', factor=0.5, patience=3
)

# ────────────────────────────────────────────
# 7. TRAINING LOOP WITH EARLY STOPPING
# ────────────────────────────────────────────
num_epochs      = 100
best_val_loss   = float('inf')
patience        = 8
patience_counter = 0
best_model_state = None
train_losses    = []
val_losses      = []

print("Training Autoencoder...")
start_time = time.time()

for epoch in range(num_epochs):

    # ── Training pass ──
    model.train()
    epoch_loss = 0
    for batch in dataloader:
        inputs  = batch[0]
        outputs = model(inputs)
        loss    = criterion(outputs, inputs)
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        epoch_loss += loss.item()

    avg_train_loss = epoch_loss / len(dataloader)
    train_losses.append(avg_train_loss)

    # ── Validation pass ──
    model.eval()
    with torch.no_grad():
        val_out  = model(X_tensor_val)
        val_loss = criterion(val_out, X_tensor_val).item()
    val_losses.append(val_loss)

    # ── LR scheduler step ──
    scheduler.step(val_loss)

    # ── Early stopping check ──
    if val_loss < best_val_loss:
        best_val_loss    = val_loss
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

# ────────────────────────────────────────────
# 8. INFERENCE — reconstruction errors
# ────────────────────────────────────────────
model.eval()
X_tensor_full = torch.tensor(X_scaled, dtype=torch.float32)
with torch.no_grad():
    reconstructed = model(X_tensor_full)
    errors = torch.mean((X_tensor_full - reconstructed) ** 2, dim=1).numpy()

# Threshold based on actual attack ratio in data
ae_threshold = np.percentile(errors, (1 - attack_ratio) * 100)
ae_preds     = (errors > ae_threshold).astype(int)

# ────────────────────────────────────────────
# SAVE TRAINED MODEL + PREPROCESSING OBJECTS
# ────────────────────────────────────────────

#Create artifacts directory if it doesn't exist
os.makedirs("./artifacts", exist_ok=True)

# Save model state dict, scaler, threshold, and feature columns for live scoring
torch.save(model.state_dict(), "./artifacts/autoencoder_model.pth")
joblib.dump(scaler, "./artifacts/scaler.pkl")
joblib.dump(ae_threshold, "./artifacts/threshold.pkl")
joblib.dump(X.columns.tolist(), "./artifacts/feature_columns.pkl")

print("Saved model, scaler, threshold, and feature columns.")

# ────────────────────────────────────────────
# Start Sniffing Packets
# ────────────────────────────────────────────

def start_live_sniff(model, scaler, ae_threshold, feature_columns, interface=None, count=0):
    print(f"Starting live sniffing on interface {interface or 'default'}...")
    global flow_counter
    flow_counter = count
    sniff(prn=lambda pkt: live_callback(pkt, model, scaler, ae_threshold, feature_columns),
          iface=interface,
          count=count,
          store=False)

# ────────────────────────────────────────────
# Multi-packet Monitoring
# ────────────────────────────────────────────
flows = {}
FLOW_PACKET_LIMIT = 10
flow_counter = 0
def live_callback(pkt, model, scaler, ae_threshold, feature_columns):
    global flow_counter
    if not (pkt.haslayer(IP) and (pkt.haslayer(TCP) or pkt.haslayer(UDP))):
        flow_counter = flow_counter - 1
        return

    src = pkt[IP].src
    dst = pkt[IP].dst

    l4 = pkt[TCP] if pkt.haslayer(TCP) else pkt[UDP]
    sport = l4.sport
    dport = l4.dport
    proto = pkt[IP].proto

    flow_id = (src, dst, sport, dport, proto)

    pkt_data = packet_to_features(pkt)

    if flow_id not in flows:
        flows[flow_id] = []

    flows[flow_id].append(pkt_data)

    # When flow has enough packets → analyze
    if len(flows[flow_id]) >= FLOW_PACKET_LIMIT:

        flow_packets = flows[flow_id]

        prediction, error = detect_event(
            flow_packets, model, scaler, ae_threshold, feature_columns
        )

        print(f"[Live Flow] Packets: {len(flow_packets)} | Prediction: {prediction} | Error: {error:.6f}")

        del flows[flow_id]
    if flow_counter == 1:
        for leftover_flow_id, leftover_packets in flows.items():
            prediction, error = detect_event(leftover_packets, model, scaler, ae_threshold, feature_columns)
            print(f"[Live Flow - Leftover] Packets: {len(leftover_packets)} | Prediction: {prediction} | Error: {error:.6f}")
        flows.clear()
    flow_counter = flow_counter - 1

def packet_to_features(pkt):
    data = {}

    data["timestamp"] = pkt.time
    data["length"] = len(pkt)

    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        l4 = pkt[TCP] if pkt.haslayer(TCP) else pkt[UDP]
        data["Source Port"] = int(l4.sport)
        data["Destination Port"] = int(l4.dport)
    else:
        data["Source Port"] = 0
        data["Destination Port"] = 0

    if pkt.haslayer(TCP):
        data["flags"] = int(pkt[TCP].flags)
    else:
        data["flags"] = 0

    return data

def flow_to_features(flow_packets, feature_columns):

    features = {col: 0 for col in feature_columns}

    timestamps = [p["timestamp"] for p in flow_packets]
    lengths = [p["length"] for p in flow_packets]

    duration = max(timestamps) - min(timestamps)
    duration = max(duration, 1e-6)

    # ── Flow duration ──
    if "Flow Duration" in feature_columns:
        features["Flow Duration"] = duration

    # ── Packet length statistics ──
    if "Min Packet Length" in feature_columns:
        features["Min Packet Length"] = min(lengths)

    if "Max Packet Length" in feature_columns:
        features["Max Packet Length"] = max(lengths)

    if "Packet Length Mean" in feature_columns:
        features["Packet Length Mean"] = sum(lengths) / len(lengths)

    if len(lengths) > 1:
        mean = sum(lengths) / len(lengths)
        variance = sum((x - mean) ** 2 for x in lengths) / len(lengths)

        if "Packet Length Variance" in feature_columns:
            features["Packet Length Variance"] = variance

        if "Packet Length Std" in feature_columns:
            features["Packet Length Std"] = variance ** 0.5

    # ── Flow throughput ──
    if "Flow Bytes/s" in feature_columns:
        features["Flow Bytes/s"] = sum(lengths) / duration

    if "Flow Packets/s" in feature_columns:
        features["Flow Packets/s"] = len(lengths) / duration

    # ── Packet counts (basic approximation) ──
    if "Total Fwd Packets" in feature_columns:
        features["Total Fwd Packets"] = len(flow_packets)

    if "Total Backward Packets" in feature_columns:
        features["Total Backward Packets"] = 0

    # ── Ports (constant for a flow) ──
    if "Source Port" in feature_columns:
        features["Source Port"] = flow_packets[0]["Source Port"]

    if "Destination Port" in feature_columns:
        features["Destination Port"] = flow_packets[0]["Destination Port"]

    # ── Return vector in correct order ──
    return [features[col] for col in feature_columns]

# ────────────────────────────────────────────
# Detect event using AE model (packet input)
# ────────────────────────────────────────────
def detect_event(flow_packets, model, scaler, ae_threshold, feature_columns):

    feature_vector = flow_to_features(flow_packets, feature_columns)
    event_df = pd.DataFrame([feature_vector], columns=feature_columns)

    # Normalize
    event_scaled = scaler.transform(event_df)
    event_tensor = torch.tensor(event_scaled, dtype=torch.float32)

    with torch.no_grad():
        reconstructed = model(event_tensor)
        error = torch.mean((event_tensor - reconstructed) ** 2).item()

    prediction = "ATTACK" if error > ae_threshold else "BENIGN"

    return prediction, error


# ────────────────────────────────────────────
# 9. EVALUATION & STATS
# ────────────────────────────────────────────
TARGET_NAMES = ["Benign", "Attack"]

print("=" * 52)
print(" AUTOENCODER — Full Evaluation")
print("=" * 52)
print(classification_report(y_binary, ae_preds, target_names=TARGET_NAMES, zero_division=0))

auc = roc_auc_score(y_binary, errors)
print(f"ROC AUC Score : {auc:.4f}")
print(f"Threshold used: {ae_threshold:.6f}  (at {(1 - attack_ratio)*100:.1f}th percentile)\n")

# Per-attack-type breakdown
print("=" * 52)
print("DETECTION RATE BY ATTACK TYPE")
print("=" * 52)
print(f"{'Attack Type':<25} {'Detected':>10} {'Total':>8} {'Rate':>8}")
print("-" * 52)

attack_types = df[df["Label"] != "BENIGN"]["Label"].unique()
for attack in sorted(attack_types):
    mask     = (df["Label"].values == attack)
    X_attack = X_scaled[mask]
    attack_tensor = torch.tensor(X_attack, dtype=torch.float32)
    with torch.no_grad():
        recon         = model(attack_tensor)
        attack_errors = torch.mean((attack_tensor - recon) ** 2, dim=1).numpy()
    detected = (attack_errors > ae_threshold).sum()
    total    = mask.sum()
    print(f"{attack:<25} {detected:>10,} {total:>8,} {detected/total:>7.1%}")

print("-" * 52)

# ────────────────────────────────────────────
# 10. VISUALIZATIONS
# ────────────────────────────────────────────

# ── A. Training Loss Curve ──
plt.figure(figsize=(8, 4))
plt.plot(train_losses, label="Train Loss", color="blue", lw=2)
plt.plot(val_losses,   label="Val Loss",   color="orange", lw=2)
early_stop_epoch = len(val_losses) - patience_counter - 1
plt.axvline(early_stop_epoch, color="red", linestyle="--", label="Early Stop Point")
plt.xlabel("Epoch")
plt.ylabel("MSE Loss")
plt.title("Autoencoder Training vs Validation Loss")
plt.legend()
plt.tight_layout()
plt.savefig("./diagrams/ae_loss_curve.png", dpi=150)
plt.show()
print("Saved: ae_loss_curve.png")

# ── B. Confusion Matrix ──
cm = confusion_matrix(y_binary, ae_preds)
plt.figure(figsize=(5, 4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=TARGET_NAMES, yticklabels=TARGET_NAMES)
plt.title("Autoencoder — Confusion Matrix")
plt.ylabel("True Label")
plt.xlabel("Predicted Label")
plt.tight_layout()
plt.savefig("./diagrams/ae_confusion_matrix.png", dpi=150)
plt.show()
print("Saved: ae_confusion_matrix.png")

# ── C. ROC Curve ──
fpr, tpr, _ = roc_curve(y_binary, errors)
plt.figure(figsize=(7, 5))
plt.plot(fpr, tpr, color="blue", lw=2, label=f"Autoencoder (AUC = {auc:.4f})")
plt.plot([0, 1], [0, 1], 'k--', lw=1, label="Random Baseline")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate (Recall)")
plt.title("Autoencoder — ROC Curve")
plt.legend(loc="lower right")
plt.tight_layout()
plt.savefig("./diagrams/ae_roc_curve.png", dpi=150)
plt.show()
print("Saved: ae_roc_curve.png")

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
plt.title("Autoencoder — Reconstruction Error Distribution")
plt.legend()
plt.tight_layout()
plt.savefig("./diagrams/ae_error_distribution.png", dpi=150)
plt.show()
print("Saved: ae_error_distribution.png")

print("\nDone.")

# Test Case
# if __name__ == "__main__":
#     start_live_sniff(model, scaler, ae_threshold, feature_columns, interface=None, count=50)