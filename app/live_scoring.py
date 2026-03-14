import pandas as pd
import torch
import torch.nn as nn
import numpy as np
import joblib


# Same model architecture as training
class Autoencoder(nn.Module):
    def __init__(self, input_dim):
        super(Autoencoder, self).__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, 16)
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


# Load saved artifacts
feature_columns = joblib.load("artifacts/feature_columns.pkl")
scaler = joblib.load("artifacts/scaler.pkl")
threshold = joblib.load("artifacts/threshold.pkl")

model = Autoencoder(len(feature_columns))
model.load_state_dict(torch.load("artifacts/autoencoder_model.pth"))
model.eval()


def score_live_vector(feature_vector):
    """
    Score a live feature vector using the trained autoencoder
    """

    x_live = pd.DataFrame([feature_vector], columns=feature_columns)

    x_live = x_live.replace([np.inf, -np.inf], np.nan)
    x_live = x_live.fillna(0)

    x_scaled = scaler.transform(x_live)
    x_tensor = torch.tensor(x_scaled, dtype=torch.float32)

    with torch.no_grad():
        reconstructed = model(x_tensor)
        error = torch.mean((x_tensor - reconstructed) ** 2, dim=1).item()

    prediction = "ATTACK" if error > threshold else "BENIGN"

    return error, prediction


# Use this block to test the live scoring function with a sample row from the dataset. Make sure to update the file path and row number as needed.
if __name__ == "__main__":
    file_path = "../test/data/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"

    df = pd.read_csv(file_path)
    df.columns = df.columns.str.strip()

    row_number = 39755

    row = df.iloc[row_number]

    actual_label = row["Label"]

    feature_vector = row.drop("Label").to_dict()

    error, prediction = score_live_vector(feature_vector)

    print("Row:", row_number)
    print("Actual label:", actual_label)
    print("Prediction:", prediction)
    print("Reconstruction error:", error)
