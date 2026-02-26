import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

np.random.seed(42)

SAMPLES = {
    "BENIGN":       3000,
    "DDoS":         1500,
    "PortScan":     1000,
    "BruteForce":    800,
    "Botnet":        600,
    "Exfiltration":  400,
    "ZeroDay":       400,
}

def make_features(label, n):
    base = {}

    if label == "BENIGN":
        base["Flow Duration"]           = np.random.lognormal(10, 2, n).clip(100, 120_000_000)
        base["Total Fwd Packets"]       = np.random.randint(2, 25, n).astype(float)
        base["Total Backward Packets"]  = np.random.randint(2, 20, n).astype(float)
        base["Flow Bytes/s"]            = np.random.lognormal(8, 2, n).clip(100, 1_000_000)
        base["Flow Packets/s"]          = np.random.lognormal(3, 1.5, n).clip(1, 5000)
        base["Flow IAT Mean"]           = np.random.lognormal(8, 2, n).clip(100, 5_000_000)
        base["Flow IAT Std"]            = np.random.lognormal(7, 2, n).clip(0, 3_000_000)
        base["Flow IAT Max"]            = np.random.lognormal(10, 2, n).clip(1000, 30_000_000)
        base["Flow IAT Min"]            = np.random.exponential(500, n).clip(0, 100_000)
        base["Fwd Packet Length Mean"]  = np.random.normal(500, 200, n).clip(40, 1500)
        base["Fwd Packet Length Std"]   = np.random.exponential(150, n).clip(0, 800)
        base["Bwd Packet Length Mean"]  = np.random.normal(450, 180, n).clip(40, 1500)
        base["Packet Length Mean"]      = np.random.normal(480, 180, n).clip(40, 1500)
        base["Packet Length Std"]       = np.random.exponential(200, n).clip(0, 1000)
        base["Min Packet Length"]       = np.random.randint(40, 100, n).astype(float)
        base["Max Packet Length"]       = np.random.randint(500, 1500, n).astype(float)
        base["SYN Flag Count"]          = np.random.binomial(1, 0.7, n).astype(float)
        base["RST Flag Count"]          = np.random.binomial(1, 0.05, n).astype(float)
        base["ACK Flag Count"]          = np.random.binomial(1, 0.9, n).astype(float)
        base["PSH Flag Count"]          = np.random.binomial(1, 0.5, n).astype(float)
        base["FIN Flag Count"]          = np.random.binomial(1, 0.6, n).astype(float)
        base["URG Flag Count"]          = np.zeros(n)
        base["Down/Up Ratio"]           = np.random.normal(1.0, 0.3, n).clip(0, 5)
        base["Fwd Packets/s"]           = np.random.lognormal(2, 1.2, n).clip(0.1, 2000)
        base["Bwd Packets/s"]           = np.random.lognormal(2, 1.2, n).clip(0.1, 2000)
        base["Init_Win_bytes_forward"]  = np.random.choice([8192, 16384, 32768, 65535], n).astype(float)
        base["Init_Win_bytes_backward"] = np.random.choice([8192, 16384, 32768, 65535], n).astype(float)

    elif label == "DDoS":
        # KEY: high packet rate, tiny packets, near-zero IAT, unidirectional
        base["Flow Duration"]           = np.random.randint(1000, 5_000_000, n).astype(float)
        base["Total Fwd Packets"]       = np.random.randint(100, 5000, n).astype(float)
        base["Total Backward Packets"]  = np.random.randint(0, 5, n).astype(float)
        base["Flow Bytes/s"]            = np.random.lognormal(11, 1, n).clip(50_000, 10_000_000)
        base["Flow Packets/s"]          = np.random.lognormal(9, 1, n).clip(1000, 500_000)  # KEY
        base["Flow IAT Mean"]           = np.random.exponential(500, n).clip(0, 5000)        # KEY near-zero
        base["Flow IAT Std"]            = np.random.exponential(200, n).clip(0, 2000)
        base["Flow IAT Max"]            = np.random.randint(100, 10_000, n).astype(float)
        base["Flow IAT Min"]            = np.random.randint(0, 100, n).astype(float)
        base["Fwd Packet Length Mean"]  = np.random.normal(60, 20, n).clip(40, 200)          # KEY tiny
        base["Fwd Packet Length Std"]   = np.random.exponential(10, n).clip(0, 50)
        base["Bwd Packet Length Mean"]  = np.random.normal(50, 15, n).clip(0, 100)
        base["Packet Length Mean"]      = np.random.normal(60, 15, n).clip(40, 200)
        base["Packet Length Std"]       = np.random.exponential(10, n).clip(0, 50)
        base["Min Packet Length"]       = np.random.randint(40, 65, n).astype(float)
        base["Max Packet Length"]       = np.random.randint(60, 200, n).astype(float)
        base["SYN Flag Count"]          = np.random.binomial(1, 0.95, n).astype(float)       # KEY
        base["RST Flag Count"]          = np.zeros(n)
        base["ACK Flag Count"]          = np.zeros(n)
        base["PSH Flag Count"]          = np.zeros(n)
        base["FIN Flag Count"]          = np.zeros(n)
        base["URG Flag Count"]          = np.zeros(n)
        base["Down/Up Ratio"]           = np.random.exponential(0.01, n).clip(0, 0.1)        # KEY
        base["Fwd Packets/s"]           = np.random.lognormal(9, 1, n).clip(1000, 500_000)
        base["Bwd Packets/s"]           = np.random.exponential(1, n).clip(0, 10)
        base["Init_Win_bytes_forward"]  = np.random.choice([512, 1024, 2048], n).astype(float)
        base["Init_Win_bytes_backward"] = np.full(n, -1.0)

    elif label == "PortScan":
        # KEY: 1-3 packets per flow, high RST, very short duration
        base["Flow Duration"]           = np.random.randint(1, 500_000, n).astype(float)     # KEY short
        base["Total Fwd Packets"]       = np.random.randint(1, 4, n).astype(float)           # KEY 1-3
        base["Total Backward Packets"]  = np.random.randint(0, 3, n).astype(float)
        base["Flow Bytes/s"]            = np.random.lognormal(5, 1.5, n).clip(10, 100_000)
        base["Flow Packets/s"]          = np.random.lognormal(4, 1.5, n).clip(1, 50_000)
        base["Flow IAT Mean"]           = np.random.lognormal(6, 2, n).clip(10, 500_000)
        base["Flow IAT Std"]            = np.zeros(n)
        base["Flow IAT Max"]            = np.random.lognormal(6, 2, n).clip(10, 500_000)
        base["Flow IAT Min"]            = np.random.lognormal(6, 2, n).clip(10, 500_000)
        base["Fwd Packet Length Mean"]  = np.random.normal(50, 10, n).clip(40, 80)
        base["Fwd Packet Length Std"]   = np.zeros(n)
        base["Bwd Packet Length Mean"]  = np.random.normal(44, 5, n).clip(0, 60)
        base["Packet Length Mean"]      = np.random.normal(47, 8, n).clip(40, 80)
        base["Packet Length Std"]       = np.random.exponential(5, n).clip(0, 30)
        base["Min Packet Length"]       = np.full(n, 40.0)
        base["Max Packet Length"]       = np.random.randint(40, 80, n).astype(float)
        base["SYN Flag Count"]          = np.ones(n)                                          # KEY
        base["RST Flag Count"]          = np.random.binomial(1, 0.7, n).astype(float)        # KEY port closed
        base["ACK Flag Count"]          = np.random.binomial(1, 0.3, n).astype(float)
        base["PSH Flag Count"]          = np.zeros(n)
        base["FIN Flag Count"]          = np.zeros(n)
        base["URG Flag Count"]          = np.zeros(n)
        base["Down/Up Ratio"]           = np.random.normal(0.5, 0.3, n).clip(0, 2)
        base["Fwd Packets/s"]           = np.random.lognormal(4, 1.5, n).clip(1, 50_000)
        base["Bwd Packets/s"]           = np.random.lognormal(3, 1.5, n).clip(0, 30_000)
        base["Init_Win_bytes_forward"]  = np.random.choice([1024, 8192], n).astype(float)
        base["Init_Win_bytes_backward"] = np.random.choice([-1, 1024, 8192], n).astype(float)

    elif label == "BruteForce":
        # KEY: machine-regular timing (low IAT std), small payloads, repeated
        base["Flow Duration"]           = np.random.normal(2_000_000, 500_000, n).clip(500_000, 5_000_000)
        base["Total Fwd Packets"]       = np.random.randint(4, 12, n).astype(float)
        base["Total Backward Packets"]  = np.random.randint(3, 10, n).astype(float)
        base["Flow Bytes/s"]            = np.random.lognormal(5, 0.5, n).clip(100, 5000)
        base["Flow Packets/s"]          = np.random.lognormal(2, 0.5, n).clip(1, 50)
        base["Flow IAT Mean"]           = np.random.normal(300_000, 50_000, n).clip(100_000, 600_000)  # KEY regular
        base["Flow IAT Std"]            = np.random.normal(10_000, 5_000, n).clip(0, 50_000)           # KEY low std
        base["Flow IAT Max"]            = np.random.normal(350_000, 60_000, n).clip(100_000, 700_000)
        base["Flow IAT Min"]            = np.random.normal(250_000, 50_000, n).clip(50_000, 500_000)
        base["Fwd Packet Length Mean"]  = np.random.normal(80, 20, n).clip(40, 200)
        base["Fwd Packet Length Std"]   = np.random.exponential(15, n).clip(0, 80)
        base["Bwd Packet Length Mean"]  = np.random.normal(70, 20, n).clip(40, 150)
        base["Packet Length Mean"]      = np.random.normal(75, 20, n).clip(40, 200)
        base["Packet Length Std"]       = np.random.exponential(20, n).clip(0, 100)
        base["Min Packet Length"]       = np.random.randint(40, 60, n).astype(float)
        base["Max Packet Length"]       = np.random.randint(100, 300, n).astype(float)
        base["SYN Flag Count"]          = np.ones(n)
        base["RST Flag Count"]          = np.random.binomial(1, 0.1, n).astype(float)
        base["ACK Flag Count"]          = np.ones(n)
        base["PSH Flag Count"]          = np.ones(n)
        base["FIN Flag Count"]          = np.random.binomial(1, 0.6, n).astype(float)
        base["URG Flag Count"]          = np.zeros(n)
        base["Down/Up Ratio"]           = np.random.normal(0.9, 0.1, n).clip(0.5, 1.5)
        base["Fwd Packets/s"]           = np.random.lognormal(1.5, 0.5, n).clip(0.5, 20)
        base["Bwd Packets/s"]           = np.random.lognormal(1.5, 0.5, n).clip(0.5, 20)
        base["Init_Win_bytes_forward"]  = np.full(n, 8192.0)
        base["Init_Win_bytes_backward"] = np.full(n, 8192.0)

    elif label == "Botnet":
        # KEY: ~60s periodic beacon, tiny consistent payload — hardest to detect
        base["Flow Duration"]           = np.random.normal(30_000_000, 5_000_000, n).clip(10_000_000, 60_000_000)
        base["Total Fwd Packets"]       = np.random.randint(3, 8, n).astype(float)
        base["Total Backward Packets"]  = np.random.randint(2, 6, n).astype(float)
        base["Flow Bytes/s"]            = np.random.lognormal(3, 0.5, n).clip(10, 500)         # KEY very low
        base["Flow Packets/s"]          = np.random.lognormal(1, 0.5, n).clip(0.1, 5)          # KEY very low
        base["Flow IAT Mean"]           = np.random.normal(60_000_000, 5_000_000, n).clip(30_000_000, 120_000_000)  # KEY ~60s
        base["Flow IAT Std"]            = np.random.normal(1_000_000, 200_000, n).clip(0, 5_000_000)               # KEY low
        base["Flow IAT Max"]            = np.random.normal(65_000_000, 5_000_000, n).clip(30_000_000, 130_000_000)
        base["Flow IAT Min"]            = np.random.normal(55_000_000, 5_000_000, n).clip(25_000_000, 110_000_000)
        base["Fwd Packet Length Mean"]  = np.random.normal(55, 10, n).clip(40, 100)             # KEY tiny beacon
        base["Fwd Packet Length Std"]   = np.random.exponential(5, n).clip(0, 25)               # KEY very consistent
        base["Bwd Packet Length Mean"]  = np.random.normal(50, 10, n).clip(40, 90)
        base["Packet Length Mean"]      = np.random.normal(52, 8, n).clip(40, 100)
        base["Packet Length Std"]       = np.random.exponential(5, n).clip(0, 30)
        base["Min Packet Length"]       = np.random.randint(40, 55, n).astype(float)
        base["Max Packet Length"]       = np.random.randint(55, 100, n).astype(float)
        base["SYN Flag Count"]          = np.ones(n)
        base["RST Flag Count"]          = np.zeros(n)
        base["ACK Flag Count"]          = np.ones(n)
        base["PSH Flag Count"]          = np.ones(n)
        base["FIN Flag Count"]          = np.random.binomial(1, 0.3, n).astype(float)
        base["URG Flag Count"]          = np.zeros(n)
        base["Down/Up Ratio"]           = np.random.normal(0.95, 0.05, n).clip(0.8, 1.2)
        base["Fwd Packets/s"]           = np.random.lognormal(0.5, 0.5, n).clip(0.05, 5)
        base["Bwd Packets/s"]           = np.random.lognormal(0.5, 0.5, n).clip(0.05, 5)
        base["Init_Win_bytes_forward"]  = np.full(n, 8192.0)
        base["Init_Win_bytes_backward"] = np.full(n, 8192.0)

    elif label == "Exfiltration":
        # KEY: huge fwd packets (upload to attacker), tiny bwd, asymmetric Down/Up near 0
        base["Flow Duration"]           = np.random.normal(50_000_000, 10_000_000, n).clip(10_000_000, 100_000_000)
        base["Total Fwd Packets"]       = np.random.randint(50, 500, n).astype(float)           # KEY many out
        base["Total Backward Packets"]  = np.random.randint(3, 15, n).astype(float)             # KEY few in
        base["Flow Bytes/s"]            = np.random.lognormal(8, 1, n).clip(10_000, 500_000)
        base["Flow Packets/s"]          = np.random.lognormal(4, 0.8, n).clip(10, 1000)
        base["Flow IAT Mean"]           = np.random.lognormal(6, 1, n).clip(1000, 1_000_000)
        base["Flow IAT Std"]            = np.random.lognormal(5, 1, n).clip(0, 500_000)
        base["Flow IAT Max"]            = np.random.lognormal(8, 1, n).clip(10_000, 10_000_000)
        base["Flow IAT Min"]            = np.random.exponential(1000, n).clip(0, 50_000)
        base["Fwd Packet Length Mean"]  = np.random.normal(1400, 100, n).clip(1000, 1500)       # KEY max-size
        base["Fwd Packet Length Std"]   = np.random.exponential(50, n).clip(0, 200)
        base["Bwd Packet Length Mean"]  = np.random.normal(200, 50, n).clip(40, 500)
        base["Packet Length Mean"]      = np.random.normal(1200, 200, n).clip(500, 1500)
        base["Packet Length Std"]       = np.random.exponential(200, n).clip(0, 600)
        base["Min Packet Length"]       = np.random.randint(40, 100, n).astype(float)
        base["Max Packet Length"]       = np.full(n, 1500.0)                                    # KEY at MTU
        base["SYN Flag Count"]          = np.ones(n)
        base["RST Flag Count"]          = np.zeros(n)
        base["ACK Flag Count"]          = np.ones(n)
        base["PSH Flag Count"]          = np.ones(n)
        base["FIN Flag Count"]          = np.random.binomial(1, 0.5, n).astype(float)
        base["URG Flag Count"]          = np.zeros(n)
        base["Down/Up Ratio"]           = np.random.exponential(0.02, n).clip(0, 0.1)           # KEY almost no download
        base["Fwd Packets/s"]           = np.random.lognormal(3.5, 0.8, n).clip(5, 500)
        base["Bwd Packets/s"]           = np.random.lognormal(1, 0.8, n).clip(0.1, 20)
        base["Init_Win_bytes_forward"]  = np.full(n, 65535.0)
        base["Init_Win_bytes_backward"] = np.random.choice([8192, 16384, 32768], n).astype(float)

    elif label == "ZeroDay":
        # Intentionally blended anomalous features — tests unsupervised detection of UNKNOWN attacks
        base["Flow Duration"]           = np.random.lognormal(10, 4, n).clip(100, 100_000_000)
        base["Total Fwd Packets"]       = np.random.randint(1, 300, n).astype(float)
        base["Total Backward Packets"]  = np.random.randint(0, 50, n).astype(float)
        base["Flow Bytes/s"]            = np.random.lognormal(7, 3, n).clip(1, 5_000_000)
        base["Flow Packets/s"]          = np.random.lognormal(4, 3, n).clip(0.1, 100_000)
        base["Flow IAT Mean"]           = np.random.lognormal(8, 3, n).clip(10, 10_000_000)
        base["Flow IAT Std"]            = np.random.lognormal(7, 3, n).clip(0, 5_000_000)
        base["Flow IAT Max"]            = np.random.lognormal(10, 3, n).clip(100, 50_000_000)
        base["Flow IAT Min"]            = np.random.lognormal(4, 3, n).clip(0, 100_000)
        base["Fwd Packet Length Mean"]  = np.random.lognormal(5, 2, n).clip(40, 1500)
        base["Fwd Packet Length Std"]   = np.random.lognormal(4, 2, n).clip(0, 800)
        base["Bwd Packet Length Mean"]  = np.random.lognormal(4, 2, n).clip(0, 1000)
        base["Packet Length Mean"]      = np.random.lognormal(5, 2, n).clip(40, 1500)
        base["Packet Length Std"]       = np.random.lognormal(4, 2, n).clip(0, 800)
        base["Min Packet Length"]       = np.random.randint(40, 200, n).astype(float)
        base["Max Packet Length"]       = np.random.randint(200, 1500, n).astype(float)
        base["SYN Flag Count"]          = np.random.binomial(1, 0.7, n).astype(float)
        base["RST Flag Count"]          = np.random.binomial(1, 0.3, n).astype(float)
        base["ACK Flag Count"]          = np.random.binomial(1, 0.7, n).astype(float)
        base["PSH Flag Count"]          = np.random.binomial(1, 0.6, n).astype(float)
        base["FIN Flag Count"]          = np.random.binomial(1, 0.4, n).astype(float)
        base["URG Flag Count"]          = np.random.binomial(1, 0.15, n).astype(float)  # KEY unusual
        base["Down/Up Ratio"]           = np.random.lognormal(0, 2, n).clip(0, 20)      # KEY unpredictable
        base["Fwd Packets/s"]           = np.random.lognormal(4, 3, n).clip(0.01, 50_000)
        base["Bwd Packets/s"]           = np.random.lognormal(3, 3, n).clip(0, 30_000)
        base["Init_Win_bytes_forward"]  = np.random.choice([512, 1024, 4096, 8192, 32768, 65535], n).astype(float)
        base["Init_Win_bytes_backward"] = np.random.choice([-1, 512, 1024, 4096, 8192, 32768], n).astype(float)

    base["Label"] = [label] * n
    return pd.DataFrame(base)


dfs = []
for label, n in SAMPLES.items():
    print(f"  Generating {n:,} {label} samples...")
    dfs.append(make_features(label, n))

df = pd.concat(dfs, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
df.to_csv("synthetic_security_dataset.csv", index=False)

print(f"\nSaved: synthetic_security_dataset.csv")
print(f"Total: {len(df):,} samples | {len(df.columns)-1} features + Label")
print("\nClass distribution:")
for label, count in df["Label"].value_counts().items():
    print(f"  {label:<15} {count:>5,}  ({count/len(df)*100:.1f}%)")