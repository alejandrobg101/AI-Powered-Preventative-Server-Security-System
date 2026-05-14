# AI-Powered Preventative Server Security System

An anomaly-detection security dashboard that watches live network traffic, scores each flow with a trained autoencoder, classifies risk, explains which features made the flow suspicious, and stores actionable alerts in SQLite.

## What It Does

In simple terms: this project acts like a lightweight security monitor for a server. It watches network traffic, looks for behavior that does not match the model's learned "normal" baseline, and shows suspicious activity in a live dashboard.

This means that when traffic looks unusual, the system:

- assigns a risk level: `Low`, `Medium`, `High`, or `Critical`
- infers an anomaly type such as `SYN_FLOOD`, `PORT_SCAN`, `SSH_BRUTE_FORCE`, or `WEB_ATTACK`
- recommends a response action
- logs the event to SQLite
- shows the alert in a Streamlit dashboard
- explains the alert with top feature deviations and a deviation score

## How It Works

The detection pipeline has four main stages:

1. **Packet capture**
   - `app/live_capture.py` uses Scapy to sniff IPv4 traffic from a selected network interface.
   - Packets are grouped into flows using a normalized 5-tuple: source IP, destination IP, source port, destination port, and protocol.

2. **Feature extraction**
   - Each flow is converted into CIC-IDS2017-style numeric features.
   - Examples include packet counts, flow duration, packet length statistics, TCP flags, byte rates, inter-arrival timing, and window sizes.

3. **ML anomaly scoring**
   - A trained PyTorch autoencoder reconstructs the feature vector.
   - The reconstruction error becomes the anomaly score.
   - `app/risk_classifier.py` maps that score into risk tiers.

4. **Response and explainability**
   - `app/response_engine.py` infers an anomaly type with network-rule logic.
   - `app/explainability.py` compares each feature against the training baseline and records:
     - top feature deviations
     - deviation score
     - whether the feature evidence supports the inferred anomaly type
   - Alerts are stored in `threat_memory.db` and surfaced in the dashboard.

## Dashboard

The Streamlit dashboard includes:

- **Live Events** - recent detections refreshed every 2 seconds
- **Risk Indicators** - Medium, High, and Critical alert totals
- **Historical Logs** - SQLite-backed anomaly table with filters for risk, source IP, anomaly type, and row count
- **Metrics** - total stored alerts, unique source IPs, repeated IPs, and latest detection time

Historical event detail views include reconstruction error, deviation score, recommendation text, top feature deviations, and response logs for High/Critical events.

## Project Structure

```text
.
|-- app/
|   |-- live_capture.py              # main live IDS runner
|   |-- dashboard.py                 # Streamlit dashboard
|   |-- autoencoder.py               # model training script
|   |-- risk_classifier.py           # reconstruction error -> risk tier
|   |-- response_engine.py           # anomaly type + recommendation rules
|   |-- explainability.py            # feature deviation and validation logic
|   |-- validate_explainability.py   # reviews stored alerts against target accuracy
|   |-- db_functions.py              # SQLite read/write helpers
|   |-- schema.py                    # SQLite schema creation/reset
|   `-- artifacts/                   # trained model, scaler, thresholds, features
|-- test/                            # lightweight unit tests and datasets
|-- attacks/                         # helper attack/test command material
|-- requirements.txt                 # Python dependency recipe
`-- README.md
```

## Requirements

- Python 3.10 to 3.12 recommended
- macOS, Linux, or Windows with Python installed
- Admin/root permissions for live packet capture
- Existing trained artifacts in `app/artifacts/`

The app uses Scapy for packet capture, PyTorch for the autoencoder, SQLite for local storage, and Streamlit for the UI.

## Setup

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Do not commit `.venv/`. It is local machine state and can be recreated from `requirements.txt`.

## Run The Full System

Run the live detector from the `app/` directory because the model artifacts, database, and logs are referenced with app-relative paths:

```bash
cd app
sudo ../.venv/bin/python live_capture.py
```

On Windows, run your terminal as Administrator and use:

```powershell
cd app
..\.venv\Scripts\python live_capture.py
```

If you need to choose a specific network interface:

```bash
sudo ../.venv/bin/python live_capture.py --iface en0
```

Useful options:

```bash
# Stop after 60 seconds
sudo ../.venv/bin/python live_capture.py --timeout 60

# Save captured packets to live.pcap
sudo ../.venv/bin/python live_capture.py --pcap

# Print top feature outliers in the terminal
sudo ../.venv/bin/python live_capture.py --debug
```

When the app starts, Streamlit should open automatically. If not, open:

```text
http://localhost:8501
```

To stop the app, press `Ctrl+C` in the terminal running `live_capture.py`.

## Run Only The Dashboard

If you want to inspect existing SQLite results without packet capture:

```bash
cd app
../.venv/bin/python -c "from schema import create_db; create_db()"
../.venv/bin/streamlit run dashboard.py
```

## Database Reset Prompt

When `live_capture.py` starts and `threat_memory.db` already exists, the app asks whether to reset:

- `no` - keep existing database and logs
- `table` - clear tables and logs, with an option to preserve threshold settings
- `database` - delete the database and logs completely

Use `no` when you want to keep historical alerts.

## Manual Smoke Test

After launching the app, generate harmless traffic in another terminal:

```bash
ping -c 10 1.1.1.1
for i in {1..20}; do curl -s https://example.com >/dev/null; done
```

Then check:

- **Live Events** updates within a few seconds
- **Historical Logs** shows stored non-low alerts
- selected events show deviation score and top feature deviations
- response logs appear for High/Critical events

You can also inspect SQLite directly:

```bash
cd app
sqlite3 threat_memory.db "SELECT id, timestamp, IP, anomaly_type, risk_level, recon_error, deviation_score FROM threat_events ORDER BY id DESC LIMIT 10;"
```

## Explainability Validation

The explainability validator reviews 100% of stored alerts and checks whether the recorded feature deviations support the inferred anomaly type.

```bash
cd app
../.venv/bin/python validate_explainability.py --target 0.90
```

Expected output includes:

- reviewed alert count
- passed/failed reviews
- interpretability score
- whether the score meets the target

If it reports `0 / 0` reviewed alerts, the database does not currently contain stored non-low alerts.

## Tests

Run the lightweight test scripts from the repository root:

```bash
./.venv/bin/python test/test_risk_classifier.py
./.venv/bin/python test/test_response_engine.py
./.venv/bin/python test/test_live_alert_feed.py
./.venv/bin/python test/test_explainability.py
./.venv/bin/python test/test_risk_classifier_db_operations.py
```

Or run them with pytest:

```bash
./.venv/bin/pytest test
```

## Training And Artifacts

The repository includes trained artifacts in `app/artifacts/`:

- `autoencoder_model.pth`
- `scaler.pkl`
- `threshold.pkl`
- `feature_columns.pkl`

These are loaded by the live capture pipeline. If you retrain the model with `app/autoencoder.py`, make sure the generated artifacts remain compatible with `live_capture.py` and `diagnose_features.py`.

## Troubleshooting

**`sudo` asks for a password**

Packet sniffing usually requires admin/root privileges. Type your macOS/Linux user password. The terminal will not show characters while you type.

**No alerts appear**

Low-risk traffic increments metrics but is not stored in the historical anomaly table. Try running longer, selecting the correct interface, or using `--debug` to inspect feature scoring.

**Streamlit does not open**

Open `http://localhost:8501` manually, or run only the dashboard with:

```bash
cd app
../.venv/bin/streamlit run dashboard.py
```

**Wrong interface**

List interfaces with a Python/Scapy shell or try common names like `en0` on macOS and `eth0`/`wlan0` on Linux.

**Dependency errors**

Recreate the venv:

```bash
rm -rf .venv
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
