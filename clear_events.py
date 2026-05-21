"""Clear stored alert rows and aggregate metric rows from the app database.

This is a small maintenance helper for local demos/tests. It keeps the database
file itself, users, thresholds, and calibration sessions intact.
"""

import sqlite3
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent / "app"
sys.path.insert(0, str(APP_DIR))

from paths import db_path
from schema import create_db

create_db()
conn = sqlite3.connect(db_path())

# Remove historical alert rows and reset aggregate metrics without deleting the
# metric keys the dashboard expects to exist.
conn.execute('DELETE FROM threat_events')
conn.execute("UPDATE general_metrics SET metric_value = 0 WHERE metric_name = 'low_risk_events'")
conn.execute("INSERT OR IGNORE INTO general_metrics (metric_name, metric_value) VALUES ('low_risk_events', 0)")
conn.commit()
remaining = conn.execute('SELECT COUNT(*) FROM threat_events').fetchone()[0]
print(f'Cleared. threat_events rows remaining: {remaining}')
conn.close()
