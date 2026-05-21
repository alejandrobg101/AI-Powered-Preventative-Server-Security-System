"""SQLite schema management for the IDS application.

The database is deliberately local and file-backed. create_db() is safe to run
on every startup; db_reset() is interactive and should only run in CLI contexts.
"""

import sqlite3
import shutil

try:
    from .paths import db_path, ensure_runtime_dirs, logs_dir
except ImportError:
    from paths import db_path, ensure_runtime_dirs, logs_dir


def create_db():
    """Create all application tables and the logs directory if needed."""
    conn = sqlite3.connect(db_path())
    cursor = conn.cursor()

    # Main alert store. Low-risk flows are intentionally excluded and counted
    # in general_metrics instead.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        IP TEXT NOT NULL,
        anomaly_type TEXT NOT NULL,
        recon_error REAL NOT NULL,
        risk_level TEXT NOT NULL,
        suggested_response TEXT NOT NULL
    )
    """)

    # Dashboard authentication. Passwords are bcrypt hashes, never plaintext.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )
    """)

    # Per-user autoencoder thresholds produced by live calibration.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_thresholds (
        user_id TEXT PRIMARY KEY,
        threshold REAL NOT NULL
    )
    """)

    # Tracks long-running dashboard calibration jobs so page refreshes can
    # resume progress display instead of losing state.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS calibration_sessions (
        session_id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        status TEXT NOT NULL,
        started_at TEXT NOT NULL,
        stopped_at TEXT,
        duration_seconds INTEGER DEFAULT 180,
        sample_count INTEGER DEFAULT 0,
        computed_threshold REAL,
        error_message TEXT,
        baseline_event_id INTEGER DEFAULT 0
    )
    """)

    # Miscellaneous counters that are not alert rows, currently Low-risk flows.
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS general_metrics (
        metric_name TEXT PRIMARY KEY,
        metric_value INTEGER DEFAULT 0
    )
    """)
    cursor.execute("INSERT OR IGNORE INTO general_metrics (metric_name, metric_value) VALUES ('low_risk_events', 0)")

    ensure_runtime_dirs()

    conn.commit()
    conn.close()


def db_reset():
    """Interactively clear the database and logs before a live capture run."""
    db_file = db_path()
    if db_file.exists():
        confirm = input("\nDatabase already exists. If you want to reset, write table or database otherwise say no?\nThis will clear existing logs: ").strip().lower()

        if confirm == "database":
            db_file.unlink()
            log_dir = logs_dir()
            if log_dir.exists():
                shutil.rmtree(log_dir)
            print("Database and logs deleted.")
        elif confirm == "table":
            while True:
                preserve = input("Preserve user_thresholds table, users table or both? ([users, threshold, both]/no): ").strip().lower()
                if preserve in ("users", "no", "threshold", "both"):
                    break
                print("Invalid input. Please type 'users' or 'threshold' or 'both' or 'no'.")
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()

            # Drop all app tables except the optional preserved state.
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()

            for table in tables:
                table_name = table[0]

                if table_name == "sqlite_sequence":
                    continue

                if table_name == "user_thresholds" and preserve in ("threshold", "both"):
                    continue

                if table_name == "users" and preserve in ("users", "both"):
                    continue

                cursor.execute(f"DROP TABLE IF EXISTS {table_name}")

            conn.commit()
            conn.close()

            log_dir = logs_dir()
            if log_dir.exists():
                shutil.rmtree(log_dir)  # removes folder + everything inside

            print("Tables and old logs cleared.")
        else:
            print("Reset cancelled.")
