import sqlite3
import os
import shutil

# This script creates the SQLite database and the threat_memory table if it doesn't already exist.
# Only run this script once to set up the database. If you need to reset the database, you can uncomment the line that drops the table.
## Version 1.2 Reset option through input prompt
    # Result File name: threat_memory.db
    # Change: Database creation will be inside an if condition
## Version 1.3 Turn file into function
def create_db():
        conn = sqlite3.connect("threat_memory.db")
        cursor = conn.cursor()

        # No need to edit code
        # Uncomment the following line to drop the table if it already exists to reset the database
        #cursor.execute("DROP TABLE IF EXISTS threat_memory")

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

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_thresholds (
            user_id TEXT PRIMARY KEY,
            threshold REAL NOT NULL
        )
        """)

        print("Database created successfully.")

        conn.commit()
        conn.close()

if os.path.exists("threat_memory.db"):
    confirm = input("\nDatabase already exists. If you want to reset, write table or database otherwise say no?\nThis will clear existing logs: ").strip().lower()

    if confirm == "database":
        os.remove("threat_memory.db")
        log_dir = "logs/response_logs"
        if os.path.exists(log_dir):
            shutil.rmtree(log_dir)
        print("Database and logs deleted.")
    elif confirm == "table":
        while True:
            preserve = input("Preserve user_thresholds table? (yes/no): ").strip().lower()
            if preserve in ("yes", "no"):
                break
            print("Invalid input. Please type 'yes' or 'no'.")
        conn = sqlite3.connect("threat_memory.db")
        cursor = conn.cursor()

        # get all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()

        # drop each table
        for table in tables:
            table_name = table[0]

            if table_name == "sqlite_sequence":
                continue

            if preserve == "yes" and table_name == "user_thresholds":
                continue

            cursor.execute(f"DROP TABLE IF EXISTS {table_name}")

        conn.commit()
        conn.close()

        log_dir = "logs/response_logs"

        if os.path.exists(log_dir):
            shutil.rmtree(log_dir)  # removes folder + everything inside

        print("Tables and old logs cleared.")
    else:
        print("Reset cancelled.")