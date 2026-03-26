import sqlite3

# This script creates the SQLite database and the threat_memory table if it doesn't already exist.
# Only run this script once to set up the database. If you need to reset the database, you can uncomment the line that drops the table.
conn = sqlite3.connect("threat_memory.db")
cursor = conn.cursor()

# Uncomment the following line to drop the table if it already exists to reset the database
#cursor.execute("DROP TABLE IF EXISTS threat_memory")

cursor.execute("""
CREATE TABLE IF NOT EXISTS threat_memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    anomaly_type TEXT NOT NULL,
    recon_error REAL NOT NULL,
    risk_level TEXT NOT NULL,
    suggested_response TEXT NOT NULL
)
""")

print("Database created successfully. Use the testdb.py file to verify the table creation.")

conn.commit()
conn.close()