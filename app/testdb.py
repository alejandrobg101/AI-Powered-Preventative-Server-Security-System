import sqlite3

# This script is used to test the database connection and verify that the threat_memory table was created successfully.
# It also inserts a mock entry into the table and retrieves all entries to confirm that the data is being stored correctly.
# Run this script after running schema.py to set up the database. You should see the mock entry printed in the output.
# It has a check so that you dont accidentally insert the mock entry multiple times if you run this script more than once.

conn = sqlite3.connect("threat_memory.db")
cursor = conn.cursor()

# Insert mock data
cursor.execute("SELECT COUNT(*) FROM threat_memory")
count = cursor.fetchone()[0]

if count == 0:
    cursor.execute("""
    INSERT INTO threat_memory (
        timestamp,
        anomaly_type,
        recon_error,
        risk_level,
        suggested_response
    ) VALUES (?, ?, ?, ?, ?)
    """, (
        "2026-03-26 22:00:00",
        "Test anomaly",
        0.75,
        "MEDIUM",
        "Log and monitor traffic"
    ))
    conn.commit()

# Retrieve data so teammates can see it worked
cursor.execute("SELECT * FROM threat_memory")
rows = cursor.fetchall()

print("Current entries in threat_memory:")
for row in rows:
    print(row)

conn.close()