import sqlite3, os
conn = sqlite3.connect(os.path.join('app', 'threat_memory.db'))
conn.execute('DELETE FROM threat_events')
conn.execute('DELETE FROM general_metrics')
conn.commit()
remaining = conn.execute('SELECT COUNT(*) FROM threat_events').fetchone()[0]
print(f'Cleared. threat_events rows remaining: {remaining}')
conn.close()
