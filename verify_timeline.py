from src.database import get_connection

conn = get_connection()

conn.execute("""
    UPDATE events
    SET host = 'WORKSTATION-01'
    WHERE source = 'enterprise_sample.log'
      AND host = 'WORKSTATION'
""")

conn.commit()

rows = conn.execute("""
    SELECT original_ts, host, severity
    FROM events
    WHERE source = 'enterprise_sample.log'
    ORDER BY original_ts
""").fetchall()

print("UPDATED EVENTS:", len(rows))

for row in rows:
    print(dict(row))

conn.close()