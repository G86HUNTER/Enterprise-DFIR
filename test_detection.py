
from datetime import datetime
from src.database import get_connection
from src.analysis.detector import detect_suspicious_activity

conn = get_connection()

rows = conn.execute("""
    SELECT original_ts, host, severity, description
    FROM events
    WHERE source = 'enterprise_sample.log'
    ORDER BY original_ts
""").fetchall()

conn.close()

events = []

for row in rows:
    events.append({
        "timestamp": datetime.strptime(
            row["original_ts"], "%Y-%m-%d %H:%M:%S"
        ),
        "host": row["host"],
        "severity": row["severity"],
        "description": row["description"]
    })

alerts = detect_suspicious_activity(events)

print("TOTAL EVENTS ANALYZED:", len(events))
print("TOTAL ALERTS DETECTED:", len(alerts))
print("\nSUSPICIOUS ACTIVITY REPORT")

for index, alert in enumerate(alerts, start=1):
    print(f"\nAlert {index}")
    print("Rule:", alert["rule"])
    print("Severity:", alert["severity"])
    print("Host:", alert["host"])
    print("Details:", alert["details"])