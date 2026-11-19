from pathlib import Path
import shutil

path = Path("src/app.py")
source = path.read_text(encoding="utf-8")

old = '''            SELECT original_ts, host, severity, description
            FROM events
            ORDER BY original_ts ASC
            """
        ).fetchall()'''

new = '''            SELECT original_ts, host, severity, description
            FROM events
            WHERE user_id = ?
            ORDER BY original_ts ASC
            """,
            (session["user_id"],)
        ).fetchall()'''

if source.count(old) != 1:
    raise SystemExit("STOPPED: Expected exactly one matching SQL query.")

backup = path.with_name("app.py.before_alert_scope.bak")
if backup.exists():
    raise SystemExit(f"STOPPED: Backup already exists: {backup}")

shutil.copy2(path, backup)
path.write_text(source.replace(old, new, 1), encoding="utf-8")

print("Alert ownership patch applied.")
print(f"Backup created: {backup}")
