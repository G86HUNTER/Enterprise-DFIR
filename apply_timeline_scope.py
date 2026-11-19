from pathlib import Path
import shutil

app_path = Path("src/app.py")
store_path = Path("src/timeline/store.py")

app = app_path.read_text(encoding="utf-8")
store = store_path.read_text(encoding="utf-8")

updated_app = app

replacements = [
(
'''        file_path = UPLOAD_FOLDER / stored_filename

        try:
            uploaded_file.save(file_path)

            parsed_events = parse_log_file(file_path)''',
'''        user_upload_folder = UPLOAD_FOLDER / str(session["user_id"])
        user_upload_folder.mkdir(parents=True, exist_ok=True)
        file_path = user_upload_folder / stored_filename

        try:
            uploaded_file.save(file_path)

            parsed_events = parse_log_file(file_path)'''
),
(
'''                inserted = store_timeline_events(
                    parsed_events,
                    str(file_path)
                )''',
'''                inserted = store_timeline_events(
                    session["user_id"],
                    parsed_events,
                    str(file_path)
                )'''
),
(
'''            SELECT *
            FROM events
            ORDER BY original_ts DESC
            """
        ).fetchall()''',
'''            SELECT *
            FROM events
            WHERE user_id = ?
            ORDER BY original_ts DESC
            """,
            (session["user_id"],)
        ).fetchall()'''
)
]

for old, new in replacements:
    count = updated_app.count(old)
    if count != 1:
        raise SystemExit(
            f"STOPPED: Expected 1 app.py match, found {count}.\n"
            f"Section: {old[:200]}"
        )
    updated_app = updated_app.replace(old, new, 1)

new_store = '''from src.database import get_connection
from src.analysis.mitre_mapping import map_mitre_technique


def store_timeline_events(user_id, events, source_file):
    if not user_id:
        raise ValueError("A valid user_id is required.")

    conn = get_connection()
    cur = conn.cursor()

    inserted = 0

    try:
        for event in events:
            original_ts = event["timestamp"].strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            mitre = map_mitre_technique(event["description"])

            existing = cur.execute(
                """
                SELECT id FROM events
                WHERE original_ts = ?
                  AND host IS ?
                  AND category = ?
                  AND description = ?
                  AND source = ?
                  AND evidence_id IS NULL
                  AND user_id = ?
                """,
                (
                    original_ts,
                    event["host"],
                    event["category"],
                    event["description"],
                    source_file,
                    user_id
                )
            ).fetchone()

            if existing:
                cur.execute(
                    """
                    UPDATE events
                    SET mitre = ?
                    WHERE id = ?
                      AND user_id = ?
                    """,
                    (mitre, existing["id"], user_id)
                )
                continue

            cur.execute(
                """
                INSERT INTO events (
                    utc_ts,
                    original_ts,
                    host,
                    source,
                    category,
                    severity,
                    description,
                    mitre,
                    evidence_id,
                    user_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    None,
                    original_ts,
                    event["host"],
                    source_file,
                    event["category"],
                    event["severity"],
                    event["description"],
                    mitre,
                    None,
                    user_id
                )
            )

            inserted += 1

        conn.commit()
        return inserted

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()
'''

app_backup = app_path.with_name("app.py.before_timeline_scope.bak")
store_backup = store_path.with_name("store.py.before_user_scope.bak")

if app_backup.exists() or store_backup.exists():
    raise SystemExit("STOPPED: A timeline backup already exists.")

shutil.copy2(app_path, app_backup)
shutil.copy2(store_path, store_backup)

app_path.write_text(updated_app, encoding="utf-8")
store_path.write_text(new_store, encoding="utf-8")

print("Timeline ownership patch applied successfully.")
print(f"App backup: {app_backup}")
print(f"Store backup: {store_backup}")
