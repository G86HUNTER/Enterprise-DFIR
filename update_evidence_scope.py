from pathlib import Path
import shutil

path = Path("src/app.py")
source = path.read_text(encoding="utf-8")
updated = source

replacements = [
    # Store each user's files in a separate directory.
    (
        '''        file_path = UPLOAD_FOLDER / stored_filename''',
        '''        user_upload_folder = UPLOAD_FOLDER / str(session["user_id"])
        user_upload_folder.mkdir(parents=True, exist_ok=True)
        file_path = user_upload_folder / stored_filename'''
    ),

    # Assign ownership when inserting evidence.
    (
        '''                    INSERT INTO evidence (
                        evidence_id,
                        original_filename,
                        file_type,
                        file_path,
                        host,
                        size_bytes,
                        sha256,
                        collected_at,
                        investigator_notes
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        '''                    INSERT INTO evidence (
                        evidence_id,
                        user_id,
                        original_filename,
                        file_type,
                        file_path,
                        host,
                        size_bytes,
                        sha256,
                        collected_at,
                        investigator_notes
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'''
    ),

    # Add the logged-in user's ID to the insert values.
    (
        '''                    (
                        evidence_id,
                        original_filename,
                        extension.upper(),
                        str(file_path),
                        host or None,
                        file_size,
                        file_hash,
                        timestamp,
                        notes or None
                    )''',
        '''                    (
                        evidence_id,
                        session["user_id"],
                        original_filename,
                        extension.upper(),
                        str(file_path),
                        host or None,
                        file_size,
                        file_hash,
                        timestamp,
                        notes or None
                    )'''
    ),

    # Only list evidence owned by the logged-in user.
    (
        '''            SELECT *
            FROM evidence
            ORDER BY collected_at DESC''',
        '''            SELECT *
            FROM evidence
            WHERE user_id = ?
            ORDER BY collected_at DESC''',
    ),

    # Supply the user ID to the evidence listing query.
    (
        '''            """
        ).fetchall()

        evidence_records = []''',
        '''            """,
            (session["user_id"],)
        ).fetchall()

        evidence_records = []'''
    ),

    # Verify only evidence belonging to the logged-in user.
    (
        '''            SELECT *
            FROM evidence
            WHERE evidence_id = ?
            """,
            (evidence_id,)
        ).fetchone()''',
        '''            SELECT *
            FROM evidence
            WHERE evidence_id = ?
              AND user_id = ?
            """,
            (evidence_id, session["user_id"])
        ).fetchone()'''
    ),

    # Prevent a database file path from escaping the user's folder.
    (
        '''        file_path = Path(record["file_path"])

        if not file_path.exists():
            result = "FAILED - Evidence file missing"
        else:
            actual_hash = calculate_sha256(file_path)

            if actual_hash == record["sha256"]:
                result = "OK - SHA-256 hash matches"
            else:
                result = "FAILED - SHA-256 hash mismatch"''',
        '''        user_upload_folder = (
            UPLOAD_FOLDER / str(session["user_id"])
        ).resolve()
        file_path = Path(record["file_path"]).resolve()

        if user_upload_folder not in file_path.parents:
            result = "FAILED - Invalid evidence storage path"
        elif not file_path.is_file():
            result = "FAILED - Evidence file missing"
        else:
            actual_hash = calculate_sha256(file_path)

            if actual_hash == record["sha256"]:
                result = "OK - SHA-256 hash matches"
            else:
                result = "FAILED - SHA-256 hash mismatch"'''
    ),
]

for old, new in replacements:
    count = updated.count(old)
    if count != 1:
        raise SystemExit(
            f"PATCH STOPPED: Expected exactly 1 match, found {count} "
            f"for:\n{old[:160]}"
        )
    updated = updated.replace(old, new, 1)

backup = path.with_name("app.py.before_evidence_scope.bak")
if backup.exists():
    raise SystemExit(f"Backup already exists: {backup}")

shutil.copy2(path, backup)
path.write_text(updated, encoding="utf-8")

print("Evidence ownership patch applied.")
print(f"Backup created: {backup}")
