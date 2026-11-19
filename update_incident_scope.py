from pathlib import Path
import shutil

path = Path("src/app.py")
source = path.read_text(encoding="utf-8")
updated = source

replacements = [
    # Security Alerts: create incident
    (
        '''            incident_ref = create_incident(
                title=title,''',
        '''            incident_ref = create_incident(
                user_id=session["user_id"],
                title=title,'''
    ),
    # Security Alerts: add investigation update
    (
        '''            add_investigation_update(
                incident_ref=incident_ref,''',
        '''            add_investigation_update(
                user_id=session["user_id"],
                incident_ref=incident_ref,'''
    ),
    # Incidents: create incident
    (
        '''                incident_ref = create_incident(
                    title=request.form.get("title", ""),''',
        '''                incident_ref = create_incident(
                    user_id=session["user_id"],
                    title=request.form.get("title", ""),'''
    ),
    # Incidents: update status
    (
        '''                if update_incident_status(incident_ref, status):''',
        '''                if update_incident_status(
                    session["user_id"], incident_ref, status
                ):'''
    ),
    # Incidents: record finding
    (
        '''                add_investigation_update(
                    incident_ref=request.form.get("incident_ref"),''',
        '''                add_investigation_update(
                    user_id=session["user_id"],
                    incident_ref=request.form.get("incident_ref"),'''
    ),
    # Incidents: link evidence
    (
        '''                link_evidence(
                    request.form.get("incident_ref"),
                    request.form.get("evidence_id")
                )''',
        '''                link_evidence(
                    session["user_id"],
                    request.form.get("incident_ref"),
                    request.form.get("evidence_id")
                )'''
    ),
    # Incidents: retrieve only this user's incidents
    (
        '''    all_incidents = get_incidents()''',
        '''    all_incidents = get_incidents(session["user_id"])'''
    ),
    # Incidents: retrieve only this user's evidence
    (
        '''            SELECT evidence_id, original_filename, host
            FROM evidence
            ORDER BY collected_at DESC
            """
        ).fetchall()''',
        '''            SELECT evidence_id, original_filename, host
            FROM evidence
            WHERE user_id = ?
            ORDER BY collected_at DESC
            """,
            (session["user_id"],)
        ).fetchall()'''
    ),
    # Incidents: retrieve updates for owned incident
    (
        '''            "updates": get_incident_updates(
                incident["incident_ref"]
            ),''',
        '''            "updates": get_incident_updates(
                session["user_id"], incident["incident_ref"]
            ),'''
    ),
    # Incidents: retrieve linked evidence for owned incident
    (
        '''            "evidence": get_incident_evidence(
                incident["incident_ref"]
            )''',
        '''            "evidence": get_incident_evidence(
                session["user_id"], incident["incident_ref"]
            )'''
    ),
]

for old, new in replacements:
    count = updated.count(old)
    if count != 1:
        raise SystemExit(
            f"PATCH STOPPED: Expected exactly 1 match, found {count} "
            f"for:\n{old[:120]}"
        )
    updated = updated.replace(old, new, 1)

backup = path.with_name("app.py.before_incident_scope.bak")
if backup.exists():
    raise SystemExit(f"Backup already exists: {backup}")

shutil.copy2(path, backup)
path.write_text(updated, encoding="utf-8")

print("Incident ownership patch applied.")
print(f"Backup created: {backup}")
