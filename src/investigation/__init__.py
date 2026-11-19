
import uuid
from datetime import datetime, timezone

from src.database import get_connection


VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
VALID_STATUSES = {"Open", "Investigating", "Resolved", "Closed"}


def current_timestamp():
    return datetime.now(timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def validate_user_id(user_id):
    if user_id is None:
        raise ValueError("Authenticated user ID is required.")


def create_incident(
    user_id,
    title,
    description="",
    severity="Medium",
    mitre=None,
    assigned_to=None
):
    validate_user_id(user_id)

    if not title or not title.strip():
        raise ValueError("Incident title is required.")

    if severity not in VALID_SEVERITIES:
        raise ValueError("Invalid incident severity.")

    incident_ref = "INC-" + uuid.uuid4().hex[:8].upper()
    timestamp = current_timestamp()

    conn = get_connection()

    try:
        conn.execute(
            """
            INSERT INTO incidents (
                incident_ref, title, description, severity,
                status, mitre, assigned_to, created_at,
                updated_at, user_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_ref, title.strip(), description,
                severity, "Open", mitre, assigned_to,
                timestamp, timestamp, user_id
            )
        )

        conn.commit()
        return incident_ref

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_incidents(user_id):
    validate_user_id(user_id)

    conn = get_connection()

    try:
        rows = conn.execute(
            """
            SELECT * FROM incidents
            WHERE user_id = ?
            ORDER BY created_at DESC
            """,
            (user_id,)
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def update_incident_status(user_id, incident_ref, status):
    validate_user_id(user_id)

    if status not in VALID_STATUSES:
        raise ValueError("Invalid incident status.")

    conn = get_connection()

    try:
        incident = conn.execute(
            """
            SELECT status FROM incidents
            WHERE incident_ref = ? AND user_id = ?
            """,
            (incident_ref, user_id)
        ).fetchone()

        if not incident:
            return False

        old_status = incident["status"]

        if old_status == status:
            return True

        timestamp = current_timestamp()

        conn.execute(
            """
            UPDATE incidents
            SET status = ?, updated_at = ?
            WHERE incident_ref = ? AND user_id = ?
            """,
            (status, timestamp, incident_ref, user_id)
        )

        conn.execute(
            """
            INSERT INTO incident_updates (
                incident_ref, update_type, notes,
                investigator, timestamp
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                incident_ref,
                "Status Change",
                f"Incident status changed from {old_status} to {status}.",
                "System",
                timestamp
            )
        )

        conn.commit()
        return True

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def add_investigation_update(
    user_id,
    incident_ref,
    notes,
    investigator=None,
    update_type="Finding"
):
    validate_user_id(user_id)

    if not notes or not notes.strip():
        raise ValueError("Investigation notes are required.")

    conn = get_connection()

    try:
        incident = conn.execute(
            """
            SELECT id FROM incidents
            WHERE incident_ref = ? AND user_id = ?
            """,
            (incident_ref, user_id)
        ).fetchone()

        if not incident:
            raise ValueError("Incident not found.")

        timestamp = current_timestamp()

        conn.execute(
            """
            INSERT INTO incident_updates (
                incident_ref, update_type, notes,
                investigator, timestamp
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                incident_ref, update_type, notes.strip(),
                investigator, timestamp
            )
        )

        conn.execute(
            """
            UPDATE incidents
            SET updated_at = ?
            WHERE incident_ref = ? AND user_id = ?
            """,
            (timestamp, incident_ref, user_id)
        )

        conn.commit()
        return True

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def link_evidence(user_id, incident_ref, evidence_id):
    validate_user_id(user_id)

    conn = get_connection()

    try:
        incident = conn.execute(
            """
            SELECT id FROM incidents
            WHERE incident_ref = ? AND user_id = ?
            """,
            (incident_ref, user_id)
        ).fetchone()

        evidence = conn.execute(
            """
            SELECT id FROM evidence
            WHERE evidence_id = ? AND user_id = ?
            """,
            (evidence_id, user_id)
        ).fetchone()

        if not incident:
            raise ValueError("Incident not found.")

        if not evidence:
            raise ValueError("Evidence not found.")

        conn.execute(
            """
            INSERT INTO incident_evidence (
                incident_ref, evidence_id, linked_at
            )
            VALUES (?, ?, ?)
            """,
            (incident_ref, evidence_id, current_timestamp())
        )

        conn.commit()
        return True

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()


def get_incident_updates(user_id, incident_ref):
    validate_user_id(user_id)

    conn = get_connection()

    try:
        rows = conn.execute(
            """
            SELECT iu.*
            FROM incident_updates iu
            JOIN incidents i
                ON i.incident_ref = iu.incident_ref
            WHERE iu.incident_ref = ? AND i.user_id = ?
            ORDER BY iu.timestamp DESC
            """,
            (incident_ref, user_id)
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_incident_evidence(user_id, incident_ref):
    validate_user_id(user_id)

    conn = get_connection()

    try:
        rows = conn.execute(
            """
            SELECT e.*
            FROM evidence e
            JOIN incident_evidence ie
                ON e.evidence_id = ie.evidence_id
            JOIN incidents i
                ON i.incident_ref = ie.incident_ref
            WHERE ie.incident_ref = ?
              AND i.user_id = ?
              AND e.user_id = ?
            ORDER BY ie.linked_at DESC
            """,
            (incident_ref, user_id, user_id)
        ).fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()
