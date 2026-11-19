from src.database import get_connection
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
