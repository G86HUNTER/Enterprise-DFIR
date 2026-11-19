
from src.database import get_connection
from src.analysis.mitre_mapping import map_mitre_technique


def store_timeline_events(events, source_file):
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
                """,
                (
                    original_ts,
                    event["host"],
                    event["category"],
                    event["description"],
                    source_file
                )
            ).fetchone()

            if existing:
                # Update MITRE mapping for previously imported events.
                cur.execute(
                    """
                    UPDATE events
                    SET mitre = ?
                    WHERE id = ?
                    """,
                    (mitre, existing["id"])
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
                    evidence_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    None
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