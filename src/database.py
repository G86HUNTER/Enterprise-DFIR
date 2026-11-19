import os
import sqlite3
from pathlib import Path

# Database file location
DB_PATH = Path(os.getenv('DB_PATH', Path(__file__).parent.parent / "data" / "dfir.db"))


def get_connection():
    """Return a SQLite connection with dictionary-like row access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def ensure_column(conn, table, column, definition):
    """Add a column only when it does not already exist."""
    existing_columns = {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }

    if column not in existing_columns:
        conn.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def init_db():
    """Create tables and safely migrate existing data."""

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = get_connection()

    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                is_active INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT UNIQUE NOT NULL,
                original_filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_path TEXT NOT NULL,
                host TEXT,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                investigator_notes TEXT,
                user_id INTEGER REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS evidence_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                evidence_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                notes TEXT,
                FOREIGN KEY(evidence_id)
                    REFERENCES evidence(evidence_id)
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                utc_ts TEXT,
                original_ts TEXT,
                host TEXT,
                source TEXT,
                category TEXT,
                severity TEXT,
                description TEXT,
                mitre TEXT,
                evidence_id INTEGER,
                user_id INTEGER REFERENCES users(id),
                FOREIGN KEY(evidence_id)
                    REFERENCES evidence(id)
            );

            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_ref TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                mitre TEXT,
                assigned_to TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                user_id INTEGER REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS incident_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_ref TEXT NOT NULL,
                update_type TEXT NOT NULL,
                notes TEXT NOT NULL,
                investigator TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY(incident_ref)
                    REFERENCES incidents(incident_ref)
            );

            CREATE TABLE IF NOT EXISTS incident_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_ref TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                linked_at TEXT NOT NULL,
                FOREIGN KEY(incident_ref)
                    REFERENCES incidents(incident_ref),
                FOREIGN KEY(evidence_id)
                    REFERENCES evidence(evidence_id),
                UNIQUE(incident_ref, evidence_id)
            );
            """
        )

        # Migrate databases created before user authentication.
        ensure_column(
            conn, "evidence", "user_id",
            "INTEGER REFERENCES users(id)"
        )
        ensure_column(
            conn, "events", "user_id",
            "INTEGER REFERENCES users(id)"
        )
        ensure_column(
            conn, "incidents", "user_id",
            "INTEGER REFERENCES users(id)"
        )

        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_evidence_user
                ON evidence(user_id);

            CREATE INDEX IF NOT EXISTS idx_events_user
                ON events(user_id);

            CREATE INDEX IF NOT EXISTS idx_incidents_user
                ON incidents(user_id);
            """
        )

        conn.commit()

    except Exception:
        conn.rollback()
        raise

    finally:
        conn.close()