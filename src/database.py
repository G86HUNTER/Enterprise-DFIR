
import sqlite3
from pathlib import Path

# Database file location
DB_PATH = Path(__file__).parent.parent / 'data' / 'dfir.db'


def get_connection():
    """Return a SQLite connection with dictionary-like row access."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create all required DFIR database tables without deleting existing data."""

    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = get_connection()
    cur = conn.cursor()

    cur.executescript(
        """
        -- Evidence table
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
            investigator_notes TEXT
        );

        -- Chain of custody
        CREATE TABLE IF NOT EXISTS evidence_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            notes TEXT,
            FOREIGN KEY(evidence_id)
                REFERENCES evidence(evidence_id)
        );

        -- Forensic timeline events
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
            FOREIGN KEY(evidence_id)
                REFERENCES evidence(id)
        );

        -- Incident investigation records
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
            updated_at TEXT NOT NULL
        );

        -- Investigation activity and findings
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

        -- Evidence linked to incidents
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

    conn.commit()
    conn.close()