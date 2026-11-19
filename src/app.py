
import os
import uuid
import hashlib
import datetime

from pathlib import Path

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template_string,
    flash
)

from werkzeug.utils import secure_filename

from src.database import init_db, get_connection
from src.timeline.parser import parse_log_file
from src.timeline.store import store_timeline_events
from src.analysis.detector import detect_suspicious_activity

from src.investigation import (
    create_incident,
    get_incidents,
    update_incident_status,
    add_investigation_update,
    link_evidence,
    get_incident_updates,
    get_incident_evidence
)


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

app.secret_key = "replace-with-strong-secret"

BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_FOLDER = BASE_DIR / "uploads"

UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)

app.config["UPLOAD_FOLDER"] = str(UPLOAD_FOLDER)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

ALLOWED_EXTENSIONS = {
    "txt", "csv", "json", "evtx",
    "pcap", "pcapng", "log"
}

init_db()


def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(65536), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def current_timestamp():
    return (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


# --------------------------------------------------
# HOME AND HEALTH
# --------------------------------------------------

@app.route("/")
def home():
    return redirect(url_for("evidence"))


@app.route("/health")
def health():
    return {
        "status": "ok",
        "version": "1.0.0"
    }, 200


# --------------------------------------------------
# EVIDENCE MANAGEMENT
# --------------------------------------------------

@app.route("/evidence", methods=["GET", "POST"])
def evidence():

    if request.method == "POST":

        uploaded_file = request.files.get("file")

        if not uploaded_file or not uploaded_file.filename:
            flash("Please select a file.")
            return redirect(url_for("evidence"))

        original_filename = secure_filename(
            uploaded_file.filename
        )

        if not allowed_file(original_filename):
            flash("Unsupported file type.")
            return redirect(url_for("evidence"))

        extension = original_filename.rsplit(".", 1)[1].lower()

        evidence_id = str(uuid.uuid4())

        stored_filename = f"{evidence_id}.{extension}"

        file_path = UPLOAD_FOLDER / stored_filename

        try:
            uploaded_file.save(file_path)

            file_hash = calculate_sha256(file_path)
            file_size = file_path.stat().st_size

            host = request.form.get("host", "").strip()
            notes = request.form.get(
                "investigator_notes", ""
            ).strip()

            timestamp = current_timestamp()

            conn = get_connection()

            try:
                conn.execute(
                    """
                    INSERT INTO evidence (
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
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        original_filename,
                        extension.upper(),
                        str(file_path),
                        host or None,
                        file_size,
                        file_hash,
                        timestamp,
                        notes or None
                    )
                )

                conn.execute(
                    """
                    INSERT INTO evidence_events (
                        evidence_id,
                        event_type,
                        timestamp,
                        notes
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        evidence_id,
                        "Evidence Uploaded",
                        timestamp,
                        "Evidence uploaded and SHA-256 hash generated."
                    )
                )

                conn.commit()

            except Exception:
                conn.rollback()
                raise

            finally:
                conn.close()

            flash(
                f"Evidence uploaded successfully. "
                f"Evidence ID: {evidence_id}"
            )

        except Exception as error:

            if file_path.exists():
                file_path.unlink()

            flash(f"Evidence upload failed: {error}")

        return redirect(url_for("evidence"))

    conn = get_connection()

    try:
        records = conn.execute(
            """
            SELECT *
            FROM evidence
            ORDER BY collected_at DESC
            """
        ).fetchall()

        evidence_records = []

        for record in records:

            item = dict(record)

            stored_path = Path(item["file_path"])

            if not stored_path.exists():
                item["integrity"] = "Missing"
            else:
                current_hash = calculate_sha256(stored_path)

                item["integrity"] = (
                    "OK"
                    if current_hash == item["sha256"]
                    else "Modified"
                )

            evidence_records.append(item)

    finally:
        conn.close()

    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1">

        <title>Enterprise DFIR - Evidence</title>

        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
              rel="stylesheet">
    </head>

    <body class="bg-light">

    <div class="container py-5">

        <div class="d-flex justify-content-between flex-wrap mb-4">
            <div>
                <h1>Digital Evidence Management</h1>
                <p class="text-muted">
                    Evidence collection, integrity verification
                    and chain of custody
                </p>
            </div>

            <div>
                <a href="{{ url_for('timeline') }}"
                   class="btn btn-outline-primary">Timeline</a>

                <a href="{{ url_for('alerts') }}"
                   class="btn btn-outline-danger">Alerts</a>

                <a href="{{ url_for('incidents') }}"
                   class="btn btn-outline-dark">Incidents</a>
            </div>
        </div>

        {% with messages = get_flashed_messages() %}
            {% for message in messages %}
                <div class="alert alert-info">{{ message }}</div>
            {% endfor %}
        {% endwith %}

        <div class="card shadow-sm mb-4">
            <div class="card-body">

                <h4>Upload Evidence</h4>

                <form method="POST"
                      enctype="multipart/form-data">

                    <div class="mb-3">
                        <label class="form-label">Select Evidence File</label>
                        <input type="file"
                               name="file"
                               class="form-control"
                               required>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Host / Device</label>
                        <input type="text"
                               name="host"
                               class="form-control"
                               placeholder="Example: WORKSTATION-01">
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Investigator Notes</label>
                        <textarea name="investigator_notes"
                                  class="form-control"
                                  rows="2"></textarea>
                    </div>

                    <button class="btn btn-primary">
                        Upload Evidence
                    </button>

                </form>
            </div>
        </div>

        <div class="card shadow-sm">
            <div class="card-body">

                <h4 class="mb-3">Collected Evidence</h4>

                <div class="table-responsive">
                    <table class="table table-bordered table-hover">

                        <thead>
                            <tr>
                                <th>Filename</th>
                                <th>Evidence ID</th>
                                <th>Host</th>
                                <th>Size</th>
                                <th>SHA-256</th>
                                <th>Integrity</th>
                                <th>Action</th>
                            </tr>
                        </thead>

                        <tbody>

                        {% for item in evidence_records %}
                            <tr>
                                <td>{{ item.original_filename }}</td>
                                <td>
                                    <small>{{ item.evidence_id }}</small>
                                </td>
                                <td>{{ item.host or 'Unknown' }}</td>
                                <td>{{ item.size_bytes }} bytes</td>
                                <td>
                                    <small>{{ item.sha256 }}</small>
                                </td>
                                <td>
                                    {% if item.integrity == 'OK' %}
                                        <span class="badge bg-success">OK</span>
                                    {% else %}
                                        <span class="badge bg-danger">
                                            {{ item.integrity }}
                                        </span>
                                    {% endif %}
                                </td>
                                <td>
                                    <form method="POST"
                                          action="{{ url_for(
                                            'verify_evidence',
                                            evidence_id=item.evidence_id
                                          ) }}">
                                        <button class="btn btn-sm btn-outline-primary">
                                            Verify
                                        </button>
                                    </form>
                                </td>
                            </tr>
                        {% else %}
                            <tr>
                                <td colspan="7" class="text-center">
                                    No evidence uploaded yet.
                                </td>
                            </tr>
                        {% endfor %}

                        </tbody>
                    </table>
                </div>

            </div>
        </div>

    </div>
    </body>
    </html>
    """, evidence_records=evidence_records)


@app.route(
    "/evidence/<evidence_id>/verify",
    methods=["POST"]
)
def verify_evidence(evidence_id):

    conn = get_connection()

    try:
        record = conn.execute(
            """
            SELECT *
            FROM evidence
            WHERE evidence_id = ?
            """,
            (evidence_id,)
        ).fetchone()

        if not record:
            flash("Evidence record not found.")
            return redirect(url_for("evidence"))

        file_path = Path(record["file_path"])

        if not file_path.exists():
            result = "FAILED - Evidence file missing"
        else:
            actual_hash = calculate_sha256(file_path)

            if actual_hash == record["sha256"]:
                result = "OK - SHA-256 hash matches"
            else:
                result = "FAILED - SHA-256 hash mismatch"

        conn.execute(
            """
            INSERT INTO evidence_events (
                evidence_id,
                event_type,
                timestamp,
                notes
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                evidence_id,
                "Integrity Check",
                current_timestamp(),
                result
            )
        )

        conn.commit()

        flash(f"Integrity verification: {result}")

    finally:
        conn.close()

    return redirect(url_for("evidence"))


# --------------------------------------------------
# FORENSIC TIMELINE
# --------------------------------------------------

@app.route("/timeline", methods=["GET", "POST"])
def timeline():

    if request.method == "POST":

        uploaded_file = request.files.get("file")

        if not uploaded_file or not uploaded_file.filename:
            flash("Please select a log file.")
            return redirect(url_for("timeline"))

        original_filename = secure_filename(
            uploaded_file.filename
        )

        extension = (
            original_filename.rsplit(".", 1)[1].lower()
            if "." in original_filename else ""
        )

        if extension not in {"txt", "log"}:
            flash("Timeline processing currently supports TXT and LOG files.")
            return redirect(url_for("timeline"))

        stored_filename = (
            f"timeline_{uuid.uuid4().hex}_{original_filename}"
        )

        file_path = UPLOAD_FOLDER / stored_filename

        try:
            uploaded_file.save(file_path)

            parsed_events = parse_log_file(file_path)

            if not parsed_events:
                flash("No valid timestamped events were found in the log.")
            else:
                inserted = store_timeline_events(
                    parsed_events,
                    str(file_path)
                )

                flash(
                    f"Log processed. Parsed {len(parsed_events)} events; "
                    f"inserted {inserted} new timeline events."
                )

        except Exception as error:
            flash(f"Timeline processing failed: {error}")

        return redirect(url_for("timeline"))

    conn = get_connection()

    try:
        rows = conn.execute(
            """
            SELECT *
            FROM events
            ORDER BY original_ts DESC
            """
        ).fetchall()

    finally:
        conn.close()

    timeline_events = [dict(row) for row in rows]

    stats = {
        "total": len(timeline_events),
        "high": sum(
            event["severity"] == "HIGH"
            for event in timeline_events
        ),
        "medium": sum(
            event["severity"] == "MEDIUM"
            for event in timeline_events
        )
    }

    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1">

        <title>DFIR - Forensic Timeline</title>

        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
              rel="stylesheet">
    </head>

    <body class="bg-light">

    <div class="container py-5">

        <div class="d-flex justify-content-between flex-wrap mb-4">
            <div>
                <h1>Forensic Timeline</h1>
                <p class="text-muted">
                    Chronological analysis of collected log events
                </p>
            </div>

            <div>
                <a href="{{ url_for('evidence') }}"
                   class="btn btn-outline-secondary">Evidence</a>

                <a href="{{ url_for('alerts') }}"
                   class="btn btn-outline-danger">Alerts</a>

                <a href="{{ url_for('incidents') }}"
                   class="btn btn-outline-dark">Incidents</a>
            </div>
        </div>

        {% with messages = get_flashed_messages() %}
            {% for message in messages %}
                <div class="alert alert-info">{{ message }}</div>
            {% endfor %}
        {% endwith %}

        <div class="card shadow-sm mb-4">
            <div class="card-body">

                <h4>Import Log File</h4>

                <form method="POST"
                      enctype="multipart/form-data">

                    <input type="file"
                           name="file"
                           class="form-control mb-3"
                           accept=".txt,.log"
                           required>

                    <button class="btn btn-primary">
                        Process Log
                    </button>

                </form>

            </div>
        </div>

        <div class="row g-3 mb-4">

            <div class="col-md-4">
                <div class="card p-3">
                    <h6>Total Events</h6>
                    <h2>{{ stats.total }}</h2>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card p-3">
                    <h6>High Severity</h6>
                    <h2 class="text-danger">{{ stats.high }}</h2>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card p-3">
                    <h6>Medium Severity</h6>
                    <h2 class="text-warning">{{ stats.medium }}</h2>
                </div>
            </div>

        </div>

        <div class="card shadow-sm">
            <div class="card-body">

                <h4 class="mb-3">Timeline Events</h4>

                <div class="table-responsive">
                    <table class="table table-bordered table-hover">

                        <thead>
                            <tr>
                                <th>Timestamp</th>
                                <th>Host</th>
                                <th>Category</th>
                                <th>Severity</th>
                                <th>Description</th>
                                <th>MITRE ATT&CK</th>
                            </tr>
                        </thead>

                        <tbody>

                        {% for event in timeline_events %}
                            <tr>
                                <td>{{ event.original_ts }}</td>
                                <td>{{ event.host or 'Unknown' }}</td>
                                <td>{{ event.category }}</td>
                                <td>{{ event.severity }}</td>
                                <td>{{ event.description }}</td>
                                <td>{{ event.mitre or 'Not mapped' }}</td>
                            </tr>
                        {% else %}
                            <tr>
                                <td colspan="6" class="text-center">
                                    No timeline events available.
                                </td>
                            </tr>
                        {% endfor %}

                        </tbody>
                    </table>
                </div>

            </div>
        </div>

    </div>
    </body>
    </html>
    """, timeline_events=timeline_events, stats=stats)


# --------------------------------------------------
# SECURITY ALERTS
# --------------------------------------------------

@app.route("/alerts", methods=["GET", "POST"])
def alerts():

    if request.method == "POST":

        try:
            title = request.form.get("title", "").strip()
            details = request.form.get("details", "").strip()
            host = request.form.get("host", "Unknown")
            alert_severity = request.form.get("severity", "MEDIUM")

            if not title or not details:
                raise ValueError("Alert information is incomplete.")

            severity_mapping = {
                "HIGH": "High",
                "MEDIUM": "Medium"
            }

            incident_severity = severity_mapping.get(
                alert_severity.upper(),
                "Medium"
            )

            incident_ref = create_incident(
                title=title,
                description=(
                    "Automatically converted from a detected security alert.\n"
                    f"Host: {host}\n"
                    f"Details: {details}"
                ),
                severity=incident_severity,
                assigned_to=None
            )

            add_investigation_update(
                incident_ref=incident_ref,
                notes=(
                    "Incident created from Security Alerts.\n"
                    f"Detection rule: {title}\n"
                    f"Host: {host}\n"
                    f"Alert details: {details}"
                ),
                investigator="DFIR Detection System",
                update_type="Alert Detection"
            )

            flash(
                f"Incident created successfully: {incident_ref}"
            )

        except Exception as error:
            flash(f"Incident creation failed: {error}")

        return redirect(url_for("alerts"))

    conn = get_connection()

    try:
        rows = conn.execute(
            """
            SELECT original_ts, host, severity, description
            FROM events
            ORDER BY original_ts ASC
            """
        ).fetchall()

    finally:
        conn.close()

    events = []

    for row in rows:
        try:
            events.append({
                "timestamp": datetime.datetime.strptime(
                    row["original_ts"],
                    "%Y-%m-%d %H:%M:%S"
                ),
                "host": row["host"],
                "severity": row["severity"],
                "description": row["description"]
            })

        except (ValueError, TypeError):
            continue

    detected_alerts = detect_suspicious_activity(events)

    stats = {
        "total": len(detected_alerts),
        "high": sum(
            alert["severity"] == "HIGH"
            for alert in detected_alerts
        ),
        "medium": sum(
            alert["severity"] == "MEDIUM"
            for alert in detected_alerts
        )
    }

    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1">

        <title>DFIR - Security Alerts</title>

        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
              rel="stylesheet">
    </head>

    <body class="bg-light">

    <div class="container py-5">

        <div class="d-flex justify-content-between align-items-center mb-4">

            <div>
                <h1>Security Alerts</h1>
                <p class="text-muted">
                    Suspicious activity detection report
                </p>
            </div>

            <div>
                <a href="{{ url_for('timeline') }}"
                   class="btn btn-outline-primary">Incident Timeline</a>

                <a href="{{ url_for('incidents') }}"
                   class="btn btn-outline-danger">Investigation Cases</a>

                <a href="{{ url_for('evidence') }}"
                   class="btn btn-outline-secondary">Evidence</a>
            </div>

        </div>

        {% with messages = get_flashed_messages() %}
            {% for message in messages %}
                <div class="alert alert-info">{{ message }}</div>
            {% endfor %}
        {% endwith %}

        <div class="row g-3 mb-4">

            <div class="col-md-4">
                <div class="card p-3">
                    <h6>Total Alerts</h6>
                    <h2>{{ stats.total }}</h2>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card p-3">
                    <h6>High Severity</h6>
                    <h2 class="text-danger">{{ stats.high }}</h2>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card p-3">
                    <h6>Medium Severity</h6>
                    <h2 class="text-warning">{{ stats.medium }}</h2>
                </div>
            </div>

        </div>

        <div class="card shadow-sm">
            <div class="card-body">

                <h4 class="mb-3">
                    Detected Suspicious Activities
                </h4>

                {% for alert in detected_alerts %}

                    <div class="border rounded p-3 mb-3 bg-white">

                        <div class="d-flex justify-content-between">
                            <h5>{{ alert.rule }}</h5>

                            {% if alert.severity == 'HIGH' %}
                                <span class="badge bg-danger">HIGH</span>
                            {% else %}
                                <span class="badge bg-warning text-dark">
                                    MEDIUM
                                </span>
                            {% endif %}
                        </div>

                        <p class="mb-1">
                            <strong>Host:</strong>
                            {{ alert.host or 'Unknown' }}
                        </p>

                        <p class="mb-3">
                            <strong>Details:</strong>
                            {{ alert.details }}
                        </p>

                        <form method="POST">

                            <input type="hidden"
                                   name="title"
                                   value="{{ alert.rule }}">

                            <input type="hidden"
                                   name="details"
                                   value="{{ alert.details }}">

                            <input type="hidden"
                                   name="host"
                                   value="{{ alert.host or 'Unknown' }}">

                            <input type="hidden"
                                   name="severity"
                                   value="{{ alert.severity }}">

                            <button type="submit"
                                    class="btn btn-primary btn-sm">
                                Create Investigation Incident
                            </button>

                        </form>

                    </div>

                {% else %}

                    <p class="text-muted">
                        No suspicious activity detected.
                    </p>

                {% endfor %}

            </div>
        </div>

    </div>
    </body>
    </html>
    """, detected_alerts=detected_alerts, stats=stats)


# --------------------------------------------------
# INCIDENT INVESTIGATION MANAGEMENT
# --------------------------------------------------

@app.route("/incidents", methods=["GET", "POST"])
def incidents():

    if request.method == "POST":

        action = request.form.get("action")

        try:

            if action == "create":

                incident_ref = create_incident(
                    title=request.form.get("title", ""),
                    description=request.form.get("description", ""),
                    severity=request.form.get("severity", "Medium"),
                    mitre=request.form.get("mitre") or None,
                    assigned_to=request.form.get("assigned_to") or None
                )

                flash(
                    f"Incident created successfully: {incident_ref}"
                )

            elif action == "status":

                incident_ref = request.form.get("incident_ref")
                status = request.form.get("status")

                if update_incident_status(incident_ref, status):
                    flash("Incident status updated successfully.")
                else:
                    flash("Incident not found.")

            elif action == "finding":

                add_investigation_update(
                    incident_ref=request.form.get("incident_ref"),
                    notes=request.form.get("notes", ""),
                    investigator=request.form.get("investigator") or None,
                    update_type="Finding"
                )

                flash("Investigation finding recorded.")

            elif action == "link_evidence":

                link_evidence(
                    request.form.get("incident_ref"),
                    request.form.get("evidence_id")
                )

                flash("Evidence linked successfully.")

        except Exception as error:
            flash(f"Operation failed: {error}")

        return redirect(url_for("incidents"))

    all_incidents = get_incidents()

    conn = get_connection()

    try:
        evidence_records = conn.execute(
            """
            SELECT evidence_id, original_filename, host
            FROM evidence
            ORDER BY collected_at DESC
            """
        ).fetchall()

    finally:
        conn.close()

    incident_details = []

    for incident in all_incidents:

        incident_details.append({
            "incident": incident,
            "updates": get_incident_updates(
                incident["incident_ref"]
            ),
            "evidence": get_incident_evidence(
                incident["incident_ref"]
            )
        })

    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport"
              content="width=device-width, initial-scale=1">

        <title>DFIR - Incident Investigation</title>

        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
              rel="stylesheet">
    </head>

    <body class="bg-light">

    <div class="container py-5">

        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                <h1>Incident Investigation</h1>
                <p class="text-muted">
                    Incident tracking and forensic investigation management
                </p>
            </div>

            <div>
                <a href="{{ url_for('timeline') }}"
                   class="btn btn-outline-primary">Timeline</a>

                <a href="{{ url_for('alerts') }}"
                   class="btn btn-outline-danger">Alerts</a>

                <a href="{{ url_for('evidence') }}"
                   class="btn btn-outline-secondary">Evidence</a>
            </div>
        </div>

        {% with messages = get_flashed_messages() %}
            {% for message in messages %}
                <div class="alert alert-info">{{ message }}</div>
            {% endfor %}
        {% endwith %}

        <div class="card shadow-sm mb-4">
            <div class="card-body">

                <h4 class="mb-3">Create New Incident</h4>

                <form method="post">

                    <input type="hidden" name="action" value="create">

                    <div class="mb-3">
                        <label class="form-label">Incident Title</label>
                        <input type="text"
                               name="title"
                               class="form-control"
                               required>
                    </div>

                    <div class="mb-3">
                        <label class="form-label">Description</label>
                        <textarea name="description"
                                  class="form-control"
                                  rows="3"></textarea>
                    </div>

                    <div class="row">

                        <div class="col-md-4 mb-3">
                            <label class="form-label">Severity</label>
                            <select name="severity" class="form-select">
                                <option>Low</option>
                                <option selected>Medium</option>
                                <option>High</option>
                                <option>Critical</option>
                            </select>
                        </div>

                        <div class="col-md-4 mb-3">
                            <label class="form-label">MITRE ATT&CK</label>
                            <input type="text"
                                   name="mitre"
                                   class="form-control"
                                   placeholder="Example: T1059.001">
                        </div>

                        <div class="col-md-4 mb-3">
                            <label class="form-label">Assigned Investigator</label>
                            <input type="text"
                                   name="assigned_to"
                                   class="form-control">
                        </div>

                    </div>

                    <button type="submit" class="btn btn-primary">
                        Create Incident
                    </button>

                </form>
            </div>
        </div>

        <h3 class="mb-3">Investigation Records</h3>

        {% for item in incident_details %}

            {% set incident = item.incident %}

            <div class="card shadow-sm mb-4">
                <div class="card-body">

                    <div class="d-flex justify-content-between flex-wrap">

                        <div>
                            <h4>{{ incident.title }}</h4>

                            <p class="text-muted mb-1">
                                Reference: {{ incident.incident_ref }}
                            </p>
                        </div>

                        <div>
                            <span class="badge bg-danger">
                                {{ incident.severity }}
                            </span>

                            <span class="badge bg-primary">
                                {{ incident.status }}
                            </span>
                        </div>

                    </div>

                    <hr>

                    <p>{{ incident.description or 'No description provided.' }}</p>

                    <p>
                        <strong>MITRE:</strong>
                        {{ incident.mitre or 'Not mapped' }}
                    </p>

                    <p>
                        <strong>Assigned to:</strong>
                        {{ incident.assigned_to or 'Unassigned' }}
                    </p>

                    <p class="text-muted">
                        Created: {{ incident.created_at }}
                    </p>

                    <hr>

                    <h5>Update Incident Status</h5>

                    <form method="post" class="row g-2 mb-4">

                        <input type="hidden" name="action" value="status">
                        <input type="hidden"
                               name="incident_ref"
                               value="{{ incident.incident_ref }}">

                        <div class="col-md-4">
                            <select name="status" class="form-select">
                                <option {% if incident.status == 'Open' %}selected{% endif %}>Open</option>
                                <option {% if incident.status == 'Investigating' %}selected{% endif %}>Investigating</option>
                                <option {% if incident.status == 'Resolved' %}selected{% endif %}>Resolved</option>
                                <option {% if incident.status == 'Closed' %}selected{% endif %}>Closed</option>
                            </select>
                        </div>

                        <div class="col-md-3">
                            <button class="btn btn-outline-primary">
                                Update Status
                            </button>
                        </div>

                    </form>

                    <h5>Add Investigation Finding</h5>

                    <form method="post" class="mb-4">

                        <input type="hidden" name="action" value="finding">
                        <input type="hidden"
                               name="incident_ref"
                               value="{{ incident.incident_ref }}">

                        <div class="mb-2">
                            <textarea name="notes"
                                      class="form-control"
                                      rows="2"
                                      placeholder="Enter investigation findings..."
                                      required></textarea>
                        </div>

                        <div class="mb-2">
                            <input type="text"
                                   name="investigator"
                                   class="form-control"
                                   placeholder="Investigator name">
                        </div>

                        <button class="btn btn-outline-success">
                            Save Finding
                        </button>

                    </form>

                    <h5>Link Existing Evidence</h5>

                    <form method="post" class="row g-2 mb-4">

                        <input type="hidden"
                               name="action"
                               value="link_evidence">

                        <input type="hidden"
                               name="incident_ref"
                               value="{{ incident.incident_ref }}">

                        <div class="col-md-7">

                            <select name="evidence_id"
                                    class="form-select"
                                    required>

                                {% for ev in evidence_records %}
                                    <option value="{{ ev.evidence_id }}">
                                        {{ ev.original_filename }}
                                        ({{ ev.evidence_id[:8] }})
                                    </option>
                                {% endfor %}

                            </select>

                        </div>

                        <div class="col-md-3">
                            <button class="btn btn-outline-primary"
                                    {% if not evidence_records %}disabled{% endif %}>
                                Link Evidence
                            </button>
                        </div>

                    </form>

                    <h5>Investigation History</h5>

                    {% for update in item.updates %}
                        <div class="border rounded p-3 mb-2 bg-light">

                            <strong>{{ update.update_type }}</strong>

                            <p class="mb-1">{{ update.notes }}</p>

                            <small class="text-muted">
                                {{ update.investigator or 'Unknown investigator' }}
                                | {{ update.timestamp }}
                            </small>

                        </div>
                    {% else %}
                        <p class="text-muted">No findings recorded yet.</p>
                    {% endfor %}

                    <h5 class="mt-3">Linked Evidence</h5>

                    {% for ev in item.evidence %}
                        <div class="border rounded p-2 mb-2">
                            {{ ev.original_filename }}
                            <small class="text-muted">
                                | {{ ev.evidence_id[:8] }}
                            </small>
                        </div>
                    {% else %}
                        <p class="text-muted">No evidence linked.</p>
                    {% endfor %}

                </div>
            </div>

        {% else %}

            <div class="alert alert-secondary">
                No incidents have been created yet.
            </div>

        {% endfor %}

    </div>
    </body>
    </html>
    """,
    incident_details=incident_details,
    evidence_records=evidence_records)


# --------------------------------------------------
# APPLICATION ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )