# Enterprise DFIR – Digital Forensics & Incident Response Platform

A Flask-based Digital Forensics and Incident Response (DFIR) platform designed to support structured cybersecurity investigations, digital evidence management, forensic integrity verification, security event analysis, timeline reconstruction, and incident response workflows.

**Repository:** [Enterprise-DFIR](https://github.com/G86HUNTER/Enterprise-DFIR)

**Live Demo:** Deployment pending — the public Render URL will be added after successful deployment.

---

## Overview

Enterprise DFIR is a web-based investigation platform built to demonstrate how security teams can collect, preserve, examine, and manage digital forensic evidence during cybersecurity incidents.

The application provides authenticated user access, evidence management, SHA-256 integrity verification, chain-of-custody tracking, timeline analysis, security alerts, and incident investigation capabilities.

The project also aims to support a controlled, harmless Advanced Persistent Threat (APT) incident simulation using synthetic enterprise security events, followed by a structured forensic investigation and final report.

## Key Features

- **User Authentication:** Registration, login, logout, and session management.
- **Evidence Management:** Upload and organize digital forensic evidence.
- **Evidence Integrity:** SHA-256 hashing to verify evidence integrity.
- **Chain of Custody:** Maintain evidence handling and tracking records.
- **Timeline Reconstruction:** Organize security events chronologically.
- **Security Alerts:** Generate alerts from configured detection rules.
- **Incident Management:** Create and manage incident investigation records.
- **Investigation Dashboard:** View investigation activity and related records.
- **User Data Isolation:** Restrict investigation records and evidence to their respective authenticated users.

## Simulated APT Investigation

The planned controlled APT simulation uses synthetic enterprise security events rather than real malware or destructive activity.

The investigation and reporting scope includes:

1. Simulated multi-stage attack scenario.
2. Synthetic enterprise event generation and ingestion.
3. Evidence collection and integrity verification.
4. Chronological attack timeline reconstruction.
5. MITRE ATT&CK technique mapping where supported by the evidence.
6. Incident findings and response recommendations.
7. Attribution limitations and forensic conclusions.

The simulation and final forensic report should be clearly identified as controlled, educational exercises rather than real-world incident attribution.

## Technology Stack

| Component | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML, CSS, Bootstrap, Jinja2 |
| Database | SQLite |
| ORM / Database Layer | SQLAlchemy and SQLite helpers |
| Authentication | Flask sessions, Werkzeug security |
| Evidence Integrity | SHA-256 |
| Deployment | Render |
| Production Server | Gunicorn |
| Version Control | Git and GitHub |

## Project Structure

```text
Enterprise-DFIR/
│
├── src/
│   ├── app.py
│   ├── auth.py
│   ├── database.py
│   ├── investigation/
│   ├── timeline/
│   └── ...
│
├── tests/
├── test_evidence/
├── requirements.txt
├── render.yaml
├── .gitignore
└── README.md
```

## Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/G86HUNTER/Enterprise-DFIR.git
cd Enterprise-DFIR
```

### 2. Create a virtual environment

```bash
py -m venv .venv
```

### 3. Activate the environment (Windows PowerShell)

```powershell
.\.venv\Scripts\Activate.ps1
```

### 4. Install dependencies

```bash
pip install -r requirements.txt
```

### 5. Configure environment variables

For local development, configure a suitable development secret key if needed. Never use a development secret in production.

### 6. Start the application

```bash
py src/app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Deployment

The project includes a `render.yaml` configuration for deployment on Render.

The deployment configuration uses:

- Gunicorn as the production WSGI server.
- Environment variables for production configuration.
- A generated production secret key.
- Persistent storage for the SQLite database and uploaded evidence.

After successful deployment, the public Render URL will be added here:

**Live Application:** Coming soon.

## Security Considerations

- Password hashing and authenticated sessions.
- CSRF protection.
- HTTP-only session cookies.
- Secure session cookie configuration in production.
- File upload size restrictions.
- User-specific investigation and evidence access.
- Persistent storage for application data.

This project is an educational and demonstration platform. It should undergo additional security testing and hardening before being used to handle real organizational or sensitive forensic evidence.

## Testing

The repository includes test-related files and sample verification utilities. Run the applicable tests from the project root after installing dependencies.

```bash
pytest
```

## Future Enhancements

- Complete synthetic APT attack simulation.
- Comprehensive MITRE ATT&CK mapping.
- Final downloadable forensic investigation report.
- Advanced log correlation and detection capabilities.
- Additional forensic artifact parsers.
- Enhanced dashboards and investigation analytics.
- Expanded automated security testing.

## Project Information

**Project:** Enterprise DFIR – Digital Forensics & Incident Response

**Developer:** Aryan Gaikwad

**GitHub:** [G86HUNTER](https://github.com/G86HUNTER)

**Repository:** https://github.com/G86HUNTER/Enterprise-DFIR

---

*Built as a cybersecurity and digital forensics project to explore evidence preservation, incident investigation, security event analysis, and structured digital forensic workflows.*
