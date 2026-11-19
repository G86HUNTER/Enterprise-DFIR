# Enterprise-Scale Digital Forensics & Incident Response (DFIR)

A modular Python project that demonstrates evidence collection, hash verification, log analysis, timeline reconstruction, incident response workflow, and reporting for a simulated multi‑stage cyber‑attack across Windows, Linux, network, and cloud environments.

## Project layout
```
Enterprise-DFIR/
│   .gitignore
│   requirements.txt
│   README.md
│
├─src/
│   ├─app.py                # Flask entry point (home + health)
│   ├─database.py           # SQLite helper / minimal schema
│   ├─evidence/__init__.py
│   ├─hashing/__init__.py
│   ├─analysis/__init__.py
│   ├─timeline/__init__.py
│   ├─response/__init__.py
│   └─reporting/__init__.py
│
└─tests/
    └─test_app.py          # Basic Flask start‑up test
```

The project uses **Flask** for the backend and **SQLite** for storage. All code is compatible with Python 3.14.
