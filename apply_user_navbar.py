from pathlib import Path
import re
import shutil

path = Path("src/app.py")
source = path.read_text(encoding="utf-8")

backup = Path("src/app.py.before_user_navbar.bak")

if backup.exists():
    raise SystemExit("Backup already exists. Stopping safely.")

pattern = re.compile(r'<body class="bg-light">')
count = len(pattern.findall(source))

if count != 4:
    raise SystemExit(f"Expected 4 page templates, found {count}.")

navbar = '''
    <body class="bg-light">

    <nav class="navbar navbar-expand-lg navbar-dark bg-dark shadow-sm">
        <div class="container-fluid px-4">
            <a class="navbar-brand fw-bold" href="{{ url_for('home') }}">
                Enterprise DFIR
            </a>

            <div class="d-flex align-items-center gap-3 flex-wrap">
                <a class="nav-link text-white"
                   href="{{ url_for('home') }}">Evidence</a>

                <a class="nav-link text-white"
                   href="{{ url_for('timeline') }}">Timeline</a>

                <a class="nav-link text-white"
                   href="{{ url_for('alerts') }}">Alerts</a>

                <a class="nav-link text-white"
                   href="{{ url_for('incidents') }}">Incidents</a>

                <span class="text-white-50">
                    Logged in as:
                    <strong class="text-white">
                        {{ session.get('username', 'User') }}
                    </strong>
                </span>

                <form method="POST"
                      action="{{ url_for('auth.logout') }}"
                      class="m-0">
                    <input type="hidden"
                           name="csrf_token"
                           value="{{ csrf_token() }}">
                    <button type="submit"
                            class="btn btn-outline-light btn-sm">
                        Logout
                    </button>
                </form>
            </div>
        </div>
    </nav>
'''

updated = pattern.sub(lambda match: navbar, source)

shutil.copy2(path, backup)
path.write_text(updated, encoding="utf-8")

print("User navigation added successfully.")
print("Updated page templates:", count)
print("Backup:", backup)
