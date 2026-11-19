from pathlib import Path
import shutil

path = Path("src/app.py")
source = path.read_text(encoding="utf-8")

backup = Path("src/app.py.before_remove_duplicate_nav_v2.bak")

if backup.exists():
    raise SystemExit("Backup already exists. Stopping safely.")

blocks = [
'''            <div>
                <a href="{{ url_for('timeline') }}"
                   class="btn btn-outline-primary">Timeline</a>

                <a href="{{ url_for('alerts') }}"
                   class="btn btn-outline-danger">Alerts</a>

                <a href="{{ url_for('incidents') }}"
                   class="btn btn-outline-dark">Incidents</a>
            </div>
''',
'''            <div>
                <a href="{{ url_for('evidence') }}"
                   class="btn btn-outline-secondary">Evidence</a>

                <a href="{{ url_for('alerts') }}"
                   class="btn btn-outline-danger">Alerts</a>

                <a href="{{ url_for('incidents') }}"
                   class="btn btn-outline-dark">Incidents</a>
            </div>
''',
'''            <div>
                <a href="{{ url_for('timeline') }}"
                   class="btn btn-outline-primary">Incident Timeline</a>

                <a href="{{ url_for('incidents') }}"
                   class="btn btn-outline-danger">Investigation Cases</a>

                <a href="{{ url_for('evidence') }}"
                   class="btn btn-outline-secondary">Evidence</a>
            </div>
''',
'''            <div>
                <a href="{{ url_for('timeline') }}"
                   class="btn btn-outline-primary">Timeline</a>

                <a href="{{ url_for('alerts') }}"
                   class="btn btn-outline-danger">Alerts</a>

                <a href="{{ url_for('evidence') }}"
                   class="btn btn-outline-secondary">Evidence</a>
            </div>
'''
]

for index, block in enumerate(blocks, start=1):
    count = source.count(block)
    if count != 1:
        raise SystemExit(
            f"Expected exactly one match for block {index}, found {count}. "
            "No changes made."
        )

updated = source
for block in blocks:
    updated = updated.replace(block, "", 1)

shutil.copy2(path, backup)
path.write_text(updated, encoding="utf-8")

print("Successfully removed all 4 duplicate navigation sections.")
print("Page content and functionality preserved.")
print("Backup created:", backup)
