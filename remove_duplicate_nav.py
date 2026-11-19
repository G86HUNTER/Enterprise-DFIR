from pathlib import Path
import re
import shutil

path = Path("src/app.py")
source = path.read_text(encoding="utf-8")

backup = Path("src/app.py.before_remove_duplicate_nav.bak")
if backup.exists():
    raise SystemExit("Backup already exists. Stopping safely.")

pattern = re.compile(
    r'<div>\s*'
    r'(?:<a href="\{\{ url_for\('
    r"'(?:timeline|alerts|incidents|evidence)'"
    r'\) \}\}"[\s\S]*?</a>\s*)+'
    r'</div>'
)

matches = list(pattern.finditer(source))

if len(matches) != 3:
    raise SystemExit(
        f"Expected 3 duplicate navigation groups, found {len(matches)}. "
        "No changes made."
    )

updated = pattern.sub("", source)

shutil.copy2(path, backup)
path.write_text(updated, encoding="utf-8")

print("Removed duplicate page navigation groups:", len(matches))
print("Top navigation and page functionality preserved.")
print("Backup:", backup)
