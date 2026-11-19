from pathlib import Path
import re
import shutil

path = Path("src/app.py")
source = path.read_text(encoding="utf-8")
updated = source

old_import = "from src.auth import auth, login_required"
new_import = (
    "from src.auth import auth, login_required, "
    "create_csrf_token, valid_csrf"
)

if updated.count(old_import) != 1:
    raise SystemExit("STOPPED: Authentication import did not match.")

updated = updated.replace(old_import, new_import, 1)

marker = "app.register_blueprint(auth)"

protection = '''app.register_blueprint(auth)


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": create_csrf_token}


@app.before_request
def protect_all_post_requests():
    if request.method == "POST" and not valid_csrf():
        return "Invalid or missing security token.", 400
'''

if updated.count(marker) != 1:
    raise SystemExit("STOPPED: Blueprint registration did not match.")

updated = updated.replace(marker, protection, 1)

pattern = re.compile(r"<form\b[^>]*>", re.IGNORECASE | re.DOTALL)
matches = list(pattern.finditer(updated))

if len(matches) != 8:
    raise SystemExit(
        f"STOPPED: Expected 8 forms, found {len(matches)}."
    )

updated = pattern.sub(
    lambda match: (
        match.group(0)
        + '\n                    <input type="hidden" '
          'name="csrf_token" value="{{ csrf_token() }}">'
    ),
    updated
)

backup = path.with_name("app.py.before_global_csrf.bak")

if backup.exists():
    raise SystemExit(f"STOPPED: Backup already exists: {backup}")

shutil.copy2(path, backup)
path.write_text(updated, encoding="utf-8")

print("Application-wide CSRF protection applied.")
print(f"Protected forms: {len(matches)}")
print(f"Backup created: {backup}")
