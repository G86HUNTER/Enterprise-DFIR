
from pathlib import Path

path = Path("src/app.py")
source = path.read_text(encoding="utf-8")

# 1. Add session to Flask imports
old_import = """    render_template_string,
    flash
)"""

new_import = """    render_template_string,
    flash,
    session
)"""

if old_import in source:
    source = source.replace(old_import, new_import, 1)
elif "    session\n)" not in source:
    raise SystemExit("Could not locate Flask import block.")

# 2. Import authentication
auth_import = "from src.auth import auth, login_required"

if auth_import not in source:
    marker = "from werkzeug.utils import secure_filename"
    if marker not in source:
        raise SystemExit("Could not locate import insertion point.")
    source = source.replace(
        marker,
        marker + "\n" + auth_import,
        1
    )

# 3. Configure Flask and register blueprint
old_config = '''app = Flask(__name__)

app.secret_key = "replace-with-strong-secret"'''

new_config = '''app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "dev-only-change-this-secret-before-deployment"
)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("APP_ENV") == "production"
)

app.register_blueprint(auth)'''

if old_config in source:
    source = source.replace(old_config, new_config, 1)
elif "app.register_blueprint(auth)" not in source:
    raise SystemExit("Could not locate Flask configuration block.")

# 4. Protect application routes
routes = [
    ("def home():", "home"),
    ("def evidence():", "evidence"),
    ("def verify_evidence(evidence_id):", "verify_evidence"),
    ("def timeline():", "timeline"),
    ("def alerts():", "alerts"),
    ("def incidents():", "incidents"),
]

for function, name in routes:
    if function not in source:
        raise SystemExit(f"Could not locate route: {function}")

    position = source.index(function)
    before = source[:position]

    if "@login_required" not in before.split("\n")[-4:]:
        source = source[:position] + "@login_required\n" + source[position:]

path.write_text(source, encoding="utf-8")

print("Authentication changes applied successfully.")