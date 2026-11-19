
import re
import secrets
from functools import wraps

from flask import (
    Blueprint,
    request,
    redirect,
    url_for,
    render_template_string,
    flash,
    session,
    current_app
)
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from src.database import get_connection


auth = Blueprint("auth", __name__)


def login_required(view):
    """Require an authenticated user before accessing a route."""

    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access the application.")
            return redirect(url_for("auth.login"))

        return view(*args, **kwargs)

    return wrapped_view


def create_csrf_token():
    """Create or retrieve a session-bound CSRF token."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)

    return session["csrf_token"]


def valid_csrf():
    """Validate the submitted CSRF token."""
    submitted = request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")

    return bool(expected) and secrets.compare_digest(
        submitted, expected
    )


@auth.before_request
def protect_auth_forms():
    """Protect authentication POST requests against CSRF."""
    if request.method == "POST" and not valid_csrf():
        return "Invalid or missing security token.", 400


@auth.route("/register", methods=["GET", "POST"])
def register():

    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash(
                "Username must be 3–30 characters and contain only "
                "letters, numbers or underscores."
            )
            return redirect(url_for("auth.register"))

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Please enter a valid email address.")
            return redirect(url_for("auth.register"))

        if len(password) < 12:
            flash("Password must contain at least 12 characters.")
            return redirect(url_for("auth.register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("auth.register"))

        conn = get_connection()

        try:
            existing = conn.execute(
                """
                SELECT id FROM users
                WHERE username = ? OR email = ?
                """,
                (username, email)
            ).fetchone()

            if existing:
                flash("Username or email is already registered.")
                return redirect(url_for("auth.register"))

            password_hash = generate_password_hash(password)

            cursor = conn.execute(
                """
                INSERT INTO users (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash)
            )

            conn.commit()
            user_id = cursor.lastrowid

        except Exception:
            conn.rollback()
            current_app.logger.exception("Registration failed")
            flash("Registration could not be completed.")
            return redirect(url_for("auth.register"))

        finally:
            conn.close()

        session.clear()
        session["user_id"] = user_id
        session["username"] = username
        session["csrf_token"] = secrets.token_hex(32)
        session.permanent = True

        flash("Your account was created successfully.")
        return redirect(url_for("home"))

    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Create Account - Enterprise DFIR</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
              rel="stylesheet">
    </head>
    <body class="bg-light">
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-5">
                <div class="card shadow-sm">
                    <div class="card-body p-4">
                        <h2 class="mb-2">Create Account</h2>
                        <p class="text-muted">Enterprise DFIR Platform</p>

                        {% with messages = get_flashed_messages() %}
                            {% for message in messages %}
                                <div class="alert alert-info">{{ message }}</div>
                            {% endfor %}
                        {% endwith %}

                        <form method="post">
                            <input type="hidden" name="csrf_token"
                                   value="{{ csrf_token }}">

                            <div class="mb-3">
                                <label class="form-label">Username</label>
                                <input name="username" class="form-control"
                                       minlength="3" maxlength="30" required>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Email</label>
                                <input type="email" name="email"
                                       class="form-control" required>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Password</label>
                                <input type="password" name="password"
                                       class="form-control" minlength="12"
                                       autocomplete="new-password" required>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Confirm Password</label>
                                <input type="password" name="confirm_password"
                                       class="form-control"
                                       autocomplete="new-password" required>
                            </div>

                            <button class="btn btn-primary w-100">
                                Register
                            </button>
                        </form>

                        <p class="text-center mt-3 mb-0">
                            Already registered?
                            <a href="{{ url_for('auth.login') }}">Login</a>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    </body>
    </html>
    """, csrf_token=create_csrf_token())


@auth.route("/login", methods=["GET", "POST"])
def login():

    if "user_id" in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")

        conn = get_connection()

        try:
            user = conn.execute(
                """
                SELECT id, username, password_hash, is_active
                FROM users
                WHERE username = ? COLLATE NOCASE
                   OR email = ? COLLATE NOCASE
                """,
                (identity, identity)
            ).fetchone()

        finally:
            conn.close()

        if (
            user is None
            or not user["is_active"]
            or not check_password_hash(user["password_hash"], password)
        ):
            flash("Invalid login credentials.")
            return redirect(url_for("auth.login"))

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["csrf_token"] = secrets.token_hex(32)
        session.permanent = True

        flash("Login successful.")
        return redirect(url_for("home"))

    return render_template_string("""
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Login - Enterprise DFIR</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
              rel="stylesheet">
    </head>
    <body class="bg-light">
    <div class="container py-5">
        <div class="row justify-content-center">
            <div class="col-md-6 col-lg-5">
                <div class="card shadow-sm">
                    <div class="card-body p-4">
                        <h2 class="mb-2">Welcome Back</h2>
                        <p class="text-muted">Enterprise DFIR Platform</p>

                        {% with messages = get_flashed_messages() %}
                            {% for message in messages %}
                                <div class="alert alert-info">{{ message }}</div>
                            {% endfor %}
                        {% endwith %}

                        <form method="post">
                            <input type="hidden" name="csrf_token"
                                   value="{{ csrf_token }}">

                            <div class="mb-3">
                                <label class="form-label">Username or Email</label>
                                <input name="identity" class="form-control"
                                       autocomplete="username" required>
                            </div>

                            <div class="mb-3">
                                <label class="form-label">Password</label>
                                <input type="password" name="password"
                                       class="form-control"
                                       autocomplete="current-password" required>
                            </div>

                            <button class="btn btn-primary w-100">
                                Login
                            </button>
                        </form>

                        <p class="text-center mt-3 mb-0">
                            New user?
                            <a href="{{ url_for('auth.register') }}">
                                Create an account
                            </a>
                        </p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    </body>
    </html>
    """, csrf_token=create_csrf_token())


@auth.route("/logout", methods=["POST"])
@login_required
def logout():

    if not valid_csrf():
        return "Invalid or missing security token.", 400

    session.clear()
    flash("You have been logged out.")

    return redirect(url_for("auth.login"))