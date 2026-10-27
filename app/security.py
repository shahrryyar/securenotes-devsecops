"""Security controls: password hashing, CSRF protection, login enforcement, HTTP headers."""
import functools
import hmac
import logging
import secrets

from flask import abort, g, redirect, request, session, url_for
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db

log = logging.getLogger("securenotes.security")

CSRF_SESSION_KEY = "_csrf_token"
CSRF_FORM_FIELD = "csrf_token"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cache-Control": "no-store",
}


# --- Passwords (OWASP A04 Cryptographic Failures) --------------------------------------

def hash_password(password):
    # Werkzeug defaults to scrypt with a random salt.
    return generate_password_hash(password)


def verify_password(password_hash, password):
    return check_password_hash(password_hash, password)


# --- CSRF (OWASP A01 Broken Access Control) --------------------------------------------

def csrf_token():
    if CSRF_SESSION_KEY not in session:
        session[CSRF_SESSION_KEY] = secrets.token_urlsafe(32)
    return session[CSRF_SESSION_KEY]


def csrf_field():
    return Markup('<input type="hidden" name="{}" value="{}">').format(CSRF_FORM_FIELD, csrf_token())


def verify_csrf():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    expected = session.get(CSRF_SESSION_KEY)
    sent = request.form.get(CSRF_FORM_FIELD, "")
    if not expected or not hmac.compare_digest(expected, sent):
        log.warning(
            "CSRF validation failed path=%s ip=%s",
            str(request.path).replace("\r", "").replace("\n", "")[:200],
            str(request.remote_addr).replace("\r", "").replace("\n", ""),
        )
        abort(400, description="Invalid CSRF token")


# --- Authentication ---------------------------------------------------------------------

def load_current_user():
    user_id = session.get("user_id")
    g.user = None
    if user_id is not None:
        g.user = get_db().execute(
            "SELECT id, username FROM users WHERE id = ?", (user_id,)
        ).fetchone()


def login_required(view):
    @functools.wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            return redirect(url_for("notes.login", next=request.path))
        return view(**kwargs)

    return wrapped


# --- HTTP security headers (OWASP A02 Security Misconfiguration) ------------------------

def set_security_headers(response):
    for header, value in SECURITY_HEADERS.items():
        response.headers.setdefault(header, value)
    return response


def init_app(app):
    app.before_request(load_current_user)
    app.before_request(verify_csrf)
    app.after_request(set_security_headers)
    app.jinja_env.globals["csrf_field"] = csrf_field
