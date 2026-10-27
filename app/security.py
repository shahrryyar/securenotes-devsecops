"""Security controls: password hashing, CSRF protection, login enforcement, HTTP headers."""
import functools
import hashlib
import logging

from flask import g, redirect, request, session, url_for
from markupsafe import Markup

from .db import get_db

log = logging.getLogger("securenotes.security")

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
    # VULN-10 (CWE-328): fast, unsalted MD5 instead of a password hashing function
    return hashlib.md5(password.encode()).hexdigest()


def verify_password(password_hash, password):
    return hash_password(password) == password_hash


# --- CSRF (OWASP A01 Broken Access Control) --------------------------------------------

def csrf_field():
    # VULN-14 (CWE-352): forms carry no CSRF token and requests are never checked
    return Markup("")


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
    # VULN-15 (CWE-693): CSRF check and security headers (CSP, X-Frame-Options, ...) not registered
    app.jinja_env.globals["csrf_field"] = csrf_field
