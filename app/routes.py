"""HTTP routes. Each handler notes which OWASP Top 10:2025 risk its control addresses."""
import logging
import os
import subprocess
import traceback

import yaml
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    render_template_string,
    request,
    send_file,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from .db import get_db
from .security import hash_password, login_required, verify_password

bp = Blueprint("notes", __name__)
log = logging.getLogger("securenotes")

ALLOWED_UPLOAD_EXTENSIONS = {".txt", ".md", ".pdf", ".png", ".jpg"}
# Pages a user may be sent back to after logging in (value = Flask endpoint).
NEXT_PAGES = {
    "/notes": "notes.list_notes",
    "/files": "notes.files",
    "/search": "notes.search",
    "/import": "notes.import_notes",
}
MAX_IMPORTED_NOTES = 100


def _clean(value):
    """Strip line breaks from user input before logging (prevents log forging, CWE-117)."""
    return str(value).replace("\r", "").replace("\n", "")[:64]


def _get_own_note(note_id):
    # VULN-07 (CWE-639): note looked up by id only - any user can open any note (IDOR)
    note = get_db().execute(
        "SELECT id, title, body, created_at FROM notes WHERE id = ?",
        (note_id,),
    ).fetchone()
    if note is None:
        abort(404)
    return note


def _user_upload_dir():
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], str(g.user["id"]))
    os.makedirs(path, exist_ok=True)
    return path


# --- Authentication ---------------------------------------------------------------------

@bp.get("/")
def index():
    return redirect(url_for("notes.list_notes" if g.user else "notes.login"))


@bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not (3 <= len(username) <= 32) or len(password) < 12:
            flash("Username must be 3-32 characters and password at least 12 characters.")
            return render_template("register.html"), 400
        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            flash("Username is taken.")
            return render_template("register.html"), 400
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, hash_password(password)),
        )
        db.commit()
        log.info("user registered username=%s", _clean(username))
        flash("Account created. Please log in.")
        return redirect(url_for("notes.login"))
    return render_template("register.html")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULN-12 (CWE-532): the plain-text password is written to the log
        log.info("login attempt username=%s password=%s", username, password)
        # VULN-01 (CWE-89): SQL query built from user input
        user = get_db().execute(
            f"SELECT id, password_hash FROM users WHERE username = '{username}'"
            f" AND password_hash = '{hash_password(password)}'"
        ).fetchone()
        if user is None:
            # A09 Logging & Alerting: record failures (never the password itself).
            log.warning(
                "login failed username=%s ip=%s", _clean(username), _clean(request.remote_addr)
            )
            flash("Invalid username or password.")
            return render_template("login.html"), 401
        session.clear()  # prevents session fixation
        session["user_id"] = user["id"]
        log.info("login succeeded username=%s", _clean(username))
        # VULN-09 (CWE-601): redirect target taken straight from the URL
        return redirect(request.args.get("next") or url_for("notes.list_notes"))
    return render_template("login.html")


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("notes.login"))


# --- Notes ------------------------------------------------------------------------------

@bp.route("/notes", methods=["GET", "POST"])
@login_required
def list_notes():
    db = get_db()
    if request.method == "POST":
        title = request.form.get("title", "").strip()[:200]
        body = request.form.get("body", "")[:10_000]
        if not title:
            flash("Title is required.")
        else:
            db.execute(
                "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
                (g.user["id"], title, body),
            )
            db.commit()
        return redirect(url_for("notes.list_notes"))
    notes = db.execute(
        "SELECT id, title, created_at FROM notes WHERE owner_id = ? ORDER BY id DESC",
        (g.user["id"],),
    ).fetchall()
    return render_template("notes.html", notes=notes)


@bp.get("/notes/<int:note_id>")
@login_required
def view_note(note_id):
    return render_template("note.html", note=_get_own_note(note_id))


@bp.post("/notes/<int:note_id>/delete")
@login_required
def delete_note(note_id):
    note = _get_own_note(note_id)
    db = get_db()
    db.execute("DELETE FROM notes WHERE id = ? AND owner_id = ?", (note["id"], g.user["id"]))
    db.commit()
    return redirect(url_for("notes.list_notes"))


@bp.post("/notes/<int:note_id>/export")
@login_required
def export_note(note_id):
    note = _get_own_note(note_id)
    filename = request.form.get("filename") or f"note-{note['id']}"
    export_dir = os.path.join(current_app.instance_path, "exports")
    os.makedirs(export_dir, exist_ok=True)
    source = os.path.join(export_dir, f"{note['id']}.txt")
    with open(source, "w", encoding="utf-8") as handle:
        handle.write(f"{note['title']}\n\n{note['body']}\n")
    # VULN-04 (CWE-78): user input inserted into a shell command
    subprocess.run(f"cp {source} {export_dir}/{filename}.txt", shell=True, check=False)
    return send_file(os.path.join(export_dir, f"{filename}.txt"), as_attachment=True)


@bp.get("/search")
@login_required
def search():
    query = request.args.get("q", "")[:100]
    results = []
    if query:
        # VULN-02 (CWE-89): user input concatenated into SQL
        results = get_db().execute(
            f"SELECT id, title FROM notes WHERE owner_id = {g.user['id']} AND title LIKE '%{query}%'"
            f" OR body LIKE '%{query}%'"
        ).fetchall()
    # VULN-03 (CWE-79, CWE-1336): user input becomes part of the template source (XSS + SSTI)
    page = (
        "{% extends 'base.html' %}{% block content %}<h1>Search</h1>"
        "<form method='get'><input name='q'><button type='submit'>Search</button></form>"
        f"<h2>Results for {query}</h2>"
        "<ul>{% for n in results %}<li><a href='/notes/{{ n.id }}'>{{ n.title }}</a></li>{% endfor %}</ul>"
        "{% endblock %}"
    )
    return render_template_string(page, results=results)


# --- Files ------------------------------------------------------------------------------

@bp.route("/files", methods=["GET", "POST"])
@login_required
def files():
    folder = _user_upload_dir()
    if request.method == "POST":
        upload = request.files.get("file")
        name = secure_filename(upload.filename) if upload else ""
        if not name or os.path.splitext(name)[1].lower() not in ALLOWED_UPLOAD_EXTENSIONS:
            flash("Choose a .txt, .md, .pdf, .png or .jpg file.")
            return redirect(url_for("notes.files"))
        upload.save(os.path.join(folder, name))
        log.info("file uploaded user_id=%s name=%s", g.user["id"], _clean(name))
        return redirect(url_for("notes.files"))
    return render_template("files.html", files=sorted(os.listdir(folder)))


@bp.get("/files/<path:name>")
@login_required
def download_file(name):
    # VULN-08 (CWE-22): file path built from user input without validation
    return send_file(os.path.join(_user_upload_dir(), name), as_attachment=True)


# --- Import -----------------------------------------------------------------------------

@bp.route("/import", methods=["GET", "POST"])
@login_required
def import_notes():
    if request.method == "POST":
        upload = request.files.get("file")
        try:
            # VULN-06 (CWE-502): yaml.Loader can construct arbitrary Python objects
            data = yaml.load(upload.read(), Loader=yaml.Loader)
            rows = [(g.user["id"], item["title"], item.get("body", "")) for item in data]
        except Exception:
            # VULN-13 (CWE-209): full stack trace returned to the user
            return f"<pre>Import failed:\n{traceback.format_exc()}</pre>", 400
        db = get_db()
        db.executemany("INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)", rows)
        db.commit()
        flash(f"Imported {len(rows)} notes.")
        return redirect(url_for("notes.list_notes"))
    return render_template("import.html")


# --- Errors -----------------------------------------------------------------------------

@bp.app_errorhandler(404)
def not_found(_error):
    return render_template("error.html", message="Page not found."), 404


@bp.app_errorhandler(500)
def server_error(_error):
    # A10: never leak stack traces to the client.
    return render_template("error.html", message="Something went wrong."), 500
