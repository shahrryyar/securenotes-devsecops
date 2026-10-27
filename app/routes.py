"""HTTP routes. Each handler notes which OWASP Top 10:2025 risk its control addresses."""
import io
import logging
import os

import yaml
from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

from .db import get_db
from .security import hash_password, login_required, verify_password

bp = Blueprint("notes", __name__)
log = logging.getLogger("securenotes")

ALLOWED_UPLOAD_EXTENSIONS = {".txt", ".md", ".pdf", ".png", ".jpg"}
MAX_IMPORTED_NOTES = 100


def _clean(value):
    """Strip line breaks from user input before logging (prevents log forging, CWE-117)."""
    return str(value).replace("\r", "").replace("\n", "")[:64]


def _get_own_note(note_id):
    # A01 Broken Access Control: always filter by the logged-in owner (prevents IDOR).
    note = get_db().execute(
        "SELECT id, title, body, created_at FROM notes WHERE id = ? AND owner_id = ?",
        (note_id, g.user["id"]),
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
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user is None or not verify_password(user["password_hash"], password):
            # A09 Logging & Alerting: record failures (never the password itself).
            log.warning(
                "login failed username=%s ip=%s", _clean(username), _clean(request.remote_addr)
            )
            flash("Invalid username or password.")
            return render_template("login.html"), 401
        session.clear()  # prevents session fixation
        session["user_id"] = user["id"]
        log.info("login succeeded username=%s", _clean(username))
        # A01: only redirect to known local pages (prevents open redirect).
        target = request.args.get("next", "")
        if target not in ("/notes", "/files", "/search", "/import"):
            target = url_for("notes.list_notes")
        return redirect(target)
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
    # A05 Injection: build the file in Python instead of calling a shell.
    filename = secure_filename(request.form.get("filename", "")) or f"note-{note['id']}"
    content = f"{note['title']}\n\n{note['body']}\n".encode()
    return send_file(
        io.BytesIO(content),
        mimetype="text/plain",
        as_attachment=True,
        download_name=f"{filename}.txt",
    )


@bp.get("/search")
@login_required
def search():
    query = request.args.get("q", "")[:100]
    results = []
    if query:
        # A05 Injection: parameterised query; Jinja2 autoescaping prevents XSS in the template.
        results = get_db().execute(
            "SELECT id, title FROM notes WHERE owner_id = ? AND (title LIKE ? OR body LIKE ?)",
            (g.user["id"], f"%{query}%", f"%{query}%"),
        ).fetchall()
    return render_template("search.html", query=query, results=results)


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
    # A01: send_from_directory rejects paths that escape the user's own folder.
    return send_from_directory(_user_upload_dir(), name, as_attachment=True)


# --- Import -----------------------------------------------------------------------------

@bp.route("/import", methods=["GET", "POST"])
@login_required
def import_notes():
    if request.method == "POST":
        upload = request.files.get("file")
        try:
            # A08 Integrity Failures: safe_load only builds plain data, never Python objects.
            data = yaml.safe_load(upload.read()) if upload else None
            if not isinstance(data, list) or len(data) > MAX_IMPORTED_NOTES:
                raise ValueError("expected a list of at most 100 notes")
            rows = []
            for item in data:
                if not isinstance(item, dict) or not isinstance(item.get("title"), str):
                    raise ValueError("each note needs a string 'title'")
                rows.append((g.user["id"], item["title"][:200], str(item.get("body", ""))[:10_000]))
        except (yaml.YAMLError, ValueError, UnicodeDecodeError):
            # A10 Exceptional Conditions: log details server-side, show a generic message.
            log.exception("note import failed user_id=%s", g.user["id"])
            flash("Import failed: the file must be a YAML list of notes with a title and body.")
            return render_template("import.html"), 400
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
