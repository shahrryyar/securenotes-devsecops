"""Security regression tests.

Each test proves that one vulnerability class from docs/VULNERABILITIES.md is
fixed. On the `vulnerable` branch these tests fail, so unit tests act as an
extra security gate next to the scanners.
"""
import ast
import io
import logging
import sqlite3
from pathlib import Path

from .conftest import PASSWORD, create_note, csrf, login, register


def test_sql_injection_login_bypass_blocked(client):
    # VULN-01 (CWE-89)
    register(client, "victim")
    response = login(client, "victim' --", password="anything")
    assert response.status_code == 401


def test_sql_injection_in_search_blocked(alice):
    # VULN-02 (CWE-89): the payload is treated as text, not SQL.
    create_note(alice, "private")
    response = alice.get("/search?q=' OR 1=1 --")
    assert response.status_code == 200
    assert "private" not in response.get_data(as_text=True).split("Results for")[1]


def test_reflected_xss_and_ssti_escaped(alice):
    # VULN-03 (CWE-79 / CWE-1336)
    page = alice.get("/search?q=<script>alert(1)</script>{{7*7}}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    assert "{{7*7}}" in page  # rendered as text, not evaluated to 49


def test_export_does_not_run_shell_commands(alice, tmp_path):
    # VULN-04 (CWE-78)
    create_note(alice, "note")
    marker = tmp_path / "pwned"
    response = alice.post(
        "/notes/1/export",
        data={"filename": f"x; touch {marker};", "csrf_token": csrf(alice, "/notes/1")},
    )
    assert not marker.exists()
    assert response.status_code == 200


def test_secret_key_not_hardcoded(tmp_path, monkeypatch):
    # VULN-05 (CWE-798): without a SECRET_KEY env var each process gets a random key.
    from app import create_app

    monkeypatch.delenv("SECRET_KEY", raising=False)
    config = {"DATABASE": str(tmp_path / "db.sqlite3"), "UPLOAD_FOLDER": str(tmp_path / "up")}
    assert create_app(config).config["SECRET_KEY"] != create_app(config).config["SECRET_KEY"]


def test_yaml_import_rejects_python_objects(alice, tmp_path):
    # VULN-06 (CWE-502)
    marker = tmp_path / "pwned"
    payload = f'- !!python/object/apply:os.system ["touch {marker}"]\n'.encode()
    response = alice.post(
        "/import",
        data={"file": (io.BytesIO(payload), "evil.yml"), "csrf_token": csrf(alice, "/import")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert not marker.exists()


def test_cannot_read_other_users_note(client):
    # VULN-07 (CWE-639, IDOR)
    register(client, "owner")
    login(client, "owner")
    create_note(client, "owner secret")
    client.post("/logout", data={"csrf_token": csrf(client, "/notes")})
    register(client, "attacker")
    login(client, "attacker")
    assert client.get("/notes/1").status_code == 404
    response = client.post("/notes/1/delete", data={"csrf_token": csrf(client, "/notes")})
    assert response.status_code == 404


def test_path_traversal_blocked(alice):
    # VULN-08 (CWE-22)
    depth = 15
    for path in ("/files/" + "../" * depth + "etc/passwd", "/files/" + "..%2f" * depth + "etc%2fpasswd"):
        response = alice.get(path)
        assert response.status_code == 404
        assert b"root:" not in response.data


def test_open_redirect_blocked(client):
    # VULN-09 (CWE-601)
    register(client, "eve")
    response = login(client, "eve", next_url="https://evil.example")
    assert response.headers["Location"].endswith("/notes")


def test_passwords_hashed_with_strong_kdf(app, client):
    # VULN-10 (CWE-328)
    register(client, "frank")
    conn = sqlite3.connect(app.config["DATABASE"])
    (stored,) = conn.execute("SELECT password_hash FROM users WHERE username='frank'").fetchone()
    conn.close()
    assert PASSWORD not in stored
    assert stored.startswith(("scrypt:", "pbkdf2:"))


def test_debugger_disabled(app):
    # VULN-11 (CWE-489): neither the config nor wsgi.py may enable the Werkzeug debugger.
    assert not app.debug
    tree = ast.parse((Path(__file__).parents[1] / "wsgi.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "debug":
            assert not (isinstance(node.value, ast.Constant) and node.value.value is True)


def test_password_never_logged(client, caplog):
    # VULN-12 (CWE-532)
    caplog.set_level(logging.DEBUG)
    register(client, "grace")
    login(client, "grace", password="this-is-a-wrong-password")
    assert "this-is-a-wrong-password" not in caplog.text


def test_errors_do_not_leak_stack_traces(alice):
    # VULN-13 (CWE-209)
    response = alice.post(
        "/import",
        data={"file": (io.BytesIO(b"key: [unclosed"), "bad.yml"), "csrf_token": csrf(alice, "/import")},
        content_type="multipart/form-data",
    )
    assert response.status_code == 400
    assert "Traceback" not in response.get_data(as_text=True)


def test_csrf_token_required(alice):
    # VULN-14 (CWE-352)
    assert alice.post("/notes", data={"title": "forged"}).status_code == 400
    assert alice.post("/notes", data={"title": "forged", "csrf_token": "guess"}).status_code == 400


def test_every_form_has_csrf_token(alice):
    for path in ("/notes", "/files", "/import"):
        assert 'name="csrf_token"' in alice.get(path).get_data(as_text=True)


def test_security_headers_present(client):
    # VULN-15 (CWE-693 / CWE-1021)
    headers = client.get("/login").headers
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-Content-Type-Options"] == "nosniff"


def test_session_cookie_flags(client):
    register(client, "heidi")
    cookie = login(client, "heidi").headers["Set-Cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
