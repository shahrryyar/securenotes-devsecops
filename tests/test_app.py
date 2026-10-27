"""Functional tests: the app works as expected for a normal user."""
import io

from .conftest import create_note, csrf, login, register


def test_index_redirects_to_login(client):
    response = client.get("/")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_register_and_login(client):
    assert register(client, "bob").status_code == 302
    response = login(client, "bob")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/notes")


def test_short_password_rejected(client):
    assert register(client, "carol", password="short").status_code == 400


def test_wrong_password_rejected(client):
    register(client, "dave")
    assert login(client, "dave", password="wrong-password-123").status_code == 401


def test_create_view_and_search_note(alice):
    create_note(alice, "Shopping list", "milk and eggs")
    page = alice.get("/notes").get_data(as_text=True)
    assert "Shopping list" in page
    assert "Shopping list" in alice.get("/search?q=milk").get_data(as_text=True)
    assert alice.get("/notes/1").status_code == 200


def test_delete_note(alice):
    create_note(alice, "Temporary")
    response = alice.post("/notes/1/delete", data={"csrf_token": csrf(alice, "/notes/1")})
    assert response.status_code == 302
    assert alice.get("/notes/1").status_code == 404


def test_export_note(alice):
    create_note(alice, "Exported", "hello")
    response = alice.post(
        "/notes/1/export", data={"filename": "my-note", "csrf_token": csrf(alice, "/notes/1")}
    )
    assert response.status_code == 200
    assert "my-note.txt" in response.headers["Content-Disposition"]
    assert b"hello" in response.data


def test_upload_and_download_file(alice):
    token = csrf(alice, "/files")
    alice.post(
        "/files",
        data={"file": (io.BytesIO(b"report"), "report.txt"), "csrf_token": token},
        content_type="multipart/form-data",
    )
    response = alice.get("/files/report.txt")
    assert response.status_code == 200
    assert response.data == b"report"


def test_import_yaml_notes(alice):
    token = csrf(alice, "/import")
    yaml_doc = b"- title: Imported one\n  body: first\n- title: Imported two\n"
    response = alice.post(
        "/import",
        data={"file": (io.BytesIO(yaml_doc), "notes.yml"), "csrf_token": token},
        content_type="multipart/form-data",
    )
    assert response.status_code == 302
    assert "Imported two" in alice.get("/notes").get_data(as_text=True)


def test_logout(alice):
    alice.post("/logout", data={"csrf_token": csrf(alice, "/notes")})
    assert alice.get("/notes").status_code == 302
