import re

import pytest

from app import create_app

CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')
PASSWORD = "correct-horse-battery"


@pytest.fixture()
def app(tmp_path):
    return create_app(
        {
            "TESTING": True,
            "SECRET_KEY": "test-only-secret",
            "DATABASE": str(tmp_path / "test.sqlite3"),
            "UPLOAD_FOLDER": str(tmp_path / "uploads"),
            "SESSION_COOKIE_SECURE": False,
        }
    )


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client, path="/login"):
    """Fetch a page and return the CSRF token embedded in its form ("" if there is none)."""
    match = CSRF_RE.search(client.get(path).get_data(as_text=True))
    return match.group(1) if match else ""


def register(client, username, password=PASSWORD):
    return client.post(
        "/register",
        data={"username": username, "password": password, "csrf_token": csrf(client, "/register")},
    )


def login(client, username, password=PASSWORD, next_url=None):
    path = "/login" + (f"?next={next_url}" if next_url else "")
    return client.post(
        path, data={"username": username, "password": password, "csrf_token": csrf(client)}
    )


def create_note(client, title, body=""):
    token = csrf(client, "/notes")
    return client.post("/notes", data={"title": title, "body": body, "csrf_token": token})


@pytest.fixture()
def alice(client):
    register(client, "alice")
    login(client, "alice")
    return client
