"""SecureNotes: a small Flask notes app that serves as the target of the DevSecOps pipeline.

The `main` branch contains the hardened version. The `vulnerable` branch plants
known vulnerabilities (marked with `VULN-xx` comments) so the pipeline can be
shown blocking them and the scanners can be benchmarked.
"""
import logging
import os
import secrets

from flask import Flask

from . import db, security
from .routes import bp


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)

    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        # A random key is safe but sessions will not survive a restart.
        secret_key = secrets.token_hex(32)
        logging.getLogger(__name__).warning("SECRET_KEY not set; using a random per-process key")

    app.config.from_mapping(
        SECRET_KEY=secret_key,
        DATABASE=os.path.join(app.instance_path, "notes.sqlite3"),
        UPLOAD_FOLDER=os.path.join(app.instance_path, "attachments"),
        MAX_CONTENT_LENGTH=1024 * 1024,  # 1 MiB upload limit
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Disabled only for plain-HTTP environments such as the DAST job.
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "true").lower() == "true",
    )
    if test_config:
        app.config.update(test_config)

    os.makedirs(app.instance_path, exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    db.init_app(app)
    security.init_app(app)
    app.register_blueprint(bp)
    return app
