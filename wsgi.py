"""WSGI entry point: `gunicorn wsgi:app` in production, `python wsgi.py` for local development."""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # VULN-11 (CWE-489): Werkzeug debugger enabled and exposed on all interfaces
    app.run(host="0.0.0.0", port=8000, debug=True)
