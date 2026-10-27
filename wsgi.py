"""WSGI entry point: `gunicorn wsgi:app` in production, `python wsgi.py` for local development."""
from app import create_app

app = create_app()

if __name__ == "__main__":
    # Local development only. The Werkzeug debugger stays off: it allows remote code execution.
    app.run(host="127.0.0.1", port=8000, debug=False)
