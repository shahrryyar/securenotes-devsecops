# syntax=docker/dockerfile:1
# Hardened container image for SecureNotes.
#  - base image pinned by digest (Dependabot updates it)
#  - dependencies installed from a hash-locked requirements file
#  - application files owned by root and read-only for the runtime user
#  - runs as an unprivileged user with a health check
FROM python:3.13-slim@sha256:b3575dcf816cdacc5292df77a6e3e59b8941631078373a045efa2ac1e9c5c3b2

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --home-dir /app --no-create-home --shell /usr/sbin/nologin app

COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

COPY app/ app/
COPY wsgi.py .
RUN mkdir -p /app/instance && chown app:app /app/instance

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/login', timeout=2)"]

# --preload creates the app once so every worker shares the same SECRET_KEY fallback.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--preload", "--no-control-socket", "--access-logfile", "-", "wsgi:app"]
