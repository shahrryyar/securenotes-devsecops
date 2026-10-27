# VULN-21 (CWE-250): end-of-life base image, mutable tag, root user, debug server
FROM python:3.9

WORKDIR /app
ADD . /app
RUN pip install -r requirements.txt

EXPOSE 8000
CMD ["python", "wsgi.py"]
