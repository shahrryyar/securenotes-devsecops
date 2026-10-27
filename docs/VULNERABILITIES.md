# Planted vulnerabilities catalogue

The `vulnerable` branch contains **23 deliberate vulnerabilities**. Each one is marked in the code with a `# VULN-xx` comment, listed in `security/ground-truth.yml`, and covered by a test in `tests/test_security.py` (where a unit test is possible).

```bash
git diff main vulnerable          # every vulnerability next to its fix
git diff main vulnerable -- app/routes.py
```

> **Lab use only.** The exploit examples below are for the vulnerable branch running on your own machine (`git checkout vulnerable && make run`). Never run them against systems you do not own.

"Expected detectors" lists the tools that *should* catch each bug. The real result of every pipeline run is in the **Scanner benchmark** table in the run summary and in the PR comment. Use those numbers in the report.

---

## A05 Injection

### VULN-01 SQL injection in login (CWE-89)
- **Where:** `app/routes.py`, `login()`
- **Vulnerable:** `f"SELECT ... WHERE username = '{username}' AND password_hash = '{hash}'"`
- **Exploit:** username `victim' --` with any password logs in as `victim`. The `--` comments out the password check.
- **Fix (main):** parameterised query `WHERE username = ?` plus a password-hash comparison.
- **Expected detectors:** Bandit B608, Semgrep (formatted SQL), CodeQL `py/sql-injection`
- **Test:** `test_sql_injection_login_bypass_blocked`

### VULN-02 SQL injection in search (CWE-89)
- **Where:** `app/routes.py`, `search()`
- **Exploit:** `/search?q=' OR 1=1 --` returns **every user's** notes.
- **Fix:** `?` placeholders; the query always filters by `owner_id`.
- **Expected detectors:** Bandit B608, Semgrep, CodeQL
- **Test:** `test_sql_injection_in_search_blocked`

### VULN-03 Reflected XSS + server-side template injection (CWE-79, CWE-1336)
- **Where:** `app/routes.py`, `search()`: the search term is pasted into the template **source** passed to `render_template_string`.
- **Exploit:** `/search?q=<script>alert(document.cookie)</script>` runs JavaScript (XSS). `/search?q={{7*7}}` prints `49`, which proves the server evaluates template code. Jinja2 SSTI leads to remote code execution, e.g. `{{ cycler.__init__.__globals__.os.popen('id').read() }}`.
- **Fix:** a normal template file (`search.html`) with autoescaping; user input is only ever template *data*.
- **Expected detectors:** Semgrep (`render-template-string`, custom `flask-response-built-with-fstring`), CodeQL `py/reflective-xss` / template injection
- **Test:** `test_reflected_xss_and_ssti_escaped`

### VULN-04 OS command injection in export (CWE-78)
- **Where:** `app/routes.py`, `export_note()`: `subprocess.run(f"cp ... {filename}.txt", shell=True)`
- **Exploit:** export with filename `x; id > /tmp/pwned;` runs `id` on the server.
- **Fix:** no shell at all. The file is built in memory (`io.BytesIO`) and the name is cleaned with `secure_filename`.
- **Expected detectors:** Bandit B602/B404, Semgrep `subprocess-shell-true`, CodeQL `py/command-line-injection`
- **Test:** `test_export_does_not_run_shell_commands`

## A07 Authentication Failures

### VULN-05 Hardcoded secret key and API token (CWE-798)
- **Where:** `app/__init__.py`
- **Impact:** anyone who can read the repo can forge Flask session cookies (log in as any user) and use the API token. Secrets also stay in **git history** after they are deleted from the code.
- **Fix:** `SECRET_KEY` comes from the environment. Without it a random key is generated. Gitleaks scans the full history; GitHub push protection blocks known token formats at `git push`.
- **Expected detectors:** Gitleaks `generic-api-key`, Bandit B105, Semgrep
- **Test:** `test_secret_key_not_hardcoded`

## A08 Software or Data Integrity Failures

### VULN-06 Unsafe YAML deserialization (CWE-502)
- **Where:** `app/routes.py`, `import_notes()`: `yaml.load(data, Loader=yaml.Loader)`
- **Exploit:** upload a YAML file containing `- !!python/object/apply:os.system ["id > /tmp/pwned"]` and the command runs.
- **Fix:** `yaml.safe_load` plus validation of the structure (list of dicts, string titles, max 100 items).
- **Expected detectors:** Bandit B506, Semgrep, CodeQL `py/unsafe-deserialization`
- **Test:** `test_yaml_import_rejects_python_objects`

## A01 Broken Access Control

### VULN-07 IDOR: read or delete any user's note (CWE-639)
- **Where:** `app/routes.py`, `_get_own_note()`: `SELECT ... WHERE id = ?` with no owner check
- **Exploit:** log in as user B and open `/notes/1`, which belongs to user A.
- **Fix:** `WHERE id = ? AND owner_id = ?` everywhere.
- **Expected detectors:** **only our custom Semgrep rule** `notes-query-without-owner-check`. Generic SAST tools do not know which data belongs to whom. This is a key finding for the report: business-logic flaws need custom rules, tests or manual review.
- **Test:** `test_cannot_read_other_users_note`

### VULN-08 Path traversal in file download (CWE-22)
- **Where:** `app/routes.py`, `download_file()`: `send_file(os.path.join(folder, name))`
- **Exploit:** `/files/..%2f..%2f..%2f..%2fetc%2fpasswd`
- **Fix:** `send_from_directory`, which rejects paths outside the user's folder.
- **Expected detectors:** CodeQL `py/path-injection`, Semgrep
- **Test:** `test_path_traversal_blocked`

### VULN-09 Open redirect after login (CWE-601)
- **Where:** `app/routes.py`, `login()`: `redirect(request.args.get("next"))`
- **Exploit:** phishing link `https://our-app/login?next=https://evil.example` sends the victim to the attacker's site after a real login.
- **Fix:** only an allow-list of local paths is accepted.
- **Expected detectors:** CodeQL `py/url-redirection`, Semgrep `open-redirect`
- **Test:** `test_open_redirect_blocked`

### VULN-14 No CSRF protection (CWE-352)
- **Where:** `app/security.py`: forms have no token and POSTs are not checked
- **Exploit:** a malicious page auto-submits a form to `/notes/1/delete` while the victim is logged in.
- **Fix:** per-session random token in every form, checked with `hmac.compare_digest`; cookies are `SameSite=Lax`.
- **Expected detectors:** **OWASP ZAP** rule 10202 (Absence of Anti-CSRF Tokens). This is a runtime finding that SAST does not report.
- **Tests:** `test_csrf_token_required`, `test_every_form_has_csrf_token`

## A04 Cryptographic Failures

### VULN-10 Passwords hashed with MD5 (CWE-328)
- **Where:** `app/security.py`, `hash_password()`
- **Impact:** a leaked database is cracked in seconds (no salt, billions of MD5 guesses per second on a GPU).
- **Fix:** Werkzeug `generate_password_hash` (scrypt with a random salt).
- **Expected detectors:** Bandit B324, Semgrep `insecure-hash-algorithm-md5`, CodeQL `py/weak-sensitive-data-hashing`
- **Test:** `test_passwords_hashed_with_strong_kdf`

## A02 Security Misconfiguration

### VULN-11 Werkzeug debugger enabled (CWE-489)
- **Where:** `wsgi.py`: `app.run(host="0.0.0.0", debug=True)`, which the vulnerable Dockerfile uses as its start command
- **Impact:** the interactive debugger gives a Python shell in the browser (remote code execution).
- **Fix:** gunicorn in production; `debug=False` and `127.0.0.1` for local development.
- **Expected detectors:** Bandit B201/B104, Semgrep, CodeQL `py/flask-debug`
- **Test:** `test_debugger_disabled`

### VULN-15 Missing security headers (CWE-693, CWE-1021)
- **Where:** `app/security.py`: `set_security_headers` is not registered
- **Impact:** no Content-Security-Policy (XSS is easier to exploit), clickjacking possible (no `X-Frame-Options` / `frame-ancestors`), MIME sniffing.
- **Fix:** strict CSP, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy`, COOP/COEP/CORP, `Cache-Control: no-store`.
- **Expected detectors:** **OWASP ZAP** rules 10038, 10020, 10021
- **Test:** `test_security_headers_present`

## A09 Security Logging and Alerting Failures

### VULN-12 Password written to the log (CWE-532)
- **Where:** `app/routes.py`, `login()`: `log.info("... password=%s", username, password)`
- **Impact:** everyone with log access (ops, log platform, backups) sees user passwords.
- **Fix:** log only the username and IP, with line breaks stripped (prevents log forging, CWE-117).
- **Expected detectors:** custom Semgrep rule `sensitive-value-logged`, CodeQL `py/clear-text-logging-sensitive-data`
- **Test:** `test_password_never_logged`

## A10 Mishandling of Exceptional Conditions

### VULN-13 Stack trace shown to users (CWE-209)
- **Where:** `app/routes.py`, `import_notes()`: returns `traceback.format_exc()`
- **Impact:** reveals file paths, library versions and code, which helps an attacker plan the next step.
- **Fix:** log the details server-side and show a generic message; generic 404/500 pages.
- **Expected detectors:** CodeQL `py/stack-trace-exposure`
- **Test:** `test_errors_do_not_leak_stack_traces`

## A03 Software Supply Chain Failures

### VULN-16 to VULN-20 Vulnerable dependencies (CWE-1395)

| ID | Package | Example CVEs |
|---|---|---|
| VULN-16 | Flask 2.3.1 | CVE-2023-30861 (session cookie disclosure via caching proxy) |
| VULN-17 | Werkzeug 2.3.6 | CVE-2023-46136 (multipart DoS), CVE-2024-34069 (debugger RCE) |
| VULN-18 | Jinja2 3.1.2 | CVE-2024-22195 / CVE-2024-34064 (XSS via `xmlattr`), CVE-2024-56201 (sandbox escape) |
| VULN-19 | PyYAML 5.3.1 | CVE-2020-14343 (arbitrary code execution, CVSS 9.8) |
| VULN-20 | gunicorn 21.2.0 | CVE-2024-1135 (HTTP request smuggling) |

- **Fix:** current versions, locked with SHA-256 hashes (`pip install --require-hashes`); Dependabot opens update PRs; a weekly scheduled scan catches new CVEs.
- **Expected detectors:** pip-audit, Trivy (fs + image), Dependency Review, Dependabot alerts

### VULN-21 Insecure Dockerfile (CWE-250)
- **Where:** `Dockerfile`: `FROM python:3.9` (mutable tag, end of life), `ADD . /app`, runs as **root**, no health check, debug server as the start command.
- **Fix:** digest-pinned slim base image, `COPY`, numeric non-root `USER 10001`, `HEALTHCHECK`, gunicorn, hash-locked install.
- **Expected detectors:** Hadolint (DL3020, DL3042), Trivy misconfig (DS-0002 root user, DS-0005 ADD, DS-0026 health check)

### VULN-22 End-of-life base image with OS CVEs (CWE-1104)
- **Where:** the full Debian-based `python:3.9` image
- **Expected detectors:** Trivy image scan (hundreds of OS package CVEs)

### VULN-23 Insecure GitHub Actions workflow (CWE-94)
- **Where:** `.github/workflows/insecure-example.yml`
- **Problems:** `${{ github.event.inputs.greeting }}` expanded inside a shell script (script injection), `actions/checkout@v4` mutable tag (see the Trivy compromise, CVE-2026-33634), no `permissions:` block (token gets default scopes), checkout persists the token.
- **Fix:** see `devsecops.yml`: values passed through `env:`, SHA pins, `permissions: {}`, `persist-credentials: false`. The repository setting "require SHA pinning" blocks it from running at all.
- **Expected detectors:** zizmor (template-injection, unpinned-uses, excessive-permissions, artipacked), CodeQL for Actions, Semgrep `p/github-actions`
