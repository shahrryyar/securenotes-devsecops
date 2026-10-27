# Local shortcuts. CI runs the same tools in .github/workflows/devsecops.yml.
.PHONY: help install test run docker scan-bandit scan-deps scan-secrets scan-semgrep scan-docker scan-workflows gate benchmark clean

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "}; {printf "  %-16s %s\n", $$1, $$2}'

install: ## install app, test and scanner dependencies into .venv
	python3 -m venv .venv
	.venv/bin/pip install --require-hashes -r requirements.txt -r requirements-dev.txt
	.venv/bin/pip install --require-hashes -r security/requirements-tools.txt

test: ## run unit + security regression tests
	.venv/bin/python -m pytest -v

run: ## run the app locally on http://127.0.0.1:8000
	SESSION_COOKIE_SECURE=false .venv/bin/python wsgi.py

docker: ## build and run the container on http://127.0.0.1:8000
	docker build -t securenotes:local .
	docker run --rm -p 8000:8000 -e SESSION_COOKIE_SECURE=false securenotes:local

reports:
	mkdir -p reports

scan-bandit: reports ## SAST: Bandit
	.venv/bin/bandit -c pyproject.toml -r app wsgi.py -f sarif -o reports/bandit.sarif || true

scan-semgrep: reports ## SAST: Semgrep (needs Docker)
	docker run --rm --user "$$(id -u):$$(id -g)" -e HOME=/tmp -v "$$PWD:/src" -w /src semgrep/semgrep:1.182.0 \
	  semgrep scan --metrics=off --config p/python --config p/flask --config p/owasp-top-ten \
	  --config p/secrets --config security/semgrep-rules --sarif --output reports/semgrep.sarif

scan-deps: reports ## SCA: pip-audit
	.venv/bin/pip-audit -r requirements.txt -r requirements-dev.txt --disable-pip --require-hashes \
	  --format json --output reports/pip-audit.json || true

scan-secrets: reports ## Secrets: Gitleaks over the whole git history (needs Docker)
	docker run --rm --user "$$(id -u):$$(id -g)" -v "$$PWD:/repo" ghcr.io/gitleaks/gitleaks:v8.30.1 \
	  git /repo --config /repo/.gitleaks.toml --redact --exit-code 0 --report-format sarif --report-path /repo/reports/gitleaks.sarif

scan-docker: reports ## Container: Hadolint (needs Docker)
	docker run --rm -v "$$PWD:/src" -w /src hadolint/hadolint:v2.15.1 hadolint --no-fail --format sarif Dockerfile > reports/hadolint.sarif

scan-workflows: reports ## CI/CD: zizmor
	.venv/bin/zizmor --format sarif .github/workflows > reports/zizmor.sarif || true

gate: ## apply security/policy.yml to whatever is in reports/
	.venv/bin/python scripts/security_gate.py --reports reports --policy security/policy.yml

benchmark: ## detection matrix against the planted vulnerabilities (vulnerable branch)
	.venv/bin/python scripts/benchmark.py --reports reports

clean: ## remove reports and caches
	rm -rf reports .pytest_cache instance
