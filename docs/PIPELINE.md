# How the pipeline works

File: `.github/workflows/devsecops.yml`. Every job writes a report in **SARIF** (the standard format for static analysis results) or JSON. Each report is uploaded to the **Security → Code scanning** tab and also saved as a run artifact for the security gate.

## Triggers

| Trigger | Why |
|---|---|
| `pull_request` to `main` | Block vulnerable code **before** it is merged |
| `push` to `main` | Keep the Security tab current for the default branch |
| `schedule` (Mondays 03:17) | New CVEs are published every day: yesterday's safe dependency can be vulnerable today |
| `workflow_dispatch` | Run by hand; choose `baseline` or `full` (active) ZAP scan |

## Jobs

| Job | Tool | How it runs | Report |
|---|---|---|---|
| Build & tests | pytest | 10 functional + 17 security regression tests | `junit.xml` |
| SAST · Semgrep | Semgrep 1.182 | Packs `p/python`, `p/flask`, `p/owasp-top-ten`, `p/secrets`, `p/dockerfile`, `p/github-actions` + our rules in `security/semgrep-rules/` | `semgrep.sarif` |
| SAST · Bandit | Bandit 1.9 | Python AST checks on `app/` and `wsgi.py` | `bandit.sarif` |
| SAST · CodeQL | CodeQL `security-extended` | Two matrix jobs: `python` and `actions`. Builds a database of the code and follows data from sources (request input) to sinks (SQL, shell, files) | `codeql/*.sarif` |
| SCA · pip-audit | pip-audit 2.10 | Checks every locked package against the PyPI/OSV advisory database | `pip-audit.json` |
| SCA · Trivy fs | Trivy 0.76 | Dependencies + Dockerfile misconfiguration + secrets | `trivy-fs.sarif` |
| SCA · Dependency review | GitHub action | PR only: fails if the PR **adds** a high-severity vulnerable or AGPL-licensed package | PR comment |
| Secrets · Gitleaks | Gitleaks 8.30 | `fetch-depth: 0`, scans **every commit** reachable from the tested revision | `gitleaks.sarif` |
| Container | Hadolint 2.15, Trivy | Lint Dockerfile → build image → scan image (only CVEs that have a fix) → CycloneDX **SBOM** | `hadolint.sarif`, `trivy-image.sarif`, `sbom.cdx.json` |
| DAST · ZAP | OWASP ZAP 2.17 | Starts the real container, then ZAP baseline (passive) or full (active) scan against it | `zap.json`, `zap.html` |
| CI/CD security | zizmor 1.31, actionlint 1.7 | zizmor: security audit of workflows (script injection, unpinned actions, token exposure). actionlint + shellcheck: correctness | `zizmor.sarif` |
| **Security gate** | `scripts/security_gate.py` | Runs after all jobs (`if: always()`), downloads every report, applies `security/policy.yml` | gate summary + PR comment |

Separate workflow: **OpenSSF Scorecard** (`scorecard.yml`) rates the repository's practices (pinned dependencies, token permissions, branch protection, code review and so on).

## The security gate

1. **Normalise:** every finding becomes `critical / high / medium / low / info`. It uses the SARIF `security-severity` score (CVSS-like 0–10) when the tool provides one. Otherwise it uses the SARIF level, Bandit's severity, or ZAP's risk code.
2. **Fail closed:** if a required report is missing or unreadable, the gate fails. A crashed scanner must never look like a clean scan.
3. **Thresholds:** default `high`. `gitleaks: low` (any secret blocks), `hadolint`, `zizmor` and `zap: medium`.
4. **Accepted risks:** entries in `policy.yml` with a reason, an owner and an **expiry date**. Expired entries fail the gate, which forces a re-review.
5. **Upstream jobs:** if any job failed (for example the unit tests), the gate fails too.
6. **Output:** a markdown table in the run summary, the same table as a PR comment, and the `security-gate-report` artifact.

Only **one** status check needs to be required in the branch ruleset: `Security gate`.

## Benchmark

`scripts/benchmark.py` runs inside the gate job. On the `vulnerable` branch it finds every `# VULN-xx` marker, matches each finding to a planted bug by file and line, package name, or DAST rule ID, and prints:

- a matrix of bugs × tools (✅ detected, ❌ missed, `·` outside that tool's scope)
- **recall** per tool = detected / planted bugs in its scope
- **precision** per tool = findings pointing at a planted bug / all findings
- the combined detection rate of the whole pipeline

On `main` there are no markers and it prints a one-line note.

## Hardening of the pipeline itself

The pipeline holds a token that can write to the repository, so it is an attack target.

| Control | Where |
|---|---|
| `permissions: {}` at the top, minimal permissions per job | every job |
| Actions pinned to full commit SHAs; repo setting "require SHA pinning"; only GitHub-owned actions + Scorecard allowed | workflow + repository settings |
| Docker images pinned by `@sha256` digest | `env:` block |
| `persist-credentials: false` on every checkout | every job |
| No `${{ }}` expressions inside `run:` scripts; values go through `env:` | e.g. `DAST_MODE`, `PR_NUMBER` |
| Python tools installed only from hash-locked files (`--require-hashes`) | `security/requirements-tools.txt` |
| `pull_request` (not `pull_request_target`), and no PR comments for forks | gate job |
| Dependabot updates every pin weekly | `.github/dependabot.yml` |
| zizmor + actionlint + CodeQL `actions` scan the workflows on every run | `pipeline-security`, `sast-codeql` |

**Case study for the report:** on 19 March 2026 attackers used stolen credentials to force-push 76 of 77 version tags of `aquasecurity/trivy-action` and every tag of `setup-trivy` to credential-stealing code, and published a malicious Trivy v0.69.4 (CVE-2026-33634). Any pipeline using `trivy-action@<tag>` ran the malware. Our pipeline runs the Trivy **image pinned by digest** (version 0.76.1, released after the incident) and pins every action by SHA, so a rewritten tag cannot change what we run.

## Shift left: pre-commit

`.pre-commit-config.yaml` runs Gitleaks, Bandit, our Semgrep rules, zizmor and basic file checks on every `git commit`:

```bash
pip install pre-commit
pre-commit install
```

## Adding a new tool

1. Add a job that writes `reports/<tool>.sarif` and uploads an artifact named `report-<tool>`.
2. Add the job to the gate's `needs:` list.
3. Add `<tool>: <tool>.sarif` under `required_reports` in `security/policy.yml` (and a threshold if needed).
4. Optional: add it to `tools:` in `security/ground-truth.yml` for the benchmark.
