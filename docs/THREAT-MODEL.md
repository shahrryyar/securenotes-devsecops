# Threat model (STRIDE)

Two systems are in scope: the **application** and the **CI/CD pipeline** that builds it. The pipeline matters because a compromised pipeline can ship malicious code that passed every review.

## Assets

| Asset | Why it matters |
|---|---|
| Users' notes and files | Confidential user data |
| Password hashes, session secret | Account takeover |
| Source code on `main` | Everything users run comes from it |
| `GITHUB_TOKEN` and runner environment | Can write to the repo, publish results, read artifacts |
| Container image | What actually runs in production |

## Application

| STRIDE | Threat | Control on `main` | Verified by |
|---|---|---|---|
| **S**poofing | Credential stuffing / weak passwords | 12+ character passwords, scrypt hashes, generic error message, failures logged | tests, Bandit, CodeQL |
| **S**poofing | Session forgery with a known secret | `SECRET_KEY` from the environment, never in code | Gitleaks, test |
| **T**ampering | SQL injection | Parameterised queries only | Bandit, Semgrep, CodeQL, tests |
| **T**ampering | CSRF | Per-session token, `SameSite=Lax` | ZAP, tests |
| **R**epudiation | No record of attacks | Login failures and CSRF failures logged, with log-injection protection | CodeQL `py/log-injection` |
| **I**nformation disclosure | IDOR, path traversal | Owner check on every query, `send_from_directory` | custom Semgrep rule, CodeQL, tests |
| **I**nformation disclosure | Stack traces, verbose errors | Generic error pages | CodeQL, test |
| **D**enial of service | Huge uploads / imports | 1 MiB request limit, max 100 imported notes | review |
| **E**levation of privilege | RCE via command injection, YAML, SSTI, debugger | No shell, `safe_load`, templates from files, debugger off | Bandit, Semgrep, CodeQL, tests |
| **E**levation of privilege | Container breakout impact | Non-root user 10001, read-only app files, no pip in image | Hadolint, Trivy |

## CI/CD pipeline

| STRIDE | Threat | Control |
|---|---|---|
| **S**poofing | Malicious action version (rewritten tag, as in the 2026 Trivy attack) | SHA-pinned actions, digest-pinned images, "require SHA pinning" setting, Dependabot updates the pins |
| **T**ampering | Script injection via PR titles or inputs in `run:` | No `${{ }}` in scripts, zizmor + CodeQL `actions` |
| **T**ampering | Someone weakens the policy or disables a scanner | CODEOWNERS on `.github/` and `security/`, required `Security gate` check, ruleset |
| **R**epudiation | Unknown who changed what | PR-only changes to `main`, linear history, required reviews |
| **I**nformation disclosure | Token leaked from a job | `permissions: {}` default, `persist-credentials: false`, no secrets used by any job |
| **I**nformation disclosure | Secret committed to git | Push protection, Gitleaks over the full history, pre-commit hook |
| **D**enial of service | Hung scanner blocks merges | `timeout-minutes` on every job; concurrency cancels outdated runs |
| **E**levation of privilege | Fork PR gets write access | `pull_request` trigger (read-only token for forks), no `pull_request_target`, no comments on fork PRs |
| **E**levation of privilege | Compromised dependency at install time | `pip install --require-hashes` for the app and for every scanner |

## Residual risks (state these honestly in the report)

- SAST cannot prove authorisation logic is correct. We rely on the custom rule and tests.
- The ZAP baseline scan is unauthenticated: it only sees the login and register pages. Future work: authenticated ZAP automation.
- Base-image CVEs without an upstream fix are ignored (`--ignore-unfixed`) and re-checked weekly.
- A compromised maintainer account could still approve a malicious PR. Mitigations: 2FA for all members and a required code-owner review.
