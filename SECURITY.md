# Security policy

## Supported versions

Only the `main` branch is supported. The `vulnerable` branch is **intentionally
insecure** teaching material: never deploy it and never merge it.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's **private vulnerability reporting**
(Security tab → "Report a vulnerability"). We aim to reply within 7 days and to fix
confirmed high or critical issues within 30 days.

## How this repository is protected

| Layer | Control |
|---|---|
| Developer machine | pre-commit hooks: Gitleaks, Bandit, Semgrep, zizmor |
| Pull request | DevSecOps pipeline + security gate (required status check), Dependency Review, CODEOWNERS review |
| Repository | Branch ruleset on `main`, secret scanning + push protection, Dependabot alerts and updates |
| Supply chain | Hash-locked Python dependencies, SHA-pinned actions, digest-pinned images, SBOM per build, OpenSSF Scorecard |
| Continuous | Weekly scheduled re-scan for newly published CVEs |
