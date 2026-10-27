# Report template: Automated Security Auditing in CI/CD Pipelines

Suggested length: 20–30 pages. **[M1] [M2] [M3]** mark who writes each part (see TEAM-GUIDE.md). Take every number from a real pipeline run and name the run (link or date).

---

## Abstract (½ page) [M1]
Problem, what you built (13 tools, policy-as-code gate, 23-bug benchmark), headline result (for example "the combined pipeline detected X/23 planted vulnerabilities; the best single tool detected Y"), main lesson.

## 1. Introduction [M1]
- Cost of finding vulnerabilities late; DevOps vs DevSecOps; "shift left".
- Goals: (1) integrate SAST + SCA into GitHub Actions, (2) block vulnerable changes automatically, (3) measure scanner effectiveness, (4) secure the pipeline itself.
- Scope and ethics: own app, own repository, fake secrets.

## 2. Background [all]
- SAST (pattern-based vs data-flow), SCA, secret scanning, container scanning, DAST.
- OWASP Top 10:2025, CWE, CVE/CVSS, SARIF.
- Supply-chain attacks on CI/CD. Case study: Trivy action compromise, March 2026 (CVE-2026-33634).

## 3. System design [M1]
- Architecture diagram (README mermaid diagram or a redrawn version).
- Table of jobs and tools (from PIPELINE.md) and why each tool was chosen.
- Security gate: normalisation, thresholds, fail-closed, accepted risks with expiry.
- Pipeline hardening table.

## 4. Target application and test corpus [M2]
- SecureNotes features; hardened controls mapped to OWASP categories.
- Vulnerable branch: the 23 planted bugs (table from VULNERABILITIES.md: ID, CWE, OWASP).
- Security regression tests: 17 tests, one per bug class; result on each branch (`main` all pass, `vulnerable` 16 fail).

## 5. Results [M2, M3]
### 5.1 Detection matrix
Paste the **Scanner benchmark** table from the latest PR run (bugs × tools).
### 5.2 Per-tool metrics
Recall, precision and number of findings per tool, plus pipeline run time per job (Actions → run → job durations).
### 5.3 Gate outcome
Gate table for `main` (pass) vs the demo PR (fail). Screenshots: red PR with "Merging is blocked", inline annotation, Security tab.
### 5.4 Real findings in our own hardened code
The first CI run on `main` found real issues we had not planted: Trivy (CVEs in pip's bundled urllib3, msgpack and setuptools in the base image) and CodeQL (`py/url-redirection` on the allow-list check). Gitleaks also flagged the demo branch secret during a scan of `main`. Describe each fix. This shows the pipeline working on real code.

## 6. Discussion [all]
- No single tool is enough: compare columns. Pattern vs data-flow SAST. SAST vs DAST (CSRF and headers are runtime findings only).
- Business logic (IDOR) needs custom rules and tests.
- False positives and developer friction; thresholds and accepted risks.
- Cost: time per run, free tier for public repos.
- Limitations: unauthenticated DAST, a small synthetic app, planted bugs are easier than real ones.

## 7. Conclusion and future work [M1]
Authenticated DAST, fuzzing, signed images (cosign / SLSA provenance), secret-manager integration, deployment stage with runtime monitoring.

## References
OWASP Top 10:2025; CWE; GitHub Actions security hardening guide; tool documentation (Semgrep, CodeQL, Bandit, pip-audit, Trivy, Gitleaks, Hadolint, OWASP ZAP, zizmor, OpenSSF Scorecard); CVE-2026-33634 advisory.

## Appendices
A. `devsecops.yml` · B. `policy.yml` · C. Custom Semgrep rules · D. Full benchmark output · E. Screenshots
