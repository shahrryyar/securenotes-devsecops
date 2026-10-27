# Team guide (3 members)

Each member **owns** one area: they understand it deeply, present it, and write its report chapter. Everyone must be able to explain the whole pipeline at a basic level, because teachers often ask the "wrong" person.

## Roles

| | Member 1: Pipeline & supply chain | Member 2: Application security (SAST) | Member 3: Dependencies, containers & DAST |
|---|---|---|---|
| Owns | `.github/workflows/`, `security/policy.yml`, `scripts/`, repository settings | `app/`, `tests/test_security.py`, `security/semgrep-rules/`, the `vulnerable` branch | `requirements*.txt`, `Dockerfile`, Dependabot, ZAP, SBOM |
| Tools to master | GitHub Actions, security gate, zizmor, actionlint, Scorecard, SHA pinning | Semgrep (incl. writing rules), Bandit, CodeQL | pip-audit, Trivy, Dependency Review, Hadolint, OWASP ZAP |
| Must explain | Triggers, permissions, fail-closed gate, accepted risks, the Trivy supply-chain attack | SQLi, XSS/SSTI, command injection, IDOR, deserialization, why SAST misses logic bugs | CVEs and CVSS, lockfiles with hashes, SBOM, image hardening, passive vs active DAST |
| Demo acts | 1 and 5 (intro, wrap-up) | 4 (vulnerable PR blocked) | 2 and 3 (pipeline code, green run), plus the SBOM in act 5 |
| Report chapters | Introduction, pipeline design, pipeline security, conclusion | SAST evaluation, custom rules, test results | SCA/container/DAST evaluation, benchmark analysis |

## Timeline (4 weeks)

| Week | Everyone | M1 | M2 | M3 |
|---|---|---|---|---|
| 1 | Read README + PIPELINE.md, run `make install && make test` on both branches | Read `devsecops.yml` line by line; accept repo invitation | Read `routes.py` and `security.py` on both branches (`git diff main vulnerable`) | Build and run the Docker image; read the Trivy and ZAP reports |
| 2 | Each member opens one small PR (see exercises) and watches the gate | Turn on the branch ruleset (SETUP-GITHUB.md step 6) | Write one more custom Semgrep rule | Run a `full` ZAP scan via *Run workflow*; compare with baseline |
| 3 | Fill in the report from the benchmark numbers | Pipeline + supply-chain chapters | SAST chapter | SCA/container/DAST chapter |
| 4 | Two full rehearsals of DEMO-SCRIPT.md with a timer | Screenshots / backup | Practise the live exploit | Practise answers to the likely questions |

## Hands-on exercises (do these, they make the demo convincing)

1. **Break it on purpose (everyone):** on a new branch, add `password = "SuperSecret123!"` to `app/__init__.py`, push, open a PR and watch Gitleaks and Bandit block it. Close the PR without merging.
2. **Dependency (M3):** change `pyyaml==6.0.3` to an old version in a branch and watch pip-audit, Trivy and Dependency Review fail. (The hashes must match: use the hash lines from the `vulnerable` branch.)
3. **Custom rule (M2):** write a Semgrep rule that flags `send_file(` called with a value from `request`. Test it with `semgrep --config security/semgrep-rules app/` on the `vulnerable` branch.
4. **Accept a risk (M1):** add an `accepted_risks` entry with an expiry date in the past and watch the gate fail with "expired".
5. **Weekly scan (M3):** explain why the scheduled run exists: a CVE can be published for a package we already use.

## Working rules

- Work on branches and open pull requests; do not push straight to `main` once the ruleset is on.
- Never merge the demo PR from `vulnerable`.
- Never commit real secrets. The fake ones on `vulnerable` are labelled.
- Use `git diff main vulnerable` whenever you need to explain a bug and its fix.

## Glossary

| Term | Meaning |
|---|---|
| SAST | Static Application Security Testing: analyses source code without running it |
| SCA | Software Composition Analysis: finds known vulnerabilities (CVEs) in third-party packages |
| DAST | Dynamic Application Security Testing: attacks the running application from outside |
| SARIF | Standard JSON format for scanner results, understood by GitHub code scanning |
| CVE / CVSS | Public ID of a vulnerability / its severity score from 0 to 10 |
| CWE | Category of weakness, e.g. CWE-89 SQL injection |
| SBOM | Software Bill of Materials: list of every component in the build |
| Shift left | Find problems as early as possible (developer machine, PR) instead of in production |
| Fail closed | When unsure (missing report, crashed tool), block instead of allowing |
| Recall / precision | Share of real bugs found / share of findings that are real bugs |
