# Live demo script (about 15 minutes)

Three presenters, five acts. Everything runs on GitHub, so you only need a laptop with a browser. Open the tabs listed in "Before the presentation" first, because GitHub pages can be slow on university Wi-Fi.

Repository: https://github.com/shahrryyar/securenotes-devsecops

---

## Before the presentation (the day before)

1. **Run the pipeline fresh on both branches** so the results are recent:
   - Actions → *DevSecOps Pipeline* → **Run workflow** → branch `main`.
   - Open the demo pull request (`vulnerable` → `main`). If it is closed, create it again: **Pull requests → New → base `main`, compare `vulnerable`**. It runs the pipeline automatically. **Never press Merge.**
2. Check that `main` shows ✅ **Security gate** and the PR shows ❌ **Security gate**.
3. Prepare these browser tabs:
   1. The repository home page (README with the pipeline diagram)
   2. `.github/workflows/devsecops.yml`
   3. Actions → the latest green run on `main` (summary page)
   4. The demo pull request → **Checks** tab, and the gate comment at the bottom of **Conversation**
   5. The PR **Files changed** tab
   6. **Security → Code scanning** (filter: branch `vulnerable`)
   7. **Security → Dependabot** and **Insights → Dependency graph**
4. **Backup plan for no internet:** take screenshots of every tab above, and download the `security-gate-report` artifact from both runs. Locally you can still run `make test` on both branches (see Act 5).

---

## Act 1: the problem and the idea (presenter 1, 2 min)

- "Security is usually tested at the end, by hand, and slowly. DevSecOps **shifts security left**: every change is scanned automatically before it can be merged."
- Show the README diagram. Explain the parts: **SAST** reads source code, **SCA** checks dependencies for known CVEs, **secret scanning**, **container scanning**, **DAST** attacks the running app, and **CI/CD security** checks the pipeline itself.
- "Thirteen tools run in parallel. One **security gate** decides pass or fail from a policy file."

## Act 2: the pipeline code (presenter 2, 3 min)

Open `.github/workflows/devsecops.yml` and point at:

- `on:` runs on **pull requests, pushes to main, and every Monday**. The weekly run catches CVEs published *after* the code was merged.
- `permissions: {}` at the top: **least privilege**. Each job asks only for what it needs.
- `uses: actions/checkout@3d3c42e…  # v7.0.1`: actions pinned to a **commit SHA**, not a tag. "In March 2026 attackers rewrote 76 version tags of the Trivy GitHub Action to steal CI secrets (CVE-2026-33634). A pinned SHA cannot be rewritten." This is your strongest talking point.
- The `security-gate` job and `security/policy.yml`: thresholds per tool, **fail closed** when a report is missing, accepted risks need a reason and an **expiry date**.

## Act 3: the secure version passes (presenter 2, 2 min)

Open the latest green run on `main`:

- All jobs are green. Scroll the **summary**: the gate table shows every tool and the threshold it is held to.
- "The same tools found real issues in our own hardened code on the first run: Trivy found CVEs in pip's bundled libraries inside the base image, and CodeQL flagged an open-redirect pattern. We fixed both. This is the pipeline doing its job." (Show the commit *"Fix first CI run findings…"* in the history.)

## Act 4: the vulnerable version is blocked (presenter 3, 5 min)

Open the demo pull request.

1. **Conversation tab:** the red ❌ **Security gate** and the "Merging is blocked" box. Scroll to the bot comment: the gate table and the **scanner benchmark matrix**.
2. **Files changed:** pick 3 bugs and show the annotation the scanners put on the exact line:
   - **VULN-01 SQL injection**: `f"SELECT … '{username}'"` (Bandit, Semgrep, CodeQL)
   - **VULN-07 IDOR**: generic tools miss it; **our custom Semgrep rule** catches it. "Business logic needs custom rules."
   - **VULN-23 insecure workflow**: zizmor finds script injection in a GitHub Actions file. "We scan the pipeline too."
3. **Checks tab → Build & unit/security tests:** 16 security regression tests fail, one per bug class.
4. **Security → Code scanning:** filter by tool (Semgrep, CodeQL, Trivy, Gitleaks, …) to show all findings in one place.
5. **The benchmark table** (PR comment or run summary): "No single tool finds everything. Each column has gaps; together the pipeline catches far more. That is why we layer tools."

Optional live exploit (only if the teacher asks, on your **own laptop**):

```bash
git checkout vulnerable
make install && make run          # http://127.0.0.1:8000, register two users
# SQL injection login bypass: username  victim' --   password  anything
# SSTI / XSS: http://127.0.0.1:8000/search?q={{7*7}}   shows 49
git checkout main && make run     # the same payloads now fail
```

## Act 5: wrap-up and supply chain (presenter 1, 3 min)

- **Dependabot** tab: update PRs arrive automatically and must pass the same gate.
- **Security → Code scanning → Scorecard**: OpenSSF rates the repo's own practices.
- **SBOM**: download `sbom.cdx.json` from the run artifacts. "This is the list of everything in our container, which customers and regulators increasingly ask for."
- Close on the results table from the report: tools × planted bugs, recall per tool, and the lesson that layered defence plus custom rules plus tests beats any single scanner.

---

## Likely teacher questions

| Question | Short answer |
|---|---|
| Why several SAST tools? | They use different techniques: pattern matching (Semgrep, Bandit) and data-flow analysis (CodeQL). The benchmark shows each misses things the others find. |
| What about false positives? | Precision per tool is in the benchmark. The gate only blocks at high severity by default, and accepted risks are documented with an expiry date in `policy.yml`. |
| Why not just GitHub's default CodeQL? | Default setup cannot be combined with our custom gate and other tools, and we wanted policy-as-code over all 13 tools. |
| Does the pipeline slow developers down? | Jobs run in parallel (about 8–12 minutes). Pre-commit hooks catch the easy things in seconds before a push. |
| What can't the pipeline find? | Complex business logic, authorisation design, and anything not reachable by the unauthenticated ZAP baseline scan. Future work: authenticated DAST, fuzzing, manual pentest. |
| How do you stop someone just disabling the checks? | Branch ruleset (required status check + code-owner review), CODEOWNERS on `.github/` and `security/`, SHA-pinning enforced in repository settings. |
