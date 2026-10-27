# GitHub setup

Repository: **https://github.com/shahrryyar/securenotes-devsecops** (public, personal account).

## Already done

| Setting | Status | Where to check |
|---|---|---|
| Public repository, `main` and `vulnerable` pushed | ✅ | Code tab |
| Dependabot alerts + security updates | ✅ | Settings → Advanced Security |
| Secret scanning + push protection | ✅ | Settings → Advanced Security |
| Private vulnerability reporting | ✅ | Settings → Advanced Security |
| CodeQL default setup **off** (the pipeline runs CodeQL itself) | ✅ | Settings → Advanced Security → Code scanning |
| Actions: default token read-only, PRs cannot be approved by Actions | ✅ | Settings → Actions → General |
| Actions: only GitHub-owned actions + `ossf/scorecard-action`, **SHA pinning required** | ✅ | Settings → Actions → General |

## Still to do

### 1. Add teammates
Settings → Collaborators → **Add people** → role *Write*. Or:

```bash
gh api -X PUT repos/shahrryyar/securenotes-devsecops/collaborators/<username> -f permission=push
```

Then add their usernames to `.github/CODEOWNERS`.

### 2. Open the demo pull request

```bash
gh pr create --repo shahrryyar/securenotes-devsecops --base main --head vulnerable \
  --title "DEMO: 23 planted vulnerabilities - the security gate must block this" \
  --body "Teaching material. Do not merge."
```

### 3. Protect `main` (turn this on once you stop pushing directly to main)

Settings → Rules → Rulesets → **New branch ruleset**:

- Target: default branch; enforcement: **Active**
- ✅ Restrict deletions, ✅ Block force pushes, ✅ Require linear history
- ✅ Require a pull request: 1 approval, dismiss stale approvals, require review from Code Owners
- ✅ Require status checks to pass: add **`Security gate`**, ✅ require branches to be up to date

The same thing in one command:

```bash
gh api -X POST repos/shahrryyar/securenotes-devsecops/rulesets --input - <<'JSON'
{"name":"Protect main","target":"branch","enforcement":"active",
 "conditions":{"ref_name":{"include":["~DEFAULT_BRANCH"],"exclude":[]}},
 "rules":[{"type":"deletion"},{"type":"non_fast_forward"},{"type":"required_linear_history"},
  {"type":"pull_request","parameters":{"required_approving_review_count":1,"dismiss_stale_reviews_on_push":true,
   "require_code_owner_review":true,"require_last_push_approval":false,"required_review_thread_resolution":true}},
  {"type":"required_status_checks","parameters":{"strict_required_status_checks_policy":true,
   "required_status_checks":[{"context":"Security gate"}]}}]}
JSON
```

This also raises the OpenSSF Scorecard *Branch-Protection* and *Code-Review* checks.

### 4. Each teammate, on their own machine

```bash
git clone https://github.com/shahrryyar/securenotes-devsecops.git
cd securenotes-devsecops
make install && make test
pip install pre-commit && pre-commit install
```

## For a brand-new copy

`scripts/setup_github.sh <repo-name> <teammate1> <teammate2>` does all of the above (including the ruleset and the demo PR) for a fresh repository.
