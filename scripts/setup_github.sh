#!/usr/bin/env bash
# One-time GitHub setup for the project. Run from the repository root:
#
#   scripts/setup_github.sh <repo-name> <teammate1-username> <teammate2-username>
#
# It creates a PUBLIC repository (code scanning and Scorecard are free for
# public repos), pushes `main` and `vulnerable`, turns on every GitHub security
# feature, protects `main` with a ruleset and opens the demo pull request.
# Requires: gh (logged in with `gh auth login`), git.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <repo-name> <teammate1-username> <teammate2-username>" >&2
  exit 2
fi
REPO_NAME=$1
MATE1=$2
MATE2=$3
OWNER=$(gh api user --jq .login)
REPO="$OWNER/$REPO_NAME"

step() { printf '\n==> %s\n' "$1"; }
warn() { printf 'WARNING: %s\n' "$1" >&2; }

step "Filling in CODEOWNERS with @$OWNER @$MATE1 @$MATE2"
for branch in main vulnerable; do
  git checkout -q "$branch"
  sed -i.bak -e "s/@MEMBER1/@$OWNER/g" -e "s/@MEMBER2/@$MATE1/g" -e "s/@MEMBER3/@$MATE2/g" .github/CODEOWNERS
  rm -f .github/CODEOWNERS.bak
  if ! git diff --quiet; then
    git commit -qam "chore: set code owners"
  fi
done
git checkout -q main

step "Creating public repository $REPO and pushing both branches"
gh repo create "$REPO" --public --source . --remote origin \
  --description "Automated security auditing (SAST, SCA, secrets, container, DAST) in a GitHub Actions DevSecOps pipeline"
git push -u origin main
git push -u origin vulnerable

step "Enabling Dependabot alerts and security updates"
gh api -X PUT "repos/$REPO/vulnerability-alerts" --silent
gh api -X PUT "repos/$REPO/automated-security-fixes" --silent

step "Enabling secret scanning and push protection"
gh api -X PATCH "repos/$REPO" --silent --input - <<'JSON'
{"security_and_analysis": {
  "secret_scanning": {"status": "enabled"},
  "secret_scanning_push_protection": {"status": "enabled"}
}}
JSON

step "Enabling private vulnerability reporting"
gh api -X PUT "repos/$REPO/private-vulnerability-reporting" --silent || warn "private vulnerability reporting not enabled"

step "Using the pipeline's CodeQL workflow instead of CodeQL default setup"
gh api -X PATCH "repos/$REPO/code-scanning/default-setup" -f state=not-configured --silent || true

step "Restricting GitHub Actions: read-only default token, SHA-pinned actions only"
gh api -X PUT "repos/$REPO/actions/permissions/workflow" --silent \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
gh api -X PUT "repos/$REPO/actions/permissions" --silent \
  -F enabled=true -f allowed_actions=selected -F sha_pinning_required=true \
  || gh api -X PUT "repos/$REPO/actions/permissions" --silent -F enabled=true -f allowed_actions=selected
gh api -X PUT "repos/$REPO/actions/permissions/selected-actions" --silent --input - <<'JSON'
{"github_owned_allowed": true, "verified_allowed": false, "patterns_allowed": ["ossf/scorecard-action@*"]}
JSON

step "Adding teammates as collaborators (they must accept the e-mail invitation)"
for mate in "$MATE1" "$MATE2"; do
  gh api -X PUT "repos/$REPO/collaborators/$mate" -f permission=push --silent || warn "could not invite $mate"
done

step "Protecting main with a ruleset"
gh api -X POST "repos/$REPO/rulesets" --silent --input - <<'JSON'
{
  "name": "Protect main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "required_linear_history"},
    {"type": "pull_request", "parameters": {
      "required_approving_review_count": 1,
      "dismiss_stale_reviews_on_push": true,
      "require_code_owner_review": true,
      "require_last_push_approval": true,
      "required_review_thread_resolution": true
    }},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": true,
      "required_status_checks": [{"context": "Security gate"}]
    }}
  ]
}
JSON

step "Opening the demo pull request (vulnerable -> main). Never merge it."
gh label create do-not-merge --repo "$REPO" --color B60205 --description "Teaching material only" 2>/dev/null || true
gh pr create --repo "$REPO" --base main --head vulnerable --label do-not-merge \
  --title "DEMO: 23 planted vulnerabilities - the security gate must block this" \
  --body "This pull request exists to prove the DevSecOps pipeline works. See docs/VULNERABILITIES.md and docs/DEMO-SCRIPT.md. **Do not merge.**"

step "Done"
echo "Repository:  https://github.com/$REPO"
echo "Pipeline:    https://github.com/$REPO/actions"
echo "Findings:    https://github.com/$REPO/security/code-scanning"
echo "Next: wait for the first pipeline run on main (about 10 minutes), then check the demo PR."
