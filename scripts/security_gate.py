#!/usr/bin/env python3
"""Security gate: decide pass/fail for the pipeline from all scanner reports.

Usage:
  python scripts/security_gate.py --reports reports --policy security/policy.yml \
      [--summary $GITHUB_STEP_SUMMARY] [--output reports/gate.md]

The NEEDS environment variable (the `needs` context of the workflow as JSON)
lets the gate also fail when an upstream job such as the unit tests failed.
"""
import argparse
import datetime
import fnmatch
import json
import os
import sys
from collections import Counter
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import SEVERITIES, load_reports, severity_rank  # noqa: E402

MAX_LISTED = 40


def load_policy(path):
    with open(path, encoding="utf-8") as handle:
        policy = yaml.safe_load(handle)
    if policy.get("fail_on") not in SEVERITIES:
        raise SystemExit(f"policy: fail_on must be one of {SEVERITIES}")
    return policy


def threshold(policy, tool):
    return (policy.get("tools") or {}).get(tool, {}).get("fail_on", policy["fail_on"])


def apply_accepted_risks(findings, risks, today):
    """Drop findings covered by a valid accepted risk. Expired entries become errors."""
    errors, valid = [], []
    for risk in risks or []:
        expires = risk.get("expires")
        if not risk.get("reason") or not expires:
            errors.append(f"accepted risk {risk.get('tool')}/{risk.get('rule')} needs a reason and an expiry date")
        elif datetime.date.fromisoformat(str(expires)) < today:
            errors.append(f"accepted risk {risk['tool']}/{risk['rule']} expired on {expires}; review it again")
        else:
            valid.append(risk)

    kept, accepted = [], []
    for finding in findings:
        if any(_risk_matches(risk, finding) for risk in valid):
            accepted.append(finding)
        else:
            kept.append(finding)
    return kept, accepted, errors


def _risk_matches(risk, finding):
    return (
        risk.get("tool") == finding.tool
        and str(risk.get("rule")) == finding.rule
        and fnmatch.fnmatch(finding.path, risk.get("path", "*"))
    )


def failed_jobs():
    needs = json.loads(os.environ.get("NEEDS") or "{}")
    return sorted(name for name, job in needs.items() if job.get("result") in ("failure", "cancelled"))


def render(policy, findings, blocking, accepted, errors, jobs):
    passed = not (blocking or errors or jobs)
    lines = [
        f"## {'✅' if passed else '❌'} Security gate {'passed' if passed else 'FAILED'}",
        "",
        f"Policy: `security/policy.yml` (default threshold: **{policy['fail_on']}**). "
        f"{len(findings)} findings, {len(blocking)} blocking, {len(accepted)} accepted risks.",
        "",
        "| Tool | Critical | High | Medium | Low | Info | Fails on | Result |",
        "|---|---:|---:|---:|---:|---:|---|---|",
    ]
    for tool in policy["required_reports"]:
        counts = Counter(f.severity for f in findings if f.tool == tool)
        tool_blocking = sum(1 for f in blocking if f.tool == tool)
        missing = any(e.startswith(f"{tool}:") for e in errors)
        status = "⚠️ report missing" if missing else ("❌ blocked" if tool_blocking else "✅ pass")
        lines.append(
            f"| {tool} | {counts['critical']} | {counts['high']} | {counts['medium']} | "
            f"{counts['low']} | {counts['info']} | {threshold(policy, tool)} | {status} |"
        )

    if jobs:
        lines += ["", "### Failed pipeline jobs", ""] + [f"- `{job}`" for job in jobs]
    if errors:
        lines += ["", "### Gate errors (fail closed)", ""] + [f"- {error}" for error in errors]
    if blocking:
        lines += ["", "### Blocking findings", "", "| Severity | Tool | Rule | Location | Message |", "|---|---|---|---|---|"]
        ordered = sorted(blocking, key=lambda f: (-severity_rank(f.severity), f.tool, f.path, f.line))
        for f in ordered[:MAX_LISTED]:
            message = f.message.replace("|", "\\|")
            lines.append(f"| {f.severity} | {f.tool} | `{f.rule}` | `{f.location}` | {message} |")
        if len(ordered) > MAX_LISTED:
            lines.append(f"\n…and {len(ordered) - MAX_LISTED} more. Full details are in the Security tab and the report artifacts.")
    if accepted:
        lines += ["", "### Accepted risks applied", ""]
        lines += sorted({f"- `{f.tool}` / `{f.rule}`: {f.message}" for f in accepted})
    return passed, "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reports", default="reports")
    parser.add_argument("--policy", default="security/policy.yml")
    parser.add_argument("--summary", help="append the markdown summary to this file")
    parser.add_argument("--output", help="also write the markdown summary to this file")
    args = parser.parse_args()

    policy = load_policy(args.policy)
    findings, errors = load_reports(args.reports, policy["required_reports"])
    findings, accepted, risk_errors = apply_accepted_risks(
        findings, policy.get("accepted_risks"), datetime.date.today()
    )
    errors += risk_errors
    blocking = [f for f in findings if severity_rank(f.severity) >= severity_rank(threshold(policy, f.tool))]

    passed, markdown = render(policy, findings, blocking, accepted, errors, failed_jobs())
    print(markdown)
    for target in filter(None, (args.summary, args.output)):
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(markdown)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
