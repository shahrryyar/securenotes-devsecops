#!/usr/bin/env python3
"""Benchmark the scanners against the planted vulnerabilities (ground truth).

On the `vulnerable` branch every planted bug carries a `VULN-xx` marker comment.
This script finds those markers, matches each scanner finding to the bug it
belongs to, and prints a detection matrix plus recall / precision per tool.

On `main` there are no markers, so it only prints a note and exits.

Usage:
  python scripts/benchmark.py --reports reports --ground-truth security/ground-truth.yml
"""
import argparse
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import load_reports  # noqa: E402

DEFAULT_SPAN = 8  # lines after a marker that belong to the planted bug


def locate_markers(items, root):
    """Add `line` to each code item: the line number of its marker comment."""
    for item in items:
        item["line"] = None
        if not item.get("file") or not item.get("marker"):
            continue
        path = Path(root) / item["file"]
        if not path.is_file():
            continue
        for number, text in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if item["marker"] in text:
                item["line"] = number
                break
    return items


def matches(item, finding):
    if finding.tool in item.get("match_tools", []):
        return True
    if item.get("package"):
        haystack = f"{finding.rule} {finding.message} {finding.path}".lower()
        return re.search(rf"\b{re.escape(item['package'].lower())}\b", haystack) is not None
    if item.get("rules") and any(re.fullmatch(rule, finding.rule) for rule in item["rules"]):
        return True
    if item.get("line") and finding.path.endswith(item["file"]):
        return item["line"] <= finding.line <= item["line"] + item.get("span", DEFAULT_SPAN)
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reports", default="reports")
    parser.add_argument("--ground-truth", default="security/ground-truth.yml")
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", help="also write the markdown table to this file")
    args = parser.parse_args()

    with open(args.ground_truth, encoding="utf-8") as handle:
        truth = yaml.safe_load(handle)
    items = locate_markers(truth["vulnerabilities"], args.root)
    present = [i for i in items if i.get("line") or i.get("package") or i.get("rules") or i.get("match_tools")]
    if not any(i.get("line") for i in items):
        print("## Scanner benchmark\n\nNo `VULN-xx` markers found: this is the hardened branch, nothing to benchmark.")
        return 0

    tools = truth["tools"]
    findings, errors = load_reports(args.reports, {t: cfg["report"] for t, cfg in tools.items()})
    by_tool = {t: [f for f in findings if f.tool == t] for t in tools}

    detected = {(i["id"], t): any(matches(i, f) for f in by_tool[t]) for i in present for t in tools}

    lines = ["## Scanner benchmark against planted vulnerabilities", ""]
    lines.append("| ID | Vulnerability | CWE | OWASP 2025 | " + " | ".join(tools) + " |")
    lines.append("|---|---|---|---|" + "---|" * len(tools))
    for item in present:
        cells = []
        for tool, cfg in tools.items():
            in_scope = item["category"] in cfg["scope"]
            cells.append("✅" if detected[(item["id"], tool)] else ("❌" if in_scope else "·"))
        lines.append(f"| {item['id']} | {item['title']} | {item['cwe']} | {item['owasp']} | " + " | ".join(cells) + " |")
    lines += ["", "✅ detected · ❌ missed (in the tool's scope) · `·` outside the tool's scope", ""]

    lines += ["| Tool | Type | Detected (in scope) | Recall | Findings | Matched | Precision* |", "|---|---|---:|---:|---:|---:|---:|"]
    caught_by_any = set()
    for tool, cfg in tools.items():
        scoped = [i for i in present if i["category"] in cfg["scope"]]
        hits = [i for i in scoped if detected[(i["id"], tool)]]
        caught_by_any.update(i["id"] for i in present if detected[(i["id"], tool)])
        total = len(by_tool[tool])
        matched = sum(1 for f in by_tool[tool] if any(matches(i, f) for i in present))
        recall = f"{len(hits) / len(scoped):.0%}" if scoped else "-"
        precision = f"{matched / total:.0%}" if total else "-"
        lines.append(f"| {tool} | {cfg['type']} | {len(hits)}/{len(scoped)} | {recall} | {total} | {matched} | {precision} |")
    lines += [
        "",
        f"**Combined pipeline: {len(caught_by_any)}/{len(present)} planted vulnerabilities detected "
        f"({len(caught_by_any) / len(present):.0%}).**",
        "",
        "\\* Precision = findings that point at a planted bug ÷ all findings of that tool. "
        "Unmatched findings are either false positives or real extra issues, so review them by hand.",
    ]
    missed = [i for i in present if i["id"] not in caught_by_any]
    if missed:
        lines += ["", "Missed by every tool: " + ", ".join(f"{i['id']} ({i['title']})" for i in missed)]
    if errors:
        lines += ["", "Reports not available: " + "; ".join(errors)]

    markdown = "\n".join(lines) + "\n"
    print(markdown)
    if args.output:
        Path(args.output).write_text(markdown, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
