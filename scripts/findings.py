"""Load scanner reports into one normalised list of findings.

Supported formats:
  * SARIF 2.1.0  - Semgrep, Bandit, CodeQL, Trivy, Gitleaks, Hadolint, zizmor
  * pip-audit JSON
  * OWASP ZAP JSON (`-J` report)

Every finding gets one of these severities: critical, high, medium, low, info.
"""
import json
import re
from dataclasses import dataclass
from pathlib import Path

SEVERITIES = ["info", "low", "medium", "high", "critical"]
SARIF_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}
BANDIT_SEVERITIES = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNDEFINED": "info"}
ZAP_RISKS = {"3": "high", "2": "medium", "1": "low", "0": "info"}

# Scanners running in Docker report paths such as file:///src/app/routes.py.
_PATH_PREFIX = re.compile(r"^(?:file://)?(?:/?(?:src|repo|zap/wrk)/|/?github/workspace/|.*/work/[^/]+/[^/]+/)")


class ReportError(Exception):
    """Raised when a report is missing or cannot be parsed."""


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str
    message: str
    path: str = ""
    line: int = 0

    @property
    def location(self):
        if not self.path:
            return "-"
        return f"{self.path}:{self.line}" if self.line else self.path


def severity_rank(severity):
    return SEVERITIES.index(severity)


def severity_from_score(score):
    """Map a CVSS-style 0-10 score (SARIF `security-severity`) to a severity name."""
    score = float(score)
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def normalise_path(uri):
    path = _PATH_PREFIX.sub("", uri or "")
    while path.startswith(("./", "/")):
        path = path[2:] if path.startswith("./") else path[1:]
    return path


def _first_line(text):
    return (text or "").strip().splitlines()[0][:200] if (text or "").strip() else ""


def _sarif_severity(result, rule):
    for props in (result.get("properties") or {}, rule.get("properties") or {}):
        if "security-severity" in props:
            try:
                return severity_from_score(props["security-severity"])
            except (TypeError, ValueError):
                pass
        if props.get("issue_severity") in BANDIT_SEVERITIES:
            return BANDIT_SEVERITIES[props["issue_severity"]]
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return SARIF_LEVELS.get(level, "medium")


def load_sarif(tool, path):
    data = _read_json(path)
    findings = []
    for run in data.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        rule_list = list(driver.get("rules") or [])
        for ext in run.get("tool", {}).get("extensions") or []:
            rule_list.extend(ext.get("rules") or [])
        rules = {r.get("id"): r for r in rule_list}
        for result in run.get("results") or []:
            if any(s.get("status", "accepted") == "accepted" for s in result.get("suppressions") or []):
                continue  # suppressed in source (e.g. `# nosemgrep`) with a review trail
            rule_id = result.get("ruleId")
            if rule_id is None and "ruleIndex" in result and result["ruleIndex"] < len(driver.get("rules") or []):
                rule_id = driver["rules"][result["ruleIndex"]].get("id")
            rule = rules.get(rule_id, {})
            location = ((result.get("locations") or [{}])[0]).get("physicalLocation", {})
            findings.append(
                Finding(
                    tool=tool,
                    rule=str(rule_id or "unknown"),
                    severity=_sarif_severity(result, rule),
                    message=_first_line(result.get("message", {}).get("text")),
                    path=normalise_path(location.get("artifactLocation", {}).get("uri")),
                    line=int(location.get("region", {}).get("startLine") or 0),
                )
            )
    return findings


def load_pip_audit(tool, path):
    data = _read_json(path)
    findings = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            aliases = ", ".join(vuln.get("aliases") or [])
            fixes = ", ".join(vuln.get("fix_versions") or []) or "none"
            findings.append(
                Finding(
                    tool=tool,
                    rule=vuln.get("id", "unknown"),
                    # pip-audit does not rate severity: an unrated known vulnerability is treated as high.
                    severity="high",
                    message=f"{dep['name']} {dep.get('version', '?')} is vulnerable ({aliases}); fixed in {fixes}",
                    path="requirements.txt",
                )
            )
    return findings


def load_zap(tool, path):
    data = _read_json(path)
    findings = []
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            if str(alert.get("confidence")) == "0":
                continue  # ZAP marks these as false positives
            instances = alert.get("instances") or [{}]
            findings.append(
                Finding(
                    tool=tool,
                    rule=str(alert.get("pluginid", "unknown")),
                    severity=ZAP_RISKS.get(str(alert.get("riskcode")), "medium"),
                    message=f"{alert.get('alert') or alert.get('name')} ({len(instances)} URLs)",
                    path=instances[0].get("uri", ""),
                )
            )
    return findings


def load_report(tool, path):
    path = Path(path)
    if not path.is_file():
        raise ReportError(f"{tool}: report {path} is missing")
    if tool == "pip-audit":
        return load_pip_audit(tool, path)
    if tool == "zap":
        return load_zap(tool, path)
    return load_sarif(tool, path)


def load_reports(reports_dir, required):
    """Load every report in `required` ({tool: relative path}). Returns (findings, errors)."""
    findings, errors = [], []
    for tool, relpath in required.items():
        try:
            findings.extend(load_report(tool, Path(reports_dir) / relpath))
        except ReportError as exc:
            errors.append(str(exc))
    return findings, errors


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise ReportError(f"cannot read {path}: {exc}") from exc
