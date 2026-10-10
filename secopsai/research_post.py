"""Building blocks for publication-grade research posts.

A research post should let a reader act in the first screen and verify
everything after it:

- a TL;DR with what happened, who is affected, what to do and current status;
- affected packages with registry status;
- a takedown tracker built from the case timeline and disclosures;
- a graded confidence statement that separates confirmed facts from
  assessment;
- a MITRE ATT&CK mapping that cites the evidence behind each technique;
- machine-readable IOC exports (JSON, CSV, STIX 2.1).

Everything here is derived from the research case; nothing is inferred
beyond what the case records, and every mapping says which evidence
triggered it.
"""

from __future__ import annotations

import csv
import io
import json
import re
import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

STIX_NAMESPACE = uuid.UUID("6f1a3c2e-5b0d-4c8e-9a51-7d2f0e4b9c13")
IDENTITY_ID = "identity--" + str(uuid.uuid5(STIX_NAMESPACE, "SecOpsAI Research"))

# Grades follow the words analysts already use; thresholds are the case's
# calibrated confidence, and "confirmed" also needs a recorded malicious
# verdict (a person's decision, not a score).
GRADES: Tuple[Tuple[int, str, str], ...] = (
    (90, "Confirmed", "Malicious behaviour is directly observed in the published artifact and a reviewer has recorded a malicious verdict."),
    (75, "High confidence", "Multiple independent indicators agree and no benign explanation fits the evidence."),
    (50, "Moderate confidence", "The evidence is consistent with malicious intent, but a benign explanation has not been ruled out."),
    (0, "Low confidence", "Early signals only; published to warn, and subject to revision."),
)
MALICIOUS_VERDICTS = {"malicious", "confirmed_malicious", "true_positive", "compromised"}

# (technique id, name, tactic, trigger pattern).  Patterns are matched against
# the case's evidence, IOC tags and summary; the first matching term is cited.
ATTACK_TECHNIQUES: Tuple[Tuple[str, str, str, str], ...] = (
    ("T1195.002", "Compromise Software Supply Chain", "Initial Access", r"\b(package|npm|pypi|registry|maintainer|typosquat|dependency)\b"),
    ("T1059.001", "PowerShell", "Execution", r"\b(powershell|pwsh|invoke-expression|iex)\b"),
    ("T1059.004", "Unix Shell", "Execution", r"\b(bash|/bin/sh|sh -c|curl[^|\n]{0,80}\|\s*(ba)?sh)\b"),
    ("T1059.006", "Python", "Execution", r"\b(setup\.py|cmdclass|exec\(|python -c)"),
    ("T1059.007", "JavaScript", "Execution", r"\b(postinstall|preinstall|child_process|node -e|eval\()"),
    ("T1105", "Ingress Tool Transfer", "Command and Control", r"\b(download(s|ed|string|file)?|invoke-webrequest|wget|curl|second[- ]stage|payload)\b"),
    ("T1027", "Obfuscated Files or Information", "Defense Evasion", r"\b(obfuscat\w*|base64|encoded|packed|xor)\b"),
    ("T1552.001", "Credentials In Files", "Credential Access", r"(\.npmrc|\.pypirc|\.aws/credentials|\.ssh/|\.env\b|wallet)"),
    ("T1552", "Unsecured Credentials", "Credential Access", r"\b(credential|token|secret|api[_ -]?key|environment variables?|process\.env|os\.environ)\b"),
    ("T1082", "System Information Discovery", "Discovery", r"\b(hostname|whoami|os\.platform|platform\.node|system info\w*|username)\b"),
    ("T1567.004", "Exfiltration Over Webhook", "Exfiltration", r"\b(discord(app)?\.com/api/webhooks|webhook)\b"),
    ("T1567", "Exfiltration Over Web Service", "Exfiltration", r"\b(api\.telegram\.org|pastebin|exfiltrat\w*)\b"),
    ("T1071.001", "Web Protocols", "Command and Control", r"\b(c2|command[- ]and[- ]control|beacon\w*)\b"),
    ("T1071.004", "DNS", "Command and Control", r"\b(dns (exfil\w*|tunnel\w*)|dns query|interactsh|oast)\b"),
    ("T1547.001", "Registry Run Keys / Startup Folder", "Persistence", r"(currentversion\\run|startup folder)"),
    ("T1543.001", "Launch Agent", "Persistence", r"\b(launchagents?|launchctl)\b"),
    ("T1053.003", "Cron", "Persistence", r"\b(crontab|cron job)\b"),
)

STIX_PATTERNS = {
    "domain": "[domain-name:value = '{v}']",
    "hostname": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "ipv4": "[ipv4-addr:value = '{v}']",
    "ip": "[ipv4-addr:value = '{v}']",
    "ipv6": "[ipv6-addr:value = '{v}']",
    "email": "[email-addr:value = '{v}']",
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "sha1": "[file:hashes.'SHA-1' = '{v}']",
    "md5": "[file:hashes.MD5 = '{v}']",
}


def _active(items: Any) -> List[Dict[str, Any]]:
    return [item for item in items or [] if isinstance(item, dict) and item.get("status", "active") == "active"]


def _date(value: Any) -> str:
    return str(value or "")[:10] or "—"


def _cell(value: Any) -> str:
    return str(value if value not in (None, "") else "—").replace("|", "\\|").replace("\n", " ")


def packages(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [item for item in _active(case.get("subjects")) if item.get("subject_type") in {"package", "extension"}]


def latest_verdict(case: Dict[str, Any]) -> Dict[str, Any]:
    verdicts = [item for item in case.get("verdicts") or [] if isinstance(item, dict)]
    return max(verdicts, key=lambda item: str(item.get("created_at") or ""), default={})


def confidence_grade(case: Dict[str, Any]) -> Dict[str, Any]:
    """Graded confidence: label, criteria and the numbers behind it."""
    score = int(case.get("confidence") or 0)
    verdict = latest_verdict(case)
    confirmed = str(verdict.get("verdict") or "").lower() in MALICIOUS_VERDICTS
    for threshold, label, criteria in GRADES:
        if score >= threshold and (label != "Confirmed" or confirmed):
            return {"label": label, "criteria": criteria, "score": score,
                    "verdict": verdict.get("verdict") or "", "verdict_rationale": verdict.get("rationale") or ""}
    return {"label": GRADES[-1][1], "criteria": GRADES[-1][2], "score": score, "verdict": "", "verdict_rationale": ""}


def _evidence_text(case: Dict[str, Any]) -> List[Tuple[str, str]]:
    """(source label, text) pairs the ATT&CK mapping may cite."""
    sources: List[Tuple[str, str]] = [("case summary", str(case.get("summary") or ""))]
    for item in packages(case):
        sources.append((f"affected package {item.get('name')}@{item.get('version') or '*'}", f"{item.get('ecosystem')} package {item.get('name')}"))
    for item in _active(case.get("evidence")):
        sources.append((f"evidence: {item.get('title') or item.get('evidence_type')}", f"{item.get('title') or ''} {item.get('notes') or ''}"))
    for item in _active(case.get("iocs")):
        sources.append((f"IOC ({item.get('ioc_type')})", f"{item.get('value') or ''} {' '.join(map(str, item.get('tags') or []))}"))
    for item in case.get("rules") or []:
        if isinstance(item, dict):
            sources.append((f"detection rule {item.get('name')}", f"{item.get('name') or ''} {item.get('description') or ''}"))
    return sources


def attack_mapping(case: Dict[str, Any]) -> List[Dict[str, str]]:
    """Techniques supported by the case's own evidence, each with its citation."""
    sources = _evidence_text(case)
    mapped: List[Dict[str, str]] = []
    for technique, name, tactic, pattern in ATTACK_TECHNIQUES:
        if technique == "T1552" and any(item["technique"] == "T1552.001" for item in mapped):
            continue  # the sub-technique already covers it
        if technique == "T1567" and any(item["technique"] == "T1567.004" for item in mapped):
            continue
        for label, text in sources:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                mapped.append({"technique": technique, "name": name, "tactic": tactic, "evidence": label, "term": match.group(0)[:60]})
                break
    return mapped


def takedown_rows(case: Dict[str, Any]) -> List[Dict[str, str]]:
    """Dated status rows: discovery, disclosure, registry action, publication."""
    rows = [{"date": _date(case.get("created_at")), "event": "Discovered by SecOpsAI", "status": "done"}]
    for item in sorted((d for d in case.get("disclosures") or [] if isinstance(d, dict)), key=lambda d: str(d.get("sent_at") or d.get("created_at") or "")):
        sent = bool(item.get("sent_at"))
        rows.append({"date": _date(item.get("sent_at") or item.get("created_at")),
                     "event": f"Reported to {item.get('recipient') or 'the registry'}",
                     "status": "sent" if sent else str(item.get("status") or "drafted")})
    for item in packages(case):
        state = str(item.get("registry_state") or "unknown")
        label = {"removed": "Removed from the registry", "unlisted": "Unlisted by the registry", "unavailable": "Unavailable on the registry",
                 "available": "Still available on the registry"}.get(state, "Registry status not yet checked")
        rows.append({"date": _date(item.get("state_checked_at")), "event": f"{label}: {item.get('name')}@{item.get('version') or '*'}",
                     "status": "done" if state in {"removed", "unlisted"} else ("open" if state == "available" else "pending")})
    metadata = case.get("metadata") or {}
    if metadata.get("osv_id"):
        rows.append({"date": _date(metadata.get("osv_published_at")), "event": f"OSV advisory {metadata['osv_id']}", "status": "done"})
    return rows


def takedown_summary(case: Dict[str, Any]) -> str:
    states = [str(item.get("registry_state") or "unknown") for item in packages(case)]
    if not states:
        return "No registry packages are involved."
    removed = sum(state in {"removed", "unlisted"} for state in states)
    live = sum(state == "available" for state in states)
    if removed == len(states):
        return "All affected packages have been removed from the registry."
    if live:
        return f"{live} of {len(states)} affected package versions are still live on the registry; takedown requested." if any(
            (d or {}).get("sent_at") for d in case.get("disclosures") or []) else f"{live} of {len(states)} affected package versions are still live on the registry."
    return f"{removed} of {len(states)} affected package versions have been removed; the rest have not been re-checked."


def recommended_actions(case: Dict[str, Any]) -> List[str]:
    ecosystems = {str(item.get("ecosystem") or "").lower() for item in packages(case)}
    names = [str(item.get("name")) for item in packages(case)][:3]
    actions: List[str] = []
    if "npm" in ecosystems:
        for name in names:
            actions.append(f"Check whether `{name}` is installed anywhere: `npm ls {name}` in each project, and search lockfiles for it.")
        actions.append("Remove the affected versions, pin to a known-good version, and reinstall with `npm ci --ignore-scripts` until the lockfile is clean.")
    if "pypi" in ecosystems:
        for name in names:
            actions.append(f"Check environments for `{name}`: `pip show {name}` and search `requirements*.txt`, `poetry.lock` and `uv.lock`.")
        actions.append("Uninstall the affected versions and rebuild virtual environments from a pinned, verified lockfile.")
    if any(item["tactic"] == "Credential Access" for item in attack_mapping(case)):
        actions.append("If an affected version was installed, treat credentials reachable from that machine or CI runner as exposed: rotate registry tokens, cloud keys and SSH keys.")
    if _active(case.get("iocs")):
        actions.append("Block the network indicators below and search proxy, DNS and EDR telemetry for them from the earliest publish date.")
    actions.append("Preserve affected lockfiles, build logs and artifacts with timestamps before cleaning up.")
    return actions


def tldr(case: Dict[str, Any], grade: Dict[str, Any]) -> List[str]:
    affected = packages(case)
    versions: Dict[str, List[str]] = {}
    for item in affected:
        versions.setdefault(str(item.get("name")), []).append(str(item.get("version") or "*"))
    shown = [f"`{name}` {', '.join(found)}" for name, found in list(versions.items())[:4]]
    names = "; ".join(shown) + (f"; and {len(versions) - 4} more packages" if len(versions) > 4 else "")
    # The summary is already the post's standfirst; the TL;DR adds what to act on.
    lines: List[str] = []
    if affected:
        ecosystems = sorted({str(item.get("ecosystem") or "") for item in affected if item.get("ecosystem")})
        lines.append(f"**Affected:** {names} ({', '.join(ecosystems)}).")
    lines.append(f"**Assessment:** {grade['label']} — {grade['criteria']}")
    lines.append(f"**Status:** {takedown_summary(case)}")
    actions = recommended_actions(case)
    if actions:
        lines.append(f"**Do now:** {actions[0]}")
    return [line for line in lines if line]


# --------------------------------------------------------------- IOC exports
def _ioc_rows(case: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for item in _active(case.get("iocs")):
        value = str(item.get("value") or "").strip()
        kind = str(item.get("ioc_type") or "other").lower()
        if kind in {"md5", "sha1", "sha256"}:
            value = value.lower()
        if value:
            rows.append({"type": kind, "value": value, "confidence": int(item.get("confidence") or 0),
                         "first_seen": item.get("first_seen") or "", "last_seen": item.get("last_seen") or "",
                         "tags": [str(tag) for tag in item.get("tags") or []]})
    for item in packages(case):
        rows.append({"type": f"{str(item.get('ecosystem') or 'package').lower()}-package", "value": f"{item.get('name')}@{item.get('version') or '*'}",
                     "confidence": int(case.get("confidence") or 0), "first_seen": "", "last_seen": "", "tags": ["affected-package"]})
    return rows


def _stix_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def ioc_exports(case: Dict[str, Any], *, generated_at: str, post_url: str = "") -> Dict[str, str]:
    """IOC files keyed by extension: json, csv, stix.json."""
    rows = _ioc_rows(case)
    case_id = str(case.get("case_id") or "")
    payload = {"schema": "secopsai.research.iocs.v1", "case_id": case_id, "title": case.get("title"), "generated_at": generated_at,
               "source": post_url, "confidence": confidence_grade(case)["label"], "indicators": rows}
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(["type", "value", "confidence", "first_seen", "last_seen", "tags"])
    for row in rows:
        writer.writerow([row["type"], row["value"], row["confidence"], row["first_seen"], row["last_seen"], ";".join(row["tags"])])
    created = (str(case.get("created_at") or generated_at)[:19] + "Z") if "T" in str(case.get("created_at") or "") else generated_at
    objects: List[Dict[str, Any]] = [{"type": "identity", "spec_version": "2.1", "id": IDENTITY_ID, "created": created, "modified": created,
                                      "name": "SecOpsAI Research", "identity_class": "organization"}]
    indicator_ids = []
    for row in rows:
        if row["type"].endswith("-package"):
            name, _, version = row["value"].rpartition("@")
            pattern = f"[software:name = '{_stix_escape(name)}'" + (f" AND software:version = '{_stix_escape(version)}']" if version and version != "*" else "]")
        elif row["type"] in STIX_PATTERNS:
            pattern = STIX_PATTERNS[row["type"]].format(v=_stix_escape(row["value"].lower() if row["type"] in {"sha256", "sha1", "md5"} else row["value"]))
        else:
            continue
        indicator_id = "indicator--" + str(uuid.uuid5(STIX_NAMESPACE, f"{case_id}|{row['type']}|{row['value']}"))
        indicator_ids.append(indicator_id)
        objects.append({"type": "indicator", "spec_version": "2.1", "id": indicator_id, "created": created, "modified": generated_at,
                        "created_by_ref": IDENTITY_ID, "name": f"{row['type']}: {row['value']}"[:250], "pattern": pattern, "pattern_type": "stix",
                        "valid_from": (str(row["first_seen"])[:19] + "Z") if "T" in str(row["first_seen"]) else created,
                        "indicator_types": ["malicious-activity"], "confidence": row["confidence"], "labels": row["tags"][:10]})
    report_id = "report--" + str(uuid.uuid5(STIX_NAMESPACE, case_id or "case"))
    objects.append({"type": "report", "spec_version": "2.1", "id": report_id, "created": created, "modified": generated_at,
                    "created_by_ref": IDENTITY_ID, "name": str(case.get("title") or case_id)[:250], "published": generated_at,
                    "report_types": ["threat-report"], "object_refs": indicator_ids or [IDENTITY_ID],
                    "external_references": [{"source_name": "SecOpsAI", "url": post_url}] if post_url else []})
    bundle = {"type": "bundle", "id": "bundle--" + str(uuid.uuid5(STIX_NAMESPACE, f"{case_id}|{generated_at}")), "objects": objects}
    return {"json": json.dumps(payload, indent=2, sort_keys=True), "csv": out.getvalue(), "stix.json": json.dumps(bundle, indent=2, sort_keys=True)}


# ----------------------------------------------------------------- markdown
def render_sections(case: Dict[str, Any], *, ioc_links: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Markdown for each structured section, keyed by section name."""
    grade = confidence_grade(case)
    affected = packages(case)
    package_lines = ["| Ecosystem | Package | Version | Publisher | Registry status |", "| --- | --- | --- | --- | --- |"] + [
        f"| {_cell(item.get('ecosystem'))} | `{_cell(item.get('name'))}` | `{_cell(item.get('version'))}` | {_cell(item.get('publisher'))} | {_cell(item.get('registry_state') or 'unknown')} |"
        for item in affected
    ]
    tracker = ["| Date | Event | Status |", "| --- | --- | --- |"] + [f"| {row['date']} | {_cell(row['event'])} | {row['status']} |" for row in takedown_rows(case)]
    mapping = attack_mapping(case)
    attack = ["| Tactic | Technique | Evidence |", "| --- | --- | --- |"] + [
        f"| {item['tactic']} | {item['technique']} {item['name']} | {_cell(item['evidence'])} (`{_cell(item['term'])}`) |" for item in mapping
    ]
    iocs = [row for row in _ioc_rows(case) if not row["type"].endswith("-package")]
    ioc_table = ["| Type | Indicator | Confidence |", "| --- | --- | --- |"] + [f"| {row['type']} | `{_cell(row['value'])}` | {row['confidence']} |" for row in iocs[:60]]
    downloads = ""
    if ioc_links:
        downloads = "Download the indicators: " + " · ".join(f"[{label}]({url})" for label, url in ioc_links.items())
    rules = [item for item in case.get("rules") or [] if isinstance(item, dict)]
    assessment = [f"**{grade['label']}** (calibrated score {grade['score']}/100). {grade['criteria']}"]
    if grade.get("verdict"):
        assessment.append(f"Recorded verdict: `{grade['verdict']}`." + (f" {grade['verdict_rationale']}" if grade.get("verdict_rationale") else ""))
    return {
        "tldr": "\n".join(f"- {line}" for line in tldr(case, grade)),
        "affected": "\n".join(package_lines) if affected else "- No registry packages are involved.",
        "tracker": "\n".join(tracker),
        "assessment": "\n\n".join(assessment),
        "attack": "\n".join(attack) if mapping else "- No ATT&CK techniques are supported by the recorded evidence yet.",
        "iocs": ("\n".join(ioc_table) if iocs else "- No network or file indicators were identified.") + (f"\n\n{downloads}" if downloads else ""),
        "detection": "\n".join(f"- `{item.get('rule_type') or 'rule'}` {item.get('name')}" for item in rules[:12]) or "- Detection content for this case is in review.",
        "actions": "\n".join(f"- {line}" for line in recommended_actions(case)),
    }


def iter_ioc_files(slug: str, exports: Dict[str, str]) -> Iterable[Tuple[str, str]]:
    for extension, content in exports.items():
        yield f"{slug}.{extension}", content
