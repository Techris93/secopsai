"""Vulnerability research desk: rank collected advisories and check their claims.

The primary-intel collector stores every advisory it sees (thousands a week),
each waiting for human verification.  The desk turns that into a short daily
list a single operator can act on:

1. **Rank.**  Advisories are grouped by CVE across sources and scored on
   severity, exploitation, remote/unauthenticated impact, the technologies
   SecOpsAI users run (rules/watchlists/desk-technologies.txt), whether a
   primary (non-aggregator) source reports it, and how many sources do.
2. **Check claims.**  For shortlisted CVEs the desk fetches the CVE record
   (cve.org) and NVD's scoring and compares them with what the sources say:
   the identifier exists and is published, the reported CVSS matches, and
   exploitation is confirmed by CISA KEV or only reported.  Every claim keeps
   its source; a mismatch is shown, never silently resolved.

Nothing here verifies or publishes.  A human still records the verification
(``event-verify``) and approves every publication; the desk decides what they
look at first and pre-checks the facts they need.
"""
from __future__ import annotations

import html
import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from secopsai.research_operation_store import append, read_connection, records

ROOT = Path(__file__).resolve().parents[1]
TECHNOLOGIES = ROOT / "rules" / "watchlists" / "desk-technologies.txt"
INVENTORY = ROOT / "rules" / "watchlists" / "desk-inventory.txt"
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
# The score must not be followed by "/": "CVSS:3.1/AV:N/..." is a vector
# string whose 3.1 is the CVSS version, not a score.
CVSS_RE = re.compile(r"CVSS(?:\s*(?:v?[234](?:\.\d)?|score|base score|rating))*\s*(?:of|:|=|is)?\s*(\d{1,2}(?:\.\d)?)\b(?![./\d])", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]{0,500}>")
# An entry with none of these is a release or listing, not an advisory
# (e.g. an Open VSX extension described as handling "critical" data).
SECURITY_RE = re.compile(r"vulnerab|exploit|security|advisor|\bCVSS\b|\bCVE-|\bGHSA-|remote code execution|\bRCE\b|malicious|malware|compromise|backdoor|patch", re.IGNORECASE)
EXPLOITED_RE = re.compile(r"actively exploited|exploited in the wild|under active exploitation|in-the-wild exploitation|"
                          r"exploit(?:ation)? attempts|(?:tried|attempts?|attempting) to exploit|being exploited|"
                          r"exploitation (?:activity|has been) (?:observed|detected)|zero-day|0-day|known exploited", re.IGNORECASE)
RCE_RE = re.compile(r"remote code execution|\bRCE\b|arbitrary code execution|execute arbitrary code", re.IGNORECASE)
SEVERITY_RE = re.compile(r"\b(critical|high)[- ]severity\b|\bcritical\b", re.IGNORECASE)
# Coined vulnerability names (PHP2Shell, Log4Shell, CitrixBleed); PowerShell is a product.
NAMED_RE = re.compile(r"\b(?:[A-Za-z]+\d[A-Za-z]*(?:Shell|Bleed|Leak|Hole|Pwn)|[A-Z][a-z]+(?:Shell|Bleed|Leak|Hole|Pwn))\b")
NOT_NAMES = {"PowerShell", "Powershell", "Shell"}
LINK_WINDOW_DAYS = 3
UNAUTH_RE = re.compile(r"unauthenticated|pre-auth(?:entication)?|without authentication|no authentication", re.IGNORECASE)
WINDOW_DAYS = 14
CLAIM_CHECK_TTL_HOURS = 6
CLAIMS_KIND = "desk_claim_check"
CVE_RECORD_URL = "https://cveawg.mitre.org/api/cve/{cve}"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
CLAIM_SOURCE_HOSTS = ("cveawg.mitre.org", "services.nvd.nist.gov")


def technologies(path: Path = TECHNOLOGIES) -> dict[str, re.Pattern]:
    patterns = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, _, keywords = line.partition(":")
        words = [re.escape(word.strip()) for word in keywords.split(",") if word.strip()]
        if not name.strip() or not words:
            raise ValueError(f"invalid desk technology line: {line!r}")
        patterns[name.strip()] = re.compile(r"(?<![\w.-])(?:" + "|".join(words) + r")(?![\w-])", re.IGNORECASE)
    return patterns


def inventory(path: Path = INVENTORY) -> set[str]:
    """Technologies this deployment runs (names from desk-technologies.txt)."""
    known = set(technologies())
    names = {line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8").splitlines()} - {""}
    unknown = names - known
    if unknown:
        raise ValueError(f"desk inventory names unknown technologies: {sorted(unknown)}")
    return names


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def dependencies(root: Path = ROOT) -> set[tuple[str, str]]:
    """(ecosystem, package) pairs this repository depends on directly."""
    found: set[tuple[str, str]] = set()
    for path in root.glob("requirements*.txt"):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line.split("#", 1)[0])
            if match and not line.strip().startswith("-"):
                found.add(("pip", _normalize(match.group(1))))
    # Only the repository's own manifests (fixtures and samples hold
    # malicious package manifests that are not dependencies).
    for path in [root / "package.json", *root.glob("cloudflare/*/package.json")]:
        if not path.is_file():
            continue
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for key in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            found.update(("npm", name.lower()) for name in (manifest.get(key) or {}))
    return found


def signals(title: str, excerpt: str, *, techs: Optional[dict[str, re.Pattern]] = None) -> dict[str, Any]:
    """Facts a source states about an advisory; reported, not verified."""
    # Vendor feeds are HTML: "<strong>CVSS</strong> 10.0" hides the score.
    text = html.unescape(TAG_RE.sub(" ", f"{title}\n{excerpt}"))
    scores = [float(match) for match in CVSS_RE.findall(text) if 0 < float(match) <= 10]
    techs = techs if techs is not None else technologies()
    severity = SEVERITY_RE.search(text)
    return {
        "cves": sorted({cve.upper() for cve in CVE_RE.findall(text)}),
        "names": sorted({name for name in NAMED_RE.findall(text) if name not in NOT_NAMES}),
        "reported_cvss": max(scores) if scores else None,
        "reported_severity": ("critical" if severity and "critical" in severity.group(0).lower() else "high") if severity else None,
        "reported_exploited": bool(EXPLOITED_RE.search(text)),
        "remote_code_execution": bool(RCE_RE.search(text)),
        "unauthenticated": bool(UNAUTH_RE.search(text)),
        "technologies": sorted(name for name, pattern in techs.items() if pattern.search(text)),
    }


def score(cluster: dict[str, Any]) -> int:
    """Priority for human attention (0-100); explained by ``score_reasons``."""
    value = 0
    cvss = cluster.get("reported_cvss") or 0
    if not cvss:  # a vendor's "Critical" without a number
        cvss = {"critical": 9.0, "high": 7.0}.get(cluster.get("reported_severity") or "", 0)
    value += 30 if cvss >= 9 else 20 if cvss >= 7 else 0
    value += 25 if cluster.get("kev") else 15 if cluster.get("reported_exploited") else 0
    value += 10 if cluster.get("remote_code_execution") else 0
    value += 5 if cluster.get("unauthenticated") else 0
    value += 15 if cluster.get("technologies") else 0
    value += 10 if cluster.get("deployment_exposure") else 0
    value += 10 if cluster.get("primary_source") else 0
    value += min(5, len(cluster.get("sources") or []))
    return min(100, value)


def _score_reasons(cluster: dict[str, Any]) -> list[str]:
    reasons = []
    if cluster.get("reported_cvss"):
        reasons.append(f"reported CVSS {cluster['reported_cvss']}")
    elif cluster.get("reported_severity"):
        reasons.append(f"reported {cluster['reported_severity']} severity")
    if cluster.get("kev"):
        reasons.append("listed in CISA Known Exploited Vulnerabilities")
    elif cluster.get("reported_exploited"):
        reasons.append("exploitation reported (not confirmed by CISA KEV)")
    if cluster.get("remote_code_execution"):
        reasons.append("remote code execution")
    if cluster.get("unauthenticated"):
        reasons.append("no authentication required")
    if cluster.get("technologies"):
        reasons.append("affects " + ", ".join(cluster["technologies"]))
    if cluster.get("deployment_exposure"):
        reasons.append("this deployment runs " + ", ".join(cluster["deployment_exposure"]))
    reasons.append(("primary source" if cluster.get("primary_source") else "aggregator only") + f", {len(cluster.get('sources') or [])} source(s)")
    if cluster.get("linked"):
        reasons.append("related reports linked by " + "; ".join(sorted({link["linked_by"] for link in cluster["linked"]})))
    return reasons


def advisory_date(event: dict[str, Any]) -> str:
    """When the advisory itself was published or updated, not when we saw it.

    Feeds such as CISA KEV and php.net carry years of history that is all
    collected at once; ranking by collection time would flood the desk.
    """
    payload = event["payload"]
    for value in (payload.get("source_updated_at"), payload.get("published_at"), event.get("published_at"),
                  payload.get("catalog_added_at")):
        if value:
            return str(value)
    return str(event.get("first_observed_at") or "")


def _events(db_path, *, since: str) -> Iterable[dict[str, Any]]:
    with read_connection(db_path) as conn:
        rows = conn.execute(
            """SELECT e.event_id,e.source_id,e.published_at,e.first_observed_at,e.payload_json,s.config_json
               FROM research_intel_events e JOIN research_intel_sources s USING(source_id)
               WHERE e.first_observed_at>=? OR e.published_at>=?""", (since, since)).fetchall()
    for row in rows:
        event = {"event_id": row["event_id"], "source_id": row["source_id"], "published_at": row["published_at"],
                 "first_observed_at": row["first_observed_at"], "payload": json.loads(row["payload_json"]),
                 "source": json.loads(row["config_json"])}
        if advisory_date(event) >= since:
            yield event


def _new_item(key: str, label: str) -> dict[str, Any]:
    return {"key": key, "label": label, "cves": [], "names": set(), "event_ids": [], "sources": [], "titles": [],
            "primary_event_ids": [], "reported_cvss": None, "reported_severity": None, "reported_exploited": False,
            "kev": False, "remote_code_execution": False, "unauthenticated": False, "technologies": set(), "linked": []}


def _absorb(item: dict[str, Any], event: dict[str, Any], found: dict[str, Any]) -> None:
    payload, source = event["payload"], event["source"]
    if event["event_id"] not in item["event_ids"]:
        item["event_ids"].append(event["event_id"])
        item["titles"].append(str(payload.get("title") or "")[:300])
    if source["name"] not in item["sources"]:
        item["sources"].append(source["name"])
    if source.get("source_class") != "aggregator" and event["event_id"] not in item["primary_event_ids"]:
        item["primary_event_ids"].append(event["event_id"])
    if source.get("parser") == "cisa_kev":
        item["kev"] = True
    if found["reported_cvss"] and (item["reported_cvss"] or 0) < found["reported_cvss"]:
        item["reported_cvss"] = found["reported_cvss"]
    if found["reported_severity"] == "critical" or (found["reported_severity"] and not item["reported_severity"]):
        item["reported_severity"] = found["reported_severity"]
    for key in ("reported_exploited", "remote_code_execution", "unauthenticated"):
        item[key] = item[key] or found[key]
    item["technologies"].update(found["technologies"])
    item["names"].update(found["names"])
    first = event["first_observed_at"]
    item["first_observed_at"] = min(item.get("first_observed_at") or first, first)
    dated = advisory_date(event)
    item["advisory_date"] = max(item.get("advisory_date") or dated, dated)
    item["earliest_date"] = min(item.get("earliest_date") or dated, dated)


def _days_apart(a: dict[str, Any], b: dict[str, Any]) -> float:
    def parse(value: str) -> Optional[datetime]:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None
        except ValueError:
            return None
    pairs = [(parse(a.get("earliest_date", "")), parse(b.get("advisory_date", ""))), (parse(b.get("earliest_date", "")), parse(a.get("advisory_date", "")))]
    if any(x is None or y is None for x, y in pairs):
        return float("inf")
    a_start, a_end = parse(a["earliest_date"]), parse(a["advisory_date"])
    b_start, b_end = parse(b["earliest_date"]), parse(b["advisory_date"])
    if a_end < b_start:
        return (b_start - a_end).total_seconds() / 86400
    if b_end < a_start:
        return (a_start - b_end).total_seconds() / 86400
    return 0.0


def clusters(*, db_path=None, now: Optional[datetime] = None, window_days: int = WINDOW_DAYS) -> list[dict[str, Any]]:
    """Advisories in the window grouped into desk items, ranked for human attention.

    An item is keyed by CVE.  Reports without a CVE (news coverage, vendor
    release posts) are grouped by a coined vulnerability name (PHP2Shell) or,
    for a watched technology, by technology and day, and then linked to a CVE
    item that shares a technology and code-execution impact within three
    days.  Every such link is recorded as inferred, never as fact.
    """
    now = now or datetime.now(timezone.utc)
    since = (now - timedelta(days=window_days)).isoformat().replace("+00:00", "Z")
    techs = technologies()
    running = inventory()
    depends = dependencies()
    by_cve: dict[str, dict[str, Any]] = {}
    stories: dict[str, dict[str, Any]] = {}
    for event in _events(db_path, since=since):
        payload = event["payload"]
        title, excerpt = str(payload.get("title") or ""), str(payload.get("excerpt") or "")
        if not SECURITY_RE.search(f"{title}\n{excerpt}\n{payload.get('external_id') or ''}"):
            continue
        found = signals(title, excerpt, techs=techs)
        if event["source"].get("source_class") == "vendor":
            # A vendor's own feed is about its technology even when an entry
            # title is just "Security Releases".
            found["technologies"] = sorted(set(found["technologies"]) | {name for name, pattern in techs.items() if pattern.search(event["source"]["name"])})
        if found["cves"]:
            for cve in found["cves"][:5]:  # round-ups mention many CVEs; their own items carry the detail
                item = by_cve.setdefault(cve, _new_item(cve, cve))
                if cve not in item["cves"]:
                    item["cves"].append(cve)
                _absorb(item, event, found)
            continue
        advisory_id = str(payload.get("external_id") or "")
        if re.fullmatch(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}", advisory_id):
            key, label = "advisory:" + advisory_id, advisory_id  # a registry advisory is its own item
            # Its "technology" is the package ecosystem, which every advisory
            # in that ecosystem mentions; exposure comes from our dependencies.
            found["technologies"] = []
            packages = {(str((row.get("package") or {}).get("ecosystem") or "").lower(), _normalize(str((row.get("package") or {}).get("name") or "")))
                        for row in payload.get("affected_versions") or [] if isinstance(row, dict)}
            item = stories.setdefault(key, _new_item(key, label))
            item.setdefault("packages", set()).update(packages)
            _absorb(item, event, found)
            continue
        elif found["names"]:
            key = "name:" + found["names"][0].lower()
            label = found["names"][0]
        elif found["technologies"] and (event["source"].get("source_class") == "vendor" or found["remote_code_execution"]
                                        or found["reported_exploited"] or found["reported_severity"]):
            day = advisory_date(event)[:10]
            key = f"tech:{found['technologies'][0].lower()}:{day}"
            label = f"{found['technologies'][0]} security issue ({day})"
        else:
            continue
        _absorb(stories.setdefault(key, _new_item(key, label)), event, found)
    # Same-technology day stories within the link window are one story.
    day_stories = sorted((s for s in stories.values() if s["key"].startswith("tech:")), key=lambda s: s["key"])
    for index, story in enumerate(day_stories):
        if story.get("merged_into"):
            continue
        for other in day_stories[index + 1:]:
            if other.get("merged_into") or other["technologies"] != story["technologies"] and not (set(other["technologies"]) & set(story["technologies"])):
                continue
            if other["key"].split(":")[1] == story["key"].split(":")[1] and _days_apart(story, other) <= LINK_WINDOW_DAYS:
                for event_id, title in zip(other["event_ids"], other["titles"]):
                    if event_id not in story["event_ids"]:
                        story["event_ids"].append(event_id)
                        story["titles"].append(title)
                story["sources"] += [x for x in other["sources"] if x not in story["sources"]]
                story["primary_event_ids"] += [x for x in other["primary_event_ids"] if x not in story["primary_event_ids"]]
                for key in ("reported_exploited", "remote_code_execution", "unauthenticated", "kev"):
                    story[key] = story[key] or other[key]
                if other["reported_cvss"] and (story["reported_cvss"] or 0) < other["reported_cvss"]:
                    story["reported_cvss"] = other["reported_cvss"]
                story["reported_severity"] = story["reported_severity"] or other["reported_severity"]
                story["advisory_date"] = max(story["advisory_date"], other["advisory_date"])
                story["earliest_date"] = min(story["earliest_date"], other["earliest_date"])
                other["merged_into"] = story["key"]
    # Fold named stories and technology stories together, then link to CVE items.
    for story in list(stories.values()):
        if story.get("merged_into"):
            continue
        if not story["key"].startswith("tech:"):
            continue
        for named in stories.values():
            if named["key"].startswith("name:") and set(story["technologies"]) & set(named["technologies"]) and _days_apart(story, named) <= LINK_WINDOW_DAYS:
                named["linked"].append({"key": story["key"], "linked_by": "shared technology and date (inferred)", "event_ids": story["event_ids"]})
                for event_id, title in zip(story["event_ids"], story["titles"]):
                    if event_id not in named["event_ids"]:
                        named["event_ids"].append(event_id)
                        named["titles"].append(title)
                named["sources"] += [s for s in story["sources"] if s not in named["sources"]]
                named["primary_event_ids"] += [e for e in story["primary_event_ids"] if e not in named["primary_event_ids"]]
                story["merged_into"] = named["key"]
                break
    remaining = [story for story in stories.values() if not story.get("merged_into") and not story["key"].startswith("advisory:")]
    for story in remaining:
        candidates = [item for item in by_cve.values()
                      if set(item["technologies"]) & set(story["technologies"]) and _days_apart(item, story) <= LINK_WINDOW_DAYS
                      and item["remote_code_execution"] and story["remote_code_execution"]]
        named_match = [item for item in by_cve.values() if story["names"] and set(story["names"]) & set(item["names"])]
        targets = named_match or candidates
        if not targets or len(candidates) > 3 and not named_match:
            continue  # ambiguous: keep the story as its own item
        linked_by = "shared vulnerability name" if named_match else "shared technology, date and code-execution impact (inferred)"
        for item in targets:
            item["linked"].append({"key": story["key"], "label": story["label"], "linked_by": linked_by, "event_ids": story["event_ids"]})
            item["sources"] += [s for s in story["sources"] if s not in item["sources"]]
            item["titles"] += story["titles"][:3]
            # Linked reports add context, never confirmation: exploitation
            # they report stays "reported", and KEV is never inherited.
            item["reported_exploited"] = item["reported_exploited"] or story["reported_exploited"]
            item["unauthenticated"] = item["unauthenticated"] or story["unauthenticated"]
            if story["reported_cvss"] and (item["reported_cvss"] or 0) < story["reported_cvss"]:
                item["reported_cvss"] = story["reported_cvss"]
        story["merged_into"] = targets[0]["key"]
    # One report that lists several CVEs (a CERT note, PHP2Shell's pair) is
    # one item: CVE items backed by exactly the same reports are merged.
    merged_cves: dict[frozenset, dict[str, Any]] = {}
    for item in sorted(by_cve.values(), key=lambda value: value["key"]):
        group = merged_cves.get(frozenset(item["event_ids"]))
        if group is None:
            merged_cves[frozenset(item["event_ids"])] = item
            continue
        group["cves"] += [cve for cve in item["cves"] if cve not in group["cves"]]
        group["label"] = ", ".join(group["cves"][:3]) + (f" (+{len(group['cves']) - 3})" if len(group["cves"]) > 3 else "")
        group["names"].update(item["names"])
    ranked = []
    for item in list(merged_cves.values()) + [story for story in stories.values() if not story.get("merged_into")]:
        item["technologies"] = sorted(item["technologies"])
        item["names"] = sorted(item["names"])
        item["primary_source"] = bool(item["primary_event_ids"])
        item["deployment_exposure"] = sorted(set(item["technologies"]) & running) + sorted(
            f"depends on {name} ({ecosystem})" for ecosystem, name in (item.get("packages") or set()) if (ecosystem, name) in depends)
        item["packages"] = sorted(f"{ecosystem}:{name}" for ecosystem, name in (item.get("packages") or set()))
        item["score"] = score(item)
        item["score_reasons"] = _score_reasons(item)
        ranked.append(item)
    # One CVE item per linked story set: keep sibling CVEs (PHP2Shell's two
    # CVEs) as separate items so each gets its own claims check.
    ranked.sort(key=lambda item: (item["score"], item.get("advisory_date") or ""), reverse=True)
    return ranked


def shortlist(*, db_path=None, now: Optional[datetime] = None, limit: int = 10, minimum_score: int = 45) -> list[dict[str, Any]]:
    checks = latest_claim_checks(db_path=db_path)
    items = [item for item in clusters(db_path=db_path, now=now) if item["score"] >= minimum_score][:max(1, min(limit, 50))]
    for item in items:
        item["claims"] = _report_level_cvss([checks[cve] for cve in item["cves"] if cve in checks])
    return items


def _report_level_cvss(checks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A release's headline CVSS belongs to its worst CVE, not to every CVE it lists.

    When one CVE in the report confirms the reported score, the others' lower
    official scores are expected, not a mismatch needing attention.
    """
    if len(checks) < 2 or not any(c["status"] == "confirmed" and c["claim"].startswith("CVSS ")
                                  for check in checks for c in check["claims"]):
        return checks
    adjusted = []
    for check in checks:
        claims = [{**c, "status": "lower_score", "detail": "the reported score belongs to another CVE in this report; " + c["detail"]}
                  if c["status"] == "mismatch" and c["claim"].startswith("CVSS ") else c for c in check["claims"]]
        adjusted.append({**check, "claims": claims,
                         "needs_attention": [c for c in claims if c["status"] in {"not_found", "not_published", "mismatch"}]})
    return adjusted


# ---------------------------------------------------------------- claims check
NOT_FOUND = {"__not_found__": True}


def _get_json(fetch: Callable[[str], Any], url: str) -> Optional[dict]:
    """Parsed JSON, ``NOT_FOUND`` for an HTTP 404, ``None`` when unavailable."""
    try:
        body = fetch(url)
    except Exception as exc:
        status = getattr(exc, "status", None)
        if status == 404 or re.search(r"\bHTTP 404\b", str(exc)):
            return NOT_FOUND
        return None
    try:
        return json.loads(body) if body else None
    except (TypeError, ValueError):
        return None


def check_claims(cluster: dict[str, Any], fetch: Callable[[str], Any], cve: Optional[str] = None) -> dict[str, Any]:
    """Compare what sources report about a CVE with its primary records."""
    cve = cve or cluster["cves"][0]
    record = _get_json(fetch, CVE_RECORD_URL.format(cve=cve))
    nvd = _get_json(fetch, NVD_URL.format(cve=cve))
    not_found = record is NOT_FOUND
    record = None if not_found else record
    nvd = None if nvd is NOT_FOUND else nvd
    claims = []
    state = ((record or {}).get("cveMetadata") or {}).get("state")
    if not_found:
        claims.append({"claim": f"{cve} exists", "status": "not_found",
                       "detail": "cve.org has no record for this identifier; it may be mistyped or not yet assigned",
                       "source": f"https://www.cve.org/CVERecord?id={cve}"})
    elif record is None:
        claims.append({"claim": f"{cve} exists", "status": "unavailable", "detail": "CVE record could not be retrieved; retry later",
                       "source": CVE_RECORD_URL.format(cve=cve)})
    elif state == "PUBLISHED":
        claims.append({"claim": f"{cve} exists", "status": "confirmed", "detail": "published CVE record",
                       "source": f"https://www.cve.org/CVERecord?id={cve}"})
    elif state:
        claims.append({"claim": f"{cve} exists", "status": "not_published", "detail": f"CVE record state {state}",
                       "source": f"https://www.cve.org/CVERecord?id={cve}"})
    else:
        claims.append({"claim": f"{cve} exists", "status": "not_found",
                       "detail": "no CVE record; the identifier may be wrong", "source": f"https://www.cve.org/CVERecord?id={cve}"})
    official_scores = []
    for vulnerability in (nvd or {}).get("vulnerabilities") or []:
        metrics = (vulnerability.get("cve") or {}).get("metrics") or {}
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
            for metric in metrics.get(key) or []:
                base = (metric.get("cvssData") or {}).get("baseScore")
                if isinstance(base, (int, float)):
                    official_scores.append(float(base))
    for container in (((record or {}).get("containers") or {}).get("cna") or {}).get("metrics") or []:
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0"):
            base = (container.get(key) or {}).get("baseScore")
            if isinstance(base, (int, float)):
                official_scores.append(float(base))
    reported = cluster.get("reported_cvss")
    if reported is not None:
        if not official_scores:
            claims.append({"claim": f"CVSS {reported}", "status": "unverified", "detail": "no CVSS score in the CVE record or NVD yet",
                           "source": NVD_URL.format(cve=cve)})
        elif any(abs(official - reported) < 0.05 for official in official_scores):
            claims.append({"claim": f"CVSS {reported}", "status": "confirmed", "detail": "matches the CVE record or NVD",
                           "source": NVD_URL.format(cve=cve)})
        else:
            claims.append({"claim": f"CVSS {reported}", "status": "mismatch",
                           "detail": "official score(s): " + ", ".join(f"{s:g}" for s in sorted(set(official_scores))),
                           "source": NVD_URL.format(cve=cve)})
    if cluster.get("kev"):
        claims.append({"claim": "exploited in the wild", "status": "confirmed", "detail": "listed in CISA Known Exploited Vulnerabilities",
                       "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"})
    elif cluster.get("reported_exploited"):
        claims.append({"claim": "exploited in the wild", "status": "reported",
                       "detail": "reported by " + ", ".join(cluster.get("sources") or []) + "; not in CISA KEV", "source": ""})
    description = ""
    for item in (((record or {}).get("containers") or {}).get("cna") or {}).get("descriptions") or []:
        if item.get("lang", "").startswith("en"):
            description = str(item.get("value") or "")[:1500]
            break
    return {"cve": cve, "claims": claims, "official_description": description,
            "official_cvss": sorted(set(official_scores)), "needs_attention": [c for c in claims if c["status"] in {"not_found", "not_published", "mismatch"}]}


def latest_claim_checks(*, db_path=None) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for record in records(CLAIMS_KIND, db_path=db_path, limit=500):
        payload = record["payload"]
        latest.setdefault(payload["cve"], {**payload, "checked_at": record["created_at"]})
    return latest


def run_claim_checks(fetch: Callable[[str], Any], *, db_path=None, now: Optional[datetime] = None, limit: int = 5) -> dict[str, Any]:
    """Check the top shortlisted CVEs whose claims are unchecked or stale."""
    now = now or datetime.now(timezone.utc)
    previous = latest_claim_checks(db_path=db_path)
    checked = []
    for item in shortlist(db_path=db_path, now=now, limit=20):
        for cve in item["cves"][:3]:
            prior = previous.get(cve)
            if prior:
                age = now - datetime.fromisoformat(prior["checked_at"].replace("Z", "+00:00"))
                if age < timedelta(hours=CLAIM_CHECK_TTL_HOURS) and not any(c["status"] == "unavailable" for c in prior["claims"]):
                    continue
            result = check_claims(item, fetch, cve)
            append(CLAIMS_KIND, result, actor="secopsai-automated-research-desk", db_path=db_path)
            checked.append(cve)
            if len(checked) >= limit:
                return {"checked": checked}
    return {"checked": checked}


def projection(*, db_path=None, now: Optional[datetime] = None, limit: int = 10) -> dict[str, Any]:
    """Bounded hosted view of the desk: ranked items and their claim checks."""
    items = []
    for item in shortlist(db_path=db_path, now=now, limit=limit):
        claims = item.get("claims") or []
        items.append({"key": item["key"], "label": item["label"], "cves": item["cves"][:5], "names": item["names"][:3],
                      "score": item["score"], "score_reasons": item["score_reasons"],
                      "titles": item["titles"][:3], "sources": item["sources"][:8], "technologies": item["technologies"],
                      "deployment_exposure": item["deployment_exposure"],
                      "primary_event_ids": item["primary_event_ids"][:5], "event_ids": item["event_ids"][:10],
                      "first_observed_at": item.get("first_observed_at"), "advisory_date": item.get("advisory_date"),
                      "linked": [{"label": link.get("label", link["key"]), "linked_by": link["linked_by"]} for link in item["linked"]][:5],
                      "claims": [claim for check in claims for claim in check["claims"]],
                      "claims_checked_at": max((check["checked_at"] for check in claims), default=None),
                      "needs_attention": [claim for check in claims for claim in check["needs_attention"]],
                      "official_description": next((check["official_description"] for check in claims if check.get("official_description")), "")})
    return {"schema_version": "secopsai.research.desk.v1", "window_days": WINDOW_DAYS, "items": items}


RULES_REGISTRY = ROOT / "docs" / "rules-registry.md"
_RULE_HEADING = re.compile(r"^### (RULE-\d+): (.+)$", re.M)


def detection_rules() -> list[dict[str, Any]]:
    """SecOpsAI rules with the CVEs and title words their registry entry names."""
    try:
        registry = RULES_REGISTRY.read_text(encoding="utf-8")
    except OSError:
        return []
    headings = list(_RULE_HEADING.finditer(registry))
    rules = []
    for index, match in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(registry)
        section = registry[match.start():end]
        rules.append({"rule_id": match.group(1), "title": match.group(2).strip(),
                      "cves": sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", section)))})
    return rules


def detections_for(item: dict[str, Any]) -> list[dict[str, Any]]:
    cves, names = set(item.get("cves") or []), {name.lower() for name in item.get("names") or []}
    return [rule for rule in detection_rules()
            if cves & set(rule["cves"]) or any(name in rule["title"].lower() for name in names)]


def research_note(event_id: str, *, db_path=None, now: Optional[datetime] = None,
                  ranked: Optional[list[dict[str, Any]]] = None, cves: Optional[list[str]] = None) -> list[str]:
    """Markdown lines for a verified brief item: claim checks, detections, exposure.

    Empty when the event is not part of a ranked desk item. ``cves`` names what
    the item itself is about; without it, the whole ranked cluster is reported.
    """
    if ranked is None:
        ranked = shortlist(db_path=db_path, now=now, limit=50, minimum_score=0)
    item = next((entry for entry in ranked
                 if event_id in entry["event_ids"]), None)
    if item is None:
        return []
    lines = []
    if cves is None:
        claims = [claim for check in item.get("claims") or [] for claim in check["claims"]]
    else:
        # Clusters group by shared CVE or name, so a cluster's checks and rules
        # can belong to a neighbouring item. Report this item's own.
        latest = latest_claim_checks(db_path=db_path)
        # "reported" and "unverified" rows repeat what the cluster's sources say
        # and were not checked, so they would read as findings about this item.
        claims = [claim for cve in cves for claim in (latest.get(cve) or {}).get("claims", [])
                  if claim["status"] not in {"reported", "unverified"}]
    if claims:
        lines += ["", "| Claim | Check | Source |", "| --- | --- | --- |"]
        lines += [f"| {claim['claim']} | {claim['status'].replace('_', ' ')} | {claim.get('source') or claim.get('detail') or ''} |"
                  for claim in claims]
    rules = detections_for(item if cves is None else {"cves": cves})
    lines.append("SecOpsAI detection: " + ("; ".join(f"{rule['rule_id']} ({rule['title']})" for rule in rules)
                                           if rules else "no SecOpsAI rule covers this yet."))
    if item["deployment_exposure"]:
        lines.append("SecOpsAI deployment exposure: " + ", ".join(item["deployment_exposure"]) + ".")
    return lines
