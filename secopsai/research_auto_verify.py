"""Automated source verification under the operator's recorded policy.

The operator delegates routine verification by recording an accepted
``automated_verification`` requirement. Each worker cycle then decides
pending public source items with deterministic rules:

* a repeat of an item already decided (same citation or same title from the
  same source) is rejected as a duplicate;
* a news report (aggregator) is never verified here; it needs its primary
  source and stays with the human reviewer;
* an old advisory with no exploitation signal is rejected: a feed sorted by
  update time resurfaces them, but they are not news;
* a primary item is verified only when every CVE it is about exists in cve.org,
  no reported score contradicts the official record, and the source itself
  states a fix or mitigation. CVEs merely mentioned in its text are named as
  related, not described as if they were the item's own;
* anything else is marked ``needs_review`` with the reason.

Decisions are recorded under the delegating operator with an ``automation``
block naming the policy and the checks that passed, so the brief can say the
item was verified automatically. Editorial approval of the brief stays human.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Optional

from secopsai.research_operation_store import append, records

AUTOMATION_POLICY_KIND = "automated_verification"
AUTOMATED_SOURCE_CLASSES = {"vendor", "government", "registry"}
CLAIMS_PER_RUN = 10
STALE_ADVISORY_DAYS = 14
# Raised when a change makes earlier automated verifications wrong. Unreleased
# recent ones are decided again, so a draft never carries the old text.
DECISION_REVISION = 3
REDECIDE_WINDOW_DAYS = 3
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
VERSION_RE = re.compile(r"\b\d+\.\d+(?:\.\d+)+\b")
FIX_WORDS = re.compile(r"\b(fix(?:es|ed)?|patch(?:es|ed)?|upgrade|update|release[sd]?|resolved?)\b", re.IGNORECASE)
MITIGATION_RE = re.compile(r"\bset\s+(?:<[^>]+>)?\s*([\w.\-]+\s*=\s*[\w.\-]+)", re.IGNORECASE)
RELEASE_TITLE_RE = re.compile(r"\breleased?\b|\bavailable\b", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]{0,500}>")
OLD_CVSS_RULE = re.compile(r"\bCVSS \d+(?:\.\d)?: mismatch")


def policy(*, db_path=None) -> Optional[dict[str, Any]]:
    """The accepted delegation, or None when verification stays manual."""
    from secopsai.research_governance import accepted_requirement

    if not accepted_requirement(AUTOMATION_POLICY_KIND, db_path=db_path):
        return None
    record = records(AUTOMATION_POLICY_KIND, db_path=db_path, limit=1)[0]
    return {**record["payload"], "record_id": record["record_id"]}


def _text(value: Any) -> str:
    return re.sub(r"\s+", " ", TAG_RE.sub(" ", str(value or ""))).strip()


def _sentences(text: str) -> list[str]:
    return [part.strip() for part in re.split(r"(?<=[.!?])\s+", text) if part.strip()]


def fixed_versions(title: str, excerpt: str, payload: dict) -> list[str]:
    """Versions the source says contain the fix, in the order it lists them."""
    found: list[str] = []
    for row in payload.get("affected_versions") or []:  # registry advisories
        patched = (row or {}).get("first_patched_version")
        name = ((row or {}).get("package") or {}).get("name")
        if patched and name:
            found.append(f"{name} {patched}")
    if found:
        return list(dict.fromkeys(found))
    for sentence in [title, *_sentences(excerpt)]:
        if FIX_WORDS.search(sentence):
            found.extend(VERSION_RE.findall(sentence))
        if found:
            break
    return list(dict.fromkeys(found))[:12]


def mitigations(excerpt: str) -> list[str]:
    return list(dict.fromkeys(match.strip() for match in MITIGATION_RE.findall(excerpt)))[:3]


def _defensive_action(title: str, excerpt: str, payload: dict, rules: list[dict]) -> str:
    parts = []
    versions = fixed_versions(title, excerpt, payload)
    if versions:
        parts.append("Upgrade to a fixed release: " + ", ".join(versions) + ".")
    for setting in mitigations(excerpt):
        parts.append(f"Until upgraded, set {setting} as the source advises.")
    if payload.get("required_action"):
        # CISA's "Notes" field is not part of the item, so the pointer leads nowhere.
        parts.append(re.sub(r"\s*\(see URL in Notes\)", "", _text(payload["required_action"])))
    if parts and rules:
        parts.append("SecOpsAI users can enable " + "; ".join(f"{rule['rule_id']} ({rule['title']})" for rule in rules) + ".")
    return " ".join(parts)


def citation_key(event: dict) -> str:
    """Citation plus the item's own identifier: feeds such as CISA KEV cite one
    catalog URL for every entry, so the URL alone does not identify an item."""
    payload = event["payload"]
    return f"{payload.get('url') or ''}|{event.get('external_id') or payload.get('external_id') or event['event_id']}"


def subject_cves(event: dict, found: dict) -> list[str]:
    """The CVEs an item is about, not every CVE its text mentions.

    A CISA entry says what its flaw chains with and a GitHub advisory cites
    prior art; those mentions are not the item's own identifiers.
    """
    payload = event["payload"]
    if payload.get("cve_id"):
        return [str(payload["cve_id"]).upper()]
    if str(payload.get("external_id") or event.get("external_id") or "").startswith("GHSA-"):
        return []
    in_title = sorted({cve.upper() for cve in CVE_RE.findall(_text(payload.get("title")))})
    return in_title or found["cves"][:8]


def _too_old(event: dict, found: dict, now: datetime) -> str:
    """The publication date of an advisory too old to be news, else empty."""
    payload = event["payload"]
    published = str(payload.get("published_at") or event.get("published_at") or "")
    if not published or payload.get("catalog_added_at") or found["reported_exploited"]:
        return ""
    if published.replace("Z", "+00:00") >= (now - timedelta(days=STALE_ADVISORY_DAYS)).isoformat():
        return ""
    return published[:10]


def _released_event_ids(db_path=None) -> set[str]:
    import json

    from secopsai.research_operation_store import read_connection

    with read_connection(db_path) as conn:
        return {item["event_id"] for row in conn.execute(
            "SELECT draft_json FROM research_editorial_editions WHERE state IN ('approved','published','corrected','retracted')")
            for item in json.loads(row["draft_json"]).get("items", [])}


def _decide(event: dict, checks: dict[str, dict], decided: dict[str, str], now: Optional[datetime] = None) -> dict[str, Any]:
    from secopsai.research_desk import detections_for, signals

    payload, source = event["payload"], event["source"]
    title, excerpt = _text(payload.get("title")), _text(payload.get("excerpt"))
    cited = citation_key(event)
    title_key = f"{event['source_id']}|{title.casefold()}"
    for key in (cited, title_key):
        if key and key in decided and decided[key] != event["event_id"]:
            return {"decision": "rejected", "reason": f"duplicate of {decided[key]} (same {'citation' if key == cited else 'title'})"}
    if source.get("source_class") not in AUTOMATED_SOURCE_CLASSES:
        return {"decision": "needs_review", "reason": "news report: verify against its primary source before it can be cited"}
    found = signals(title, excerpt)
    published = _too_old(event, found, now or datetime.now(timezone.utc))
    if published:
        return {"decision": "rejected", "reason": f"advisory published {published}; over {STALE_ADVISORY_DAYS} days old with no exploitation signal, so not news"}
    cves = subject_cves(event, found)
    related = [cve for cve in found["cves"] if cve not in cves][:8]
    missing = [cve for cve in cves if cve not in checks]
    if missing:
        return {"decision": None, "reason": "claim checks pending for " + ", ".join(missing), "unchecked": missing}
    # Identifier claims come from the cached per-CVE checks. The score is
    # judged for this item: its reported CVSS must match the official score of
    # at least one CVE it lists (a release's headline score belongs to its
    # worst CVE). Cached CVSS claims reflect whichever report was checked first.
    concerns = [f"{claim['claim']}: {claim['status'].replace('_', ' ')}" for cve in cves for claim in checks[cve]["claims"]
                if not claim["claim"].startswith("CVSS ") and claim["status"] in {"not_found", "not_published", "mismatch", "unavailable"}]
    reported = found.get("reported_cvss")
    official = sorted({score for cve in cves for score in (checks[cve].get("official_cvss") or [])})
    if reported is not None and official and not any(abs(score - reported) < 0.05 for score in official):
        concerns.append(f"reported CVSS {reported:g} matches no listed CVE (official: {', '.join(f'{s:g}' for s in official)})")
    if concerns:
        return {"decision": "needs_review", "reason": "official records disagree: " + "; ".join(concerns)}
    if RELEASE_TITLE_RE.search(title) and cves and any(f"cves:{source['name']}:{','.join(cves)}" == key for key in decided):
        return {"decision": "rejected", "reason": "release announcement for a fix already covered by this source's advisory"}
    rules = detections_for({"cves": cves, "names": found["names"]})
    action = _defensive_action(title, excerpt, payload, rules)
    if not action:
        return {"decision": "needs_review", "reason": "the source states no fixed version or mitigation"}
    official = [checks[cve] for cve in cves]
    summary_parts = [f"{source['name']} reports: {title}."]
    for check in official:
        description = _sentences(check.get("official_description") or "")
        score = check.get("official_cvss") or []
        line = check["cve"] + (f" (official CVSS {' and '.join(f'{value:g}' for value in score)})" if score else "")
        summary_parts.append(line + (": " + description[0] if description else "."))
    if related:
        summary_parts.append("The source also mentions " + ", ".join(related) + ".")
    kev = source.get("source_class") == "government" and "known exploited" in source.get("name", "").casefold()
    limitations = ["Source-reported; SecOpsAI did not reproduce the issue."]
    if kev:
        summary_parts.append("CISA lists it as exploited in the wild.")
    elif found["reported_exploited"]:
        limitations.append("Exploitation is reported but not confirmed by CISA KEV.")
    if not cves:
        limitations.append("SecOpsAI recorded no CVE identifier for this advisory.")
    return {"decision": "verified", "reason": "primary source; identifiers and scores match official records; fix or mitigation stated",
            "summary": " ".join(summary_parts)[:4000], "defensive_action": action[:4000], "limitations": " ".join(limitations),
            "cves": cves, "checks": {cve: [c["status"] for c in checks[cve]["claims"]] for cve in cves}}


def ranked_event_ids(*, db_path=None) -> dict[str, None]:
    """Events of the research desk's shortlist, in rank order (primary sources first)."""
    from secopsai.research_desk import shortlist

    ranked: dict[str, None] = {}
    for item in shortlist(db_path=db_path, limit=50):
        for event_id in [*(item.get("primary_event_ids") or []), *(item.get("event_ids") or [])]:
            ranked.setdefault(event_id, None)
    return ranked


def _withdraw_unranked(ranked: dict[str, None], delegation: dict, *, db_path=None) -> list[str]:
    """Undo this policy's own recent verifications of items the desk does not rank.

    Items already in an approved or published brief are left as they are.
    """
    from secopsai.research_primary_intel import verify_event, intel_event

    since = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat().replace("+00:00", "Z")
    released = _released_event_ids(db_path)
    latest: dict[str, dict] = {}
    for record in records("intel_verification", db_path=db_path, limit=10000):
        latest.setdefault(record["payload"]["event_id"], record)
    withdrawn = []
    for event_id, record in latest.items():
        value = record["payload"]
        if (value.get("decision") != "verified" or not value.get("automation") or event_id in ranked
                or event_id in released or record["created_at"] < since):
            continue
        event = intel_event(event_id, db_path=db_path)
        reason = "not ranked by the research desk; routine registry item kept out of the brief"
        verify_event(event_id, {"decision": "needs_review", "rationale": "Automated verification withdrawn: " + reason,
                                "limitations": reason, "primary_url": event["payload"]["url"], "attribution": "source_reported"},
                     actor=delegation["operator_id"], db_path=db_path,
                     automation={"policy_record_id": delegation["record_id"], "rule": reason, "checks": {}})
        withdrawn.append(event_id)
    return withdrawn


def run(fetch: Optional[Callable[[str], Any]] = None, *, db_path=None, limit: int = 20) -> dict[str, Any]:
    """Decide pending public source items under the operator's policy."""
    from secopsai.research_desk import CLAIMS_KIND, check_claims, latest_claim_checks, signals
    from secopsai.research_primary_intel import intel_event, pending_public_reviews, verify_event

    redecide_since = (datetime.now(timezone.utc) - timedelta(days=REDECIDE_WINDOW_DAYS)).isoformat().replace("+00:00", "Z")
    released = _released_event_ids(db_path)

    delegation = policy(db_path=db_path)
    if not delegation:
        return {"status": "disabled", "reason": "no accepted automated_verification policy"}
    operator = delegation["operator_id"]
    checks = latest_claim_checks(db_path=db_path)
    decided: dict[str, str] = {}
    redo: list[str] = []
    latest_seen: set[str] = set()
    for record in records("intel_verification", db_path=db_path, limit=10000):
        value = record["payload"]
        first = value["event_id"] not in latest_seen
        latest_seen.add(value["event_id"])
        rule = str((value.get("automation") or {}).get("rule", ""))
        if first and value.get("automation") and (
                (value.get("decision") == "rejected" and "(same citation)" in rule)
                or (value.get("decision") == "needs_review" and OLD_CVSS_RULE.search(rule))):
            # Decided under a superseded rule (URL-only citation key, or cached
            # per-CVE scores); decide again under the current one.
            redo.append(value["event_id"])
            continue
        if (first and value.get("automation") and value.get("decision") == "verified" and value["event_id"] not in released
                and int(value["automation"].get("revision") or 1) < DECISION_REVISION and record["created_at"] >= redecide_since):
            redo.append(value["event_id"])
            continue
        if not first:
            continue  # only an item's latest decision counts
        if value.get("decision") not in {"verified", "rejected"}:
            continue
        try:
            prior = intel_event(value["event_id"], db_path=db_path)
        except ValueError:
            continue
        decided.setdefault(citation_key(prior), value["event_id"])
        decided.setdefault(f"{prior['source_id']}|{_text(prior['payload'].get('title')).casefold()}", value["event_id"])
        if value.get("decision") == "verified":
            cves = subject_cves(prior, signals(_text(prior["payload"].get("title")), _text(prior["payload"].get("excerpt"))))
            if cves:
                decided.setdefault(f"cves:{prior['source']['name']}:{','.join(cves)}", value["event_id"])
    outcome = {"verified": [], "rejected": [], "needs_review": [], "waiting": [], "claim_checks": 0, "withdrawn": []}
    # Only what the research desk ranks: the newest collected items are
    # mostly routine registry advisories that do not belong in a brief.
    ranked = ranked_event_ids(db_path=db_path)
    outcome["withdrawn"] = _withdraw_unranked(ranked, delegation, db_path=db_path)
    # Primary sources first, so a later repeat or release note is matched to them.
    # Within one title the newest copy goes first: a re-collected entry carries
    # the corrected citation (e.g. php.net's per-advisory link), so the older
    # copy is the one rejected as its duplicate.
    queue = sorted((item for item in pending_public_reviews(db_path=db_path, limit=50, event_ids=list(ranked)) if item["event_id"] in ranked),
                   key=lambda item: item["first_observed_at"], reverse=True)
    queue.sort(key=lambda item: "advisory" not in item["title"].casefold())
    redo_items = [{"event_id": event_id, "review_status": "pending_review"} for event_id in redo if event_id in ranked]
    for item in redo_items + queue[:limit]:
        if item["review_status"] not in {"pending_review", "source_changed_review_required"}:
            continue
        event = intel_event(item["event_id"], db_path=db_path)
        result = _decide(event, checks, decided)
        if result["decision"] is None and fetch is not None and outcome["claim_checks"] < CLAIMS_PER_RUN:
            found = signals(_text(event["payload"].get("title")), _text(event["payload"].get("excerpt")))
            cluster = {**found, "sources": [event["source"]["name"]],
                       "kev": "known exploited" in event["source"].get("name", "").casefold()}
            for cve in result["unchecked"][: CLAIMS_PER_RUN - outcome["claim_checks"]]:
                checks[cve] = check_claims(cluster, fetch, cve)
                append(CLAIMS_KIND, checks[cve], actor="secopsai-automated-research-desk", db_path=db_path)
                outcome["claim_checks"] += 1
            result = _decide(event, checks, decided)
        if result["decision"] is None:
            outcome["waiting"].append(item["event_id"])
            continue
        automation = {"policy_record_id": delegation["record_id"], "rule": result["reason"], "checks": result.get("checks", {}),
                      "revision": DECISION_REVISION}
        payload = {"decision": result["decision"], "rationale": "Automated verification: " + result["reason"],
                   "summary": result.get("summary", ""), "defensive_action": result.get("defensive_action", ""),
                   "limitations": result.get("limitations") or result["reason"], "primary_url": event["payload"]["url"],
                   "primary_event_id": event["event_id"], "attribution": "source_reported"}
        verify_event(event["event_id"], payload, actor=operator, automation=automation, db_path=db_path)
        outcome[result["decision"]].append(event["event_id"])
        if result["decision"] in {"verified", "rejected"}:
            decided.setdefault(citation_key(event), event["event_id"])
            decided.setdefault(f"{event['source_id']}|{_text(event['payload'].get('title')).casefold()}", event["event_id"])
            if result["decision"] == "verified" and result.get("cves"):
                decided.setdefault(f"cves:{event['source']['name']}:{','.join(result['cves'])}", event["event_id"])
    return {"status": "ran", **{key: value if isinstance(value, int) else len(value) for key, value in outcome.items()},
            "needs_review_ids": outcome["needs_review"]}
