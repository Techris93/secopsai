"""A staffed, seven-day editorial workflow; collection never grants publication permission."""
from __future__ import annotations

import json
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import soc_store
from secopsai.research_operation_store import read_connection
from secopsai.research_assurance import person
from secopsai.research_operation_store import append, canonical, digest, records, text, transaction
from secopsai.research_primary_intel import intel_event

TIMEZONE = ZoneInfo("Europe/Istanbul")
PRODUCTS = {"daily_brief", "technical_advisory", "research_report"}
BOARD_STATES = {"proposed", "verifying", "vendor_contact", "embargoed", "technical_review", "approved", "published", "updating", "corrected", "retracted"}
BRIEF_CHECKS = {"claims", "primary_sources", "affected_versions", "defensive_actions", "uncertainty", "privacy", "secrets", "sharing_rights", "licensing", "embargo", "credits", "conflicts"}


def configure_roster(payload: dict, *, actor: str, db_path=None) -> dict:
    person(actor, role="operator", db_path=db_path)
    days = payload.get("days")
    if not isinstance(days, dict) or set(days) != {str(d) for d in range(7)}:
        raise ValueError("roster requires Monday=0 through Sunday=6, including weekends")
    for entry in days.values():
        person(entry.get("author_id", ""), role="author", db_path=db_path)
        person(entry.get("editor_id", ""), role="editor", db_path=db_path)
        person(entry.get("backup_id", ""), role="editor", db_path=db_path)
        if len({entry["author_id"], entry["editor_id"], entry["backup_id"]}) != 3:
            raise ValueError("each duty shift requires distinct author, editor and backup")
    return append("editorial_roster", {"days": days, "timezone": "Europe/Istanbul", "research_hours": "10:00–15:00", "brief_at": "16:00", "release_target": "17:00", "handoff_at": "18:00"}, actor=actor, db_path=db_path)


def _event_decisions(*, db_path=None) -> dict:
    result = {}
    for record in records("intel_verification", db_path=db_path, limit=10000):
        value = record["payload"]
        if value["event_id"] not in result:
            result[value["event_id"]] = value
    return result


def _edition(edition_id: str, *, db_path=None) -> dict:
    soc_store.init_db(db_path)
    with read_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM research_editorial_editions WHERE edition_id=?", (edition_id,)).fetchone()
    if row is None:
        raise ValueError("unknown editorial edition")
    value = dict(row)
    value["draft"] = json.loads(value.pop("draft_json"))
    return value


def create_daily_brief(*, date: str | None = None, db_path=None) -> dict:
    date = date or datetime.now(TIMEZONE).date().isoformat()
    day = datetime.fromisoformat(date).date()
    if day.isoformat() != date:
        raise ValueError("edition date must be YYYY-MM-DD")
    identity = "BRIEF-" + date
    soc_store.init_db(db_path)
    with read_connection(db_path) as conn:
        existing = conn.execute("SELECT 1 FROM research_editorial_editions WHERE edition_id=?", (identity,)).fetchone()
    if existing:
        return {**_edition(identity, db_path=db_path), "reused": True}
    rosters = records("editorial_roster", db_path=db_path)
    if not rosters:
        return {"status": "blocked", "blockers": ["a named seven-day editorial roster and backup are required"]}
    duty = rosters[0]["payload"]["days"][str(day.weekday())]
    author = person(duty["author_id"], role="author", db_path=db_path)
    person(duty["editor_id"], role="editor", db_path=db_path)
    person(duty["backup_id"], role="editor", db_path=db_path)
    decisions = _event_decisions(db_path=db_path)
    start = datetime.combine(day, datetime.min.time(), TIMEZONE)
    end = start + timedelta(days=1)
    with read_connection(db_path) as conn:
        ids = [r["event_id"] for r in conn.execute("SELECT event_id FROM research_intel_events WHERE first_observed_at>=? AND first_observed_at<? ORDER BY first_observed_at DESC LIMIT 1000", (start.astimezone(ZoneInfo("UTC")).isoformat().replace("+00:00", "Z"), end.astimezone(ZoneInfo("UTC")).isoformat().replace("+00:00", "Z")))]
    items, roots = [], set()
    for event_id in ids:
        decision = decisions.get(event_id, {})
        if decision.get("decision") != "verified":
            continue
        event = intel_event(event_id, db_path=db_path)
        if decision["event_fingerprint"] != digest(event):
            continue
        primary = intel_event(decision["primary_event_id"], db_path=db_path)
        if primary["root_source_key"] in roots:
            continue
        person(decision["reviewer_id"], role="technical_reviewer", db_path=db_path)
        roots.add(primary["root_source_key"])
        items.append({"event_id": event_id, "event_fingerprint": digest(event), "primary_event_id": primary["event_id"],
                      "primary_fingerprint": digest(primary), "source": primary["source"]["name"], "title": event["payload"]["title"],
                      "url": decision["primary_url"], "attribution": "source_reported", "summary": decision["summary"], "verification_fingerprint": digest(decision), "defensive_action": decision["defensive_action"],
                      "limitations": decision["limitations"], "published_at": event["published_at"], "first_observed_at": event["first_observed_at"],
                      "collected_at": event["collected_at"], "source_sha256": primary["sha256"]})
        if len(items) == 15:
            break
    from secopsai.research_coverage import coverage_report
    coverage = coverage_report(db_path=db_path)
    lines = [f"# SecOpsAI Daily Intelligence Brief — {date}", "", "This brief distinguishes source reporting from SecOpsAI's original observations."]
    if not items:
        lines.extend(["", "No new items passed technical verification for this edition. Collection gaps and unresolved leads remain visible to the editor."])
    for item in items:
        lines.extend(["", f"## {item['title']}", "", f"Source-reported by [{item['source']}]({item['url']}).",
                      item["summary"],
                      f"Defensive action: {item['defensive_action']}", f"Limitations: {item['limitations']}",
                      f"Published: {item['published_at'] or 'not supplied'}; first observed: {item['first_observed_at']}."])
    lines.extend(["", "## Collection scope", "", coverage["public_summary"], "", "## Credits and corrections", "", f"Prepared by {author['display_name']}. Technical verification and final release require recorded human review. Corrections will retain the previous edition and explain material changes."])
    draft = {"title": f"SecOpsAI Daily Intelligence Brief — {date}", "slug": f"daily-intelligence-{date}", "summary": f"Verified intelligence and defensive updates for {date}.",
             "body_markdown": "\n\n".join(lines), "author": author["display_name"], "author_id": author["person_id"], "items": items,
             "sources": [item["url"] for item in items], "references": [item["url"] for item in items], "categories": ["Threat Intelligence"], "severity": "info",
             "editorial_edition_id": identity, "review_status": "needs_review", "coverage": coverage, "external_news": False,
             "duty": duty, "status": "draft"}
    now = soc_store.utc_now()
    with transaction(db_path) as conn:
        conn.execute("INSERT INTO research_editorial_editions VALUES (?,?,?,?,?,?,'verifying','',?,?)", (identity, date, "daily_brief", author["person_id"], canonical(draft), digest(draft), now, now))
        append("edition_created", {"edition_id": identity, "item_count": len(items)}, actor="editorial-scheduler", connection=conn)
    return _edition(identity, db_path=db_path)


def edit_edition(edition_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    person(actor, role="author", db_path=db_path)
    edition = _edition(edition_id, db_path=db_path)
    if actor != edition["author_id"]:
        raise ValueError("only the assigned author may change the edition")
    if edition["state"] in {"published", "corrected", "retracted"}:
        raise ValueError("published editions require the correction workflow")
    allowed = {"title", "summary", "body_markdown"}
    if not payload or not set(payload) <= allowed:
        raise ValueError("edition edit supports title, summary and body_markdown")
    draft = {**edition["draft"], **{k: text(v, k, limit=200000) for k, v in payload.items()}}
    with transaction(db_path) as conn:
        append("edition_revision", {"edition_id": edition_id, "before": edition["draft"], "after": draft}, actor=actor, connection=conn)
        conn.execute("UPDATE research_editorial_editions SET draft_json=?,fingerprint=?,state='verifying',updated_at=? WHERE edition_id=?", (canonical(draft), digest(draft), soc_store.utc_now(), edition_id))
    return _edition(edition_id, db_path=db_path)


def _items_current(edition: dict, db_path) -> bool:
    decisions = _event_decisions(db_path=db_path)
    for item in edition["draft"]["items"]:
        event = intel_event(item["event_id"], db_path=db_path)
        primary = intel_event(item["primary_event_id"], db_path=db_path)
        decision = decisions.get(item["event_id"], {})
        if (digest(event) != item["event_fingerprint"] or digest(primary) != item["primary_fingerprint"]
                or decision.get("decision") != "verified" or decision.get("event_fingerprint") != digest(event) or digest(decision) != item["verification_fingerprint"]
                or event["source"]["sharing"] != "public" or primary["source"]["sharing"] != "public"):
            return False
        person(decision["reviewer_id"], role="technical_reviewer", db_path=db_path)
    return True


def approve_edition(edition_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    edition = _edition(edition_id, db_path=db_path)
    person(actor, role="editor", db_path=db_path)
    if actor == edition["author_id"] or actor not in {edition["draft"]["duty"]["editor_id"], edition["draft"]["duty"]["backup_id"]}:
        raise ValueError("release requires the assigned duty editor or backup, distinct from the author")
    checks = payload.get("checks")
    if payload.get("expected_fingerprint") != edition["fingerprint"]:
        raise ValueError("editor must approve the fingerprint of the exact edition they reviewed")
    if payload.get("reviewed_draft") != edition["draft"]["body_markdown"]:
        raise ValueError("editor approval requires the complete current draft text")
    if not isinstance(checks, dict) or set(checks) != BRIEF_CHECKS or any(v != "passed" for v in checks.values()):
        raise ValueError("every daily brief release check must pass explicitly")
    if not _items_current(edition, db_path):
        raise ValueError("brief source verification changed; approval must be repeated")
    with transaction(db_path) as conn:
        append("edition_approval", {"edition_id": edition_id, "checks": checks, "editor_id": actor, "reviewer_fingerprint": digest(person(actor, role="editor", db_path=db_path)), "rationale": text(payload.get("rationale"), "editorial rationale")}, actor=actor, fingerprint=edition["fingerprint"], connection=conn)
        conn.execute("UPDATE research_editorial_editions SET state='approved',updated_at=? WHERE edition_id=?", (soc_store.utc_now(), edition_id))
    return _edition(edition_id, db_path=db_path)


def validate_release(edition_id: str, post: dict, *, db_path=None) -> dict:
    edition = _edition(edition_id, db_path=db_path)
    approvals = [r for r in records("edition_approval", db_path=db_path) if r["payload"]["edition_id"] == edition_id]
    if edition["state"] not in {"approved", "published", "corrected", "retracted"} or not approvals or approvals[0]["fingerprint"] != edition["fingerprint"]:
        raise ValueError("edition has no current human release approval")
    if approvals[0]["payload"].get("reviewer_fingerprint") != digest(person(approvals[0]["actor"], role="editor", db_path=db_path)):
        raise ValueError("editor identity or qualification changed after approval")
    if not _items_current(edition, db_path):
        raise ValueError("edition evidence is no longer eligible for publication")
    # Every public field must match the approved draft. Operational fields may
    # be normalized by the blog renderer; they cannot authorize changed text.
    for key in ("title", "summary", "body_markdown", "author", "sources", "references", "slug"):
        if post.get(key) != edition["draft"].get(key):
            raise ValueError("publication content changed after editorial approval")
    return edition


def publish_edition(edition_id: str, *, actor: str, db_path=None, paths=None) -> dict:
    from secopsai import blog
    person(actor, role="editor", db_path=db_path)
    edition = _edition(edition_id, db_path=db_path)
    validate_release(edition_id, edition["draft"], db_path=db_path)
    if edition["state"] in {"published", "corrected", "retracted"}:
        return {"edition_id": edition_id, "published": True, "url": edition["published_url"], "reused": True}
    paths = paths or blog.BlogPaths()
    path = paths.drafts / (edition["draft"]["slug"] + ".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(edition["draft"], indent=2), encoding="utf-8")
    result = blog.publish(str(path), confirm=True, paths=paths, db_path=db_path)
    with transaction(db_path) as conn:
        state = {"correction": "corrected", "retraction": "retracted"}.get(edition["draft"].get("correction_action"), "published")
        conn.execute("UPDATE research_editorial_editions SET state=?,published_url=?,updated_at=? WHERE edition_id=?", (state, result["url"], soc_store.utc_now(), edition_id))
        append("edition_published", {"edition_id": edition_id, "url": result["url"], "fingerprint": edition["fingerprint"]}, actor=actor, connection=conn)
    return {"edition_id": edition_id, **result}


def correct_edition(edition_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    person(actor, role="editor", db_path=db_path)
    edition = _edition(edition_id, db_path=db_path)
    if edition["state"] not in {"published", "corrected", "retracted"}:
        raise ValueError("corrections require an existing publication")
    action = payload.get("action")
    if action not in {"correction", "retraction"}:
        raise ValueError("invalid correction action")
    reason = text(payload.get("reason"), "public correction reason")
    draft = dict(edition["draft"])
    draft["correction_action"] = action
    if action == "correction":
        draft["body_markdown"] = text(payload.get("body_markdown"), "corrected draft", limit=200000)
    else:
        draft["items"] = []
        draft["body_markdown"] = f"# Retraction: {draft['title']}\n\n{reason}\n\nThe original record remains preserved in SecOpsAI's editorial audit history."
    draft["body_markdown"] += f"\n\n## Correction history\n\n{soc_store.utc_now()}: {reason}"
    with transaction(db_path) as conn:
        append("edition_correction", {"edition_id": edition_id, "action": action, "reason": reason, "before": edition["draft"], "after": draft}, actor=actor, connection=conn)
        conn.execute("UPDATE research_editorial_editions SET state='verifying',draft_json=?,fingerprint=?,updated_at=? WHERE edition_id=?", (canonical(draft), digest(draft), soc_store.utc_now(), edition_id))
    return _edition(edition_id, db_path=db_path)


def update_board(case_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    from secopsai.research_cases import get_case
    case = get_case(case_id, db_path=db_path)
    owner = payload.get("owner_id")
    person(owner, role="researcher", db_path=db_path)
    state = payload.get("state")
    if state not in BOARD_STATES or payload.get("product") not in PRODUCTS:
        raise ValueError("invalid editorial state or product")
    program = payload.get("program")
    if program not in {"software_supply_chain", "ai_agent_security"}:
        raise ValueError("initial research programs are software supply chains and AI/agent security")
    latest = {}
    soc_store.init_db(db_path)
    with read_connection(db_path) as conn:
        case_ids = [r[0] for r in conn.execute("SELECT DISTINCT case_id FROM research_operation_records WHERE kind='editorial_board'")]
    for identity in case_ids:
        latest[identity] = records("editorial_board", case_id=identity, db_path=db_path)[0]["payload"]
    active = sum(v.get("owner_id") == owner and v["state"] in {"verifying", "vendor_contact", "technical_review"} and v["product"] != "daily_brief" for k, v in latest.items() if k != case_id)
    if active >= 2 and state in {"verifying", "vendor_contact", "technical_review"}:
        raise ValueError("researcher already has two active original investigations")
    if state in {"approved", "published"} and not case["research_assurance"]["ready"]:
        raise ValueError("editorial state requires current independent review gates")
    value = {"state": state, "owner_id": owner, "product": payload["product"], "program": program,
             "channel": payload.get("channel", "planned_investigation"), "next_action": text(payload.get("next_action"), "next action"),
             "due_at": payload.get("due_at"), "hypothesis": text(payload.get("hypothesis", ""), "research hypothesis", required=False)}
    if value["channel"] not in {"continuous_monitoring", "planned_investigation", "partner_submission"}:
        raise ValueError("invalid discovery channel")
    return append("editorial_board", value, actor=actor, case_id=case_id, db_path=db_path)


def scheduled_brief(*, db_path=None, now=None) -> dict:
    local = (now or datetime.now(TIMEZONE)).astimezone(TIMEZONE)
    if local.hour < 16:
        return {"status": "waiting", "assemble_at": "16:00 Europe/Istanbul"}
    return create_daily_brief(date=local.date().isoformat(), db_path=db_path)
