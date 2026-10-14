"""Claim-specific evidence and independent human publication review.

Extraction creates candidates, never factual endorsements. A human assessment
must identify the exact statement, a verifiable evidence span, its scope and
alternatives. Scores and model agreement cannot substitute for those records.
"""
from __future__ import annotations

import json
import math
import re
from contextlib import closing
from typing import Any

import soc_store
from secopsai.research_operation_store import read_connection
from secopsai.research_operation_store import append, canonical, digest, records, text, timestamp, transaction

ASSESSMENTS = {"observation", "source_reported", "inference", "disputed", "unknown"}
TECHNICAL_CHECKS = {"claims", "affected_versions", "reproduction", "alternatives", "detections", "mitigations", "attribution", "limitations"}
EDITORIAL_CHECKS = {"privacy", "secrets", "sharing_rights", "licensing", "embargo", "vendor_coordination", "credits", "conflicts", "exposure_counts"}
ROLES = {"author", "researcher", "technical_reviewer", "editor", "duty_editor", "backup", "operator"}


def register_person(payload: dict, *, actor: str, db_path=None) -> dict:
    soc_store.init_db(db_path)
    with read_connection(db_path) as conn:
        count = conn.execute("SELECT COUNT(*) FROM research_people").fetchone()[0]
    if count:
        person(actor, role="operator", db_path=db_path)
    elif payload.get("person_id") != actor or "operator" not in payload.get("roles", []):
        raise ValueError("initial human registration must explicitly establish the operator")
    person_id = text(payload.get("person_id"), "person_id", limit=160)
    if not re.fullmatch(r"[a-zA-Z0-9_.@-]{3,160}", person_id) or re.search(r"(?:model|agent|bot|jev|clef|system|publisher)$", person_id, re.I):
        raise ValueError("register a named human identity, not a service or model")
    name = text(payload.get("display_name"), "display_name", limit=240)
    roles = payload.get("roles")
    if not isinstance(roles, list) or not roles or not set(roles) <= ROLES:
        raise ValueError("invalid human roles")
    qualification = text(payload.get("qualification"), "qualification", limit=4000)
    active = payload.get("active", True)
    if not isinstance(active, bool):
        raise ValueError("active must be boolean")
    with transaction(db_path) as conn:
        conn.execute("INSERT INTO research_people VALUES (?,?,?,?,?,?,?) ON CONFLICT(person_id) DO UPDATE SET display_name=excluded.display_name,roles_json=excluded.roles_json,qualification=excluded.qualification,active=excluded.active,registered_by=excluded.registered_by,updated_at=excluded.updated_at",
                     (person_id, name, canonical(sorted(set(roles))), qualification, int(active), actor, soc_store.utc_now()))
        append("person_registration", payload, actor=actor, connection=conn)
    return {"person_id": person_id, "display_name": name, "roles": sorted(set(roles)), "qualification": qualification, "active": active}


def person(person_id: str, *, role: str = "", db_path=None) -> dict:
    soc_store.init_db(db_path)
    with read_connection(db_path) as conn:
        row = conn.execute("SELECT * FROM research_people WHERE person_id=?", (person_id,)).fetchone()
    if not row or not row["active"]:
        raise ValueError("active registered human identity is required")
    value = dict(row)
    value["roles"] = json.loads(value.pop("roles_json"))
    if role and role not in value["roles"]:
        raise ValueError(f"human lacks {role} role")
    return value


def case_fingerprint(case: dict) -> str:
    # Workflow status and append-only timelines are excluded: a review survives
    # approval changing the state. All publication facts and evidence are bound.
    fields = {key: case.get(key) for key in ("case_id", "title", "summary", "case_type", "severity", "confidence", "owner", "embargo_until", "disclosure_status", "metadata")}
    for name in ("subjects", "evidence", "iocs", "rules", "claims", "verdicts", "disclosures"):
        fields[name] = sorted((
            {k: v for k, v in item.items() if k not in {"updated_at", "occurrence_count", "last_observed_at"}}
            for item in case.get(name, [])
        ), key=canonical)
    return digest(fields)


def _case(case_id: str, db_path) -> dict:
    from secopsai.research_cases import get_case
    return get_case(case_id, db_path=db_path)


def _number(value: Any, *, field: str, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= maximum:
        raise ValueError(f"invalid {field}")
    return value


def _string_list(value: Any, field: str, *, required=False) -> list[str]:
    if not isinstance(value, list) or len(value) > 100 or (required and not value):
        raise ValueError(f"invalid {field}")
    return [text(item, field, limit=4000) for item in value]


def evidence_reference(case: dict, reference: dict) -> dict:
    evidence = next((item for item in case.get("evidence", []) if item.get("evidence_id") == reference.get("evidence_id") and item.get("status", "active") == "active"), None)
    if evidence is None or not evidence.get("sha256") or not evidence.get("provenance") or not evidence.get("collected_at"):
        raise ValueError("reference requires active evidence with hash, provenance and acquisition time")
    selector = text(reference.get("selector"), "selector", limit=1000)
    # Descriptions, titles, shared hashes and analyst notes are not proof spans.
    categories = ("source_excerpts", "file_contents", "trace_events", "matched_strings", "experiment_output")
    if not any(selector in {f"metadata.{key}", f"/metadata/{key}"} or selector.startswith((f"metadata.{key}.", f"/metadata/{key}/")) for key in categories):
        raise ValueError("reference must select archived source text, code, matched text, trace or experiment output")
    node: Any = evidence
    parts = [p.replace("~1", "/").replace("~0", "~") for p in selector[1:].split("/")] if selector.startswith("/") else selector.split(".")
    for part in parts:
        if isinstance(node, dict):
            node = node.get(part)
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            node = None
    if not isinstance(node, str):
        raise ValueError("evidence selector must resolve to recorded text")
    start, end = reference.get("start"), reference.get("end")
    excerpt = text(reference.get("excerpt"), "excerpt", limit=12000)
    if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(node) or node[start:end] != excerpt:
        raise ValueError("evidence span does not match the archived text exactly")
    return {"evidence_id": evidence["evidence_id"], "selector": selector, "start": start, "end": end, "excerpt": excerpt,
            "sha256": evidence["sha256"], "content_sha256": digest(node), "origin": evidence.get("locator") or evidence["provenance"],
            "acquired_at": evidence["collected_at"], "root_source_key": evidence.get("independent_source_key") or evidence["sha256"],
            "evidence_type": evidence["evidence_type"]}


def assess_claim(case_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    person(actor, role="technical_reviewer", db_path=db_path)
    case = _case(case_id, db_path)
    if actor == case.get("owner"):
        raise ValueError("claim assessment requires a reviewer distinct from the author")
    statement = text(payload.get("statement"), "statement", limit=16000)
    assessment = payload.get("assessment")
    if assessment not in ASSESSMENTS:
        raise ValueError("invalid claim assessment")
    references = payload.get("references")
    if not isinstance(references, list) or not 1 <= len(references) <= 50:
        raise ValueError("precise claim evidence references are required")
    checked = [evidence_reference(case, ref) for ref in references]
    scope = payload.get("scope")
    if not isinstance(scope, dict) or not all(scope.get(key) for key in ("versions", "environment", "sample_set", "observation_period")):
        raise ValueError("claim scope requires versions, environment, sample set and observation period")
    scope = {key: text(scope[key], key, limit=4000) for key in ("versions", "environment", "sample_set", "observation_period")}
    if assessment == "observation" and any(ref["evidence_type"] not in {"static_analysis", "sandbox_analysis", "package_artifact"} for ref in checked):
        raise ValueError("observation requires direct code or experiment evidence; a third-party article is source-reported")
    from secopsai.research_reliability import ATTRIBUTION_TERMS, VICTIM_TERMS, RUNTIME_TERMS

    if assessment == "observation" and (ATTRIBUTION_TERMS.search(statement) or VICTIM_TERMS.search(statement) or re.search(r"\b(?:actor|attacker|victims?|attribution)\b", statement, re.I)):
        raise ValueError("victim impact and actor attribution require corroborated source reporting or an explicitly reviewed inference; lab code cannot establish them")

    if assessment == "observation" and RUNTIME_TERMS.search(statement):
        experiments = records("experiment", case_id=case_id, db_path=db_path)
        if (not any(ref["evidence_type"] == "sandbox_analysis" for ref in checked)
                or not any(r["fingerprint"] == case_fingerprint(case) and r["payload"]["mode"] != "static" for r in experiments)):
            raise ValueError("runtime observations require recorded execution output and a scoped laboratory experiment")
    probability = payload.get("likelihood")
    if probability is not None:
        _number(probability, field="likelihood", maximum=1)
    confidence = _number(payload.get("confidence"), field="analytic confidence", maximum=100)
    malicious = payload.get("malicious_behavior", False)
    if not isinstance(malicious, bool):
        raise ValueError("malicious_behavior must be boolean")
    contradictions = _string_list(payload.get("contradictions"), "contradictions")
    if contradictions and assessment not in {"disputed", "unknown"} and not payload.get("contradiction_resolution"):
        raise ValueError("contrary evidence requires an explicit resolution")
    result = {"statement": statement, "statement_hash": digest(statement), "assessment": assessment, "references": checked,
              "scope": scope, "confidence": confidence, "likelihood": probability, "malicious_behavior": malicious,
              "rationale": text(payload.get("rationale"), "rationale"), "quality": text(payload.get("quality"), "evidence quality"),
              "alternatives": _string_list(payload.get("alternatives"), "alternatives", required=True), "contradictions": contradictions,
              "contradiction_resolution": text(payload.get("contradiction_resolution", ""), "contradiction resolution", required=False),
              "limitations": _string_list(payload.get("limitations"), "limitations"), "reviewer_id": actor,
              "reviewer_fingerprint": digest(person(actor, role="technical_reviewer", db_path=db_path))}
    return append("claim_assessment", result, actor=actor, case_id=case_id, fingerprint=case_fingerprint(case), db_path=db_path)


def claim_assessments(case: dict, *, db_path=None) -> dict[str, dict]:
    result = {}
    fingerprint = case_fingerprint(case)
    for record in records("claim_assessment", case_id=case["case_id"], db_path=db_path):
        value = record["payload"]
        if value["statement_hash"] in result:
            continue
        # Latest assessment wins, including revoked qualification or disputed
        # conclusions. Older favorable decisions cannot be resurrected.
        result[value["statement_hash"]] = {**value, "current": record["fingerprint"] == fingerprint}
        try:
            reviewer = person(record["actor"], role="technical_reviewer", db_path=db_path)
            result[value["statement_hash"]]["current"] &= value.get("reviewer_fingerprint") == digest(reviewer)
        except ValueError:
            result[value["statement_hash"]]["current"] = False
    return result


def record_prior_art(case_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    person(actor, role="researcher", db_path=db_path)
    case = _case(case_id, db_path)
    queries = payload.get("searches")
    if not isinstance(queries, list) or not queries:
        raise ValueError("dated prior-art searches are required")
    for query in queries:
        text(query.get("query"), "query")
        text(query.get("index"), "search index")
        timestamp(query.get("searched_at", ""))
    reports = payload.get("earlier_reports")
    if not isinstance(reports, list):
        raise ValueError("earlier_reports must be explicit, including an empty list")
    for report in reports:
        if not re.match(r"^https://", text(report.get("url"), "prior report URL")):
            raise ValueError("prior-art URL requires HTTPS")
        timestamp(report.get("published_at", ""))
        text(report.get("relationship"), "relationship to contribution")
    value = {"searches": queries, "earlier_reports": reports, "contribution": text(payload.get("contribution"), "specific new contribution"),
             "originality_claim": payload.get("originality_claim", "independent_verification"),
             "limitations": _string_list(payload.get("limitations"), "limitations", required=True)}
    if value["originality_claim"] not in {"original_discovery", "independent_verification", "extension", "source_summary"}:
        raise ValueError("invalid originality claim")
    return append("prior_art", value, actor=actor, case_id=case_id, fingerprint=case_fingerprint(case), db_path=db_path)


def record_experiment(case_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    person(actor, role="researcher", db_path=db_path)
    case = _case(case_id, db_path)
    required = ("artifact_sha256", "affected_versions", "environment", "trigger", "observed_behavior", "competing_explanations", "demonstrated_impact", "mitigation", "reproduction_steps", "authorization_scope", "limitations")
    value = {key: text(payload.get(key), key, limit=16000) for key in required}
    if not re.fullmatch(r"[a-fA-F0-9]{64}", value["artifact_sha256"]) or value["artifact_sha256"].lower() not in {str(e.get("sha256", "")).lower() for e in case["evidence"]}:
        raise ValueError("experiment artifact must match case evidence")
    mode = payload.get("mode")
    if mode not in {"static", "dynamic", "fuzz", "differential", "patch_verification", "detection_test"}:
        raise ValueError("invalid laboratory mode")
    if mode != "static" and not all(payload.get(k) is True for k in ("disposable_system", "synthetic_credentials", "controlled_network", "authorized_target")):
        raise ValueError("execution experiments require disposable systems, synthetic credentials, controlled networking and authorized targets")
    value.update({"mode": mode, "references": [evidence_reference(case, ref) for ref in payload.get("references", [])],
                  "independent_reproduction_of": payload.get("independent_reproduction_of", ""), "researcher_id": actor})
    if not value["references"]:
        raise ValueError("recorded experiment output is required; a recipe is not an observation")
    return append("experiment", value, actor=actor, case_id=case_id, fingerprint=case_fingerprint(case), db_path=db_path)


def record_behavior(case_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    person(actor, role="technical_reviewer", db_path=db_path)
    from secopsai.research_post import ATTACK_TECHNIQUES
    case = _case(case_id, db_path)
    technique = payload.get("technique")
    definition = next((item for item in ATTACK_TECHNIQUES if item[0] == technique), None)
    if not definition:
        raise ValueError("unsupported ATT&CK technique; update the reviewed catalog first")
    statement = text(payload.get("statement"), "behavior statement")
    claim = claim_assessments(case, db_path=db_path).get(digest(statement), {})
    if not claim.get("current") or claim.get("assessment") != "observation":
        raise ValueError("ATT&CK mapping requires a current, reviewed direct observation")
    value = {"technique": technique, "name": definition[1], "tactic": definition[2], "statement": statement,
             "evidence": "; ".join(f"{r['evidence_id']} {r['selector']}[{r['start']}:{r['end']}]" for r in claim["references"]),
             "rationale": text(payload.get("rationale"), "mapping rationale"), "reviewer_id": actor}
    return append("behavior_mapping", value, actor=actor, case_id=case_id, fingerprint=case_fingerprint(case), db_path=db_path)


def review_case(case_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    role = payload.get("role")
    target = payload.get("target", "blog")
    if target not in {"blog", "osv", "technical_advisory", "research_report"}:
        raise ValueError("invalid publication review target")
    if role not in {"technical_reviewer", "editor"}:
        raise ValueError("review role must be technical_reviewer or editor")
    person(actor, role=role, db_path=db_path)
    case = _case(case_id, db_path)
    person(case.get("owner", ""), role="author", db_path=db_path)
    if actor == case["owner"]:
        raise ValueError("publication reviewers must be distinct from the author")
    checks = payload.get("checks")
    required = TECHNICAL_CHECKS if role == "technical_reviewer" else EDITORIAL_CHECKS
    if not isinstance(checks, dict) or set(checks) != required or any(value not in {"passed", "blocked"} for value in checks.values()):
        raise ValueError("every required review check needs an explicit passed or blocked result")
    draft = text(payload.get("draft"), "exact publication draft", limit=200000)
    value = {"role": role, "target": target, "checks": checks, "draft_sha256": digest(draft), "decision": payload.get("decision"),
             "rationale": text(payload.get("rationale"), "review rationale"), "reviewer_id": actor,
             "claim_statements": _string_list(payload.get("claim_statements"), "material claim statements", required=True),
             "reviewer_fingerprint": digest(person(actor, role=role, db_path=db_path)),
             "author_fingerprint": digest(person(case.get("owner", ""), role="author", db_path=db_path))}
    if value["decision"] not in {"approved", "changes_required", "rejected"}:
        raise ValueError("invalid review decision")
    if value["decision"] == "approved":
        if any(v != "passed" for v in checks.values()):
            raise ValueError("blocked review checks cannot be approved")
        claims = claim_assessments(case, db_path=db_path)
        for statement in value["claim_statements"]:
            claim = claims.get(digest(statement), {})
            if statement not in draft or not claim.get("current") or claim.get("assessment") in {"disputed", "unknown", None}:
                raise ValueError("each material claim must be in the draft and have a current evidence assessment")
        prior = records("prior_art", case_id=case_id, db_path=db_path)
        if not prior or prior[0]["fingerprint"] != case_fingerprint(case):
            raise ValueError("a current prior-art ledger is required")
        if role == "editor":
            state = assurance_state(case, draft=draft, target=target, db_path=db_path)
            if not state["technical_review_current"]:
                raise ValueError("editorial release requires independent technical approval of this exact draft")
    record = append("human_review", value, actor=actor, case_id=case_id, fingerprint=case_fingerprint(case), db_path=db_path)
    if role == "technical_reviewer" and value["decision"] == "approved":
        from secopsai.research_coverage import record_case_stage
        record_case_stage(case, "substantiated", db_path=db_path)
    return record


def assurance_state(case: dict, *, draft: str | None = None, target: str = "blog", db_path=None) -> dict:
    fingerprint = case_fingerprint(case)
    reviews = {}
    for record in records("human_review", case_id=case["case_id"], db_path=db_path):
        if record["payload"].get("target", "blog") != target:
            continue
        role = record["payload"]["role"]
        if role in reviews:
            continue
        value = record["payload"]
        current = record["fingerprint"] == fingerprint and value["decision"] == "approved" and record["actor"] != case.get("owner")
        current = current and (draft is None or value["draft_sha256"] == digest(draft))
        try:
            current = current and value.get("reviewer_fingerprint") == digest(person(record["actor"], role=role, db_path=db_path))
            current = current and value.get("author_fingerprint") == digest(person(case.get("owner", ""), role="author", db_path=db_path))
        except ValueError:
            current = False
        reviews[role] = {**value, "current": current, "record_id": record["record_id"]}
    technical, editor = reviews.get("technical_reviewer", {}), reviews.get("editor", {})
    same_draft = bool(technical and editor and technical["draft_sha256"] == editor["draft_sha256"])
    claims = claim_assessments(case, db_path=db_path)
    reviewed = [claims.get(digest(s), {}) for s in technical.get("claim_statements", [])]
    claims_current = bool(reviewed) and all(c.get("current") and c.get("assessment") not in {None, "disputed", "unknown"} for c in reviewed)
    technical_current = bool(technical.get("current") and claims_current)
    editor_current = bool(editor.get("current") and technical_current and same_draft)
    prior = records("prior_art", case_id=case["case_id"], db_path=db_path)
    prior_current = bool(prior and prior[0]["fingerprint"] == fingerprint)
    mappings = []
    seen = set()
    for record in records("behavior_mapping", case_id=case["case_id"], db_path=db_path):
        value = record["payload"]
        if value["technique"] in seen:
            continue
        seen.add(value["technique"])
        claim = claims.get(digest(value["statement"]), {})
        try:
            person(record["actor"], role="technical_reviewer", db_path=db_path)
            mapping_reviewer_active = True
        except ValueError:
            mapping_reviewer_active = False
        if mapping_reviewer_active and record["fingerprint"] == fingerprint and claim.get("current") and claim.get("assessment") == "observation":
            mappings.append(value)
    blockers = []
    if not technical_current:
        blockers.append("current independent qualified human technical review is required")
    if not editor_current:
        blockers.append("current human editorial approval of the same draft is required")
    if not prior_current:
        blockers.append("current dated prior-art searches and contribution record are required")
    for submission in records("partner_submission", case_id=case["case_id"], db_path=db_path):
        if not submission["payload"]["consent"].get("public_release") or submission["payload"]["tlp"] != "CLEAR":
            blockers.append("partner evidence has restricted sharing rights; a separately authorized public evidence set is required")
            break
    return {"policy_version": "research-assurance-v1", "fingerprint": fingerprint, "ready": not blockers, "blockers": blockers,
            "technical_review_current": technical_current, "editorial_review_current": editor_current, "prior_art_current": prior_current,
            "confirmed_observation": bool(technical_current and any(c.get("assessment") == "observation" and c.get("malicious_behavior") for c in reviewed)),
            "reviews": reviews, "behavior_mappings": mappings, "assessed_claims": list(claims.values())}
