"""Evidence-led routing for research findings and registry candidates.

Review priority and publication readiness are independent decisions.  Scores
are intentionally excluded from both decisions.  Candidate metadata can route
work to validation, but only a current evidence-linked human assessment can
raise an item to urgent review or publication candidacy.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from secopsai.research_operation_store import records


POLICY_VERSION = "evidence-routing-v1"
ROUTES = {"urgent_review", "validate", "publication_candidate", "close_or_suppress"}
HIGH_SIGNAL_CATEGORIES = {"credential_access", "execution", "network", "lifecycle"}
IMPACT_INDICATORS = {
    "active_exploitation",
    "credential_theft",
    "harmful_install_time_behavior",
    "victim_exposure",
}


def _active_evidence(case: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(item.get("evidence_id")): item
        for item in case.get("evidence") or []
        if item.get("status", "active") == "active" and item.get("evidence_id")
    }


def _observations(value: Any) -> list[dict[str, Any]]:
    """Extract typed static observations without scanning prose or snippets."""
    found: list[dict[str, Any]] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            category = str(item.get("category") or "").lower()
            if (
                category in HIGH_SIGNAL_CATEGORIES
                and item.get("contributes_to_score") is True
                and item.get("context_classification") not in {"documentation", "test", "example", "static_data"}
                and item.get("reachability_status") in {"direct_call", "package_manager_lifecycle", "autoload"}
            ):
                found.append(item)
            stack.extend(v for k, v in item.items() if k not in {"snippet", "notes", "reason"})
        elif isinstance(item, list):
            stack.extend(item)
    unique: dict[str, dict[str, Any]] = {}
    for item in found:
        key = str(item.get("observation_fingerprint") or "")
        if not key:
            key = hashlib.sha256(json.dumps({k: item.get(k) for k in ("rule_id", "category", "path", "source_range")}, sort_keys=True).encode()).hexdigest()
        unique[key] = item
    return list(unique.values())


def _grouping(candidate: dict[str, Any]) -> dict[str, str]:
    ecosystem = str(candidate.get("ecosystem") or "unknown").strip().lower()
    package = re.sub(r"\s+", "", str(candidate.get("package") or candidate.get("identifier") or "unknown")).lower()
    version = str(candidate.get("version") or "unknown").strip().lower()
    behavior = candidate.get("evidence") if isinstance(candidate.get("evidence"), dict) else {}
    observations = _observations(behavior)
    fingerprints = sorted({str(item.get("observation_fingerprint")) for item in observations if item.get("observation_fingerprint")})
    campaign = str(candidate.get("campaign_id") or "").strip()
    return {
        "package_key": f"{ecosystem}:{package}",
        "release_key": f"{ecosystem}:{package}@{version}",
        "behavior_key": hashlib.sha256("|".join(fingerprints).encode()).hexdigest()[:20] if fingerprints else "",
        "campaign_key": campaign,
    }


def route_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    """Route a registry lead without mistaking similarity for impact."""
    evidence = candidate.get("evidence") if isinstance(candidate.get("evidence"), dict) else {}
    observations = _observations(evidence)
    artifact_hash = str(evidence.get("artifact_sha256") or "").lower()
    exact_artifact = bool(re.fullmatch(r"[a-f0-9]{64}", artifact_hash))
    reasons = ["registry discovery is a lead, not a maliciousness or publication finding"]
    gaps = []
    if not exact_artifact:
        gaps.append("exact package artifact and SHA-256 have not been recorded")
    if not observations:
        gaps.append("no behavior-level structural observation is recorded")
    if not evidence.get("comparison") and not evidence.get("version_comparison"):
        gaps.append("release comparison has not been recorded")
    if not evidence.get("prior_art"):
        gaps.append("prior-art search has not been recorded")
    publisher_mismatch = evidence.get("publisher_mismatch") is True
    manual_review = bool(observations or publisher_mismatch)
    if observations:
        reasons.append("structured executable behavior is present and needs contextual technical review")
    if publisher_mismatch:
        reasons.append("the exact package name is published by an identity outside the recorded expected-publisher set")
        gaps.append("independently verify publisher identity and ownership")
    if not manual_review:
        reasons.append("name similarity and registry metadata alone do not trigger a human threat review")
    return {
        "policy_version": POLICY_VERSION,
        "route": "validate",
        "review_required": manual_review,
        "review_priority": "routine" if manual_review else "none",
        "publication_candidate": False,
        "publication_blockers": [
            "a registry candidate is not a substantiated research case",
            "claim-level evidence assessment, reproducibility or independent corroboration, scope, prior art, disclosure and review are incomplete",
        ],
        "reasons": reasons,
        "evidence_gaps": gaps,
        "next_actions": ["acquire and hash the exact artifact", "inspect complete relevant code and install hooks", "compare adjacent releases", "search prior reports"],
        "grouping": _grouping(candidate),
    }


def _current_claims(case: dict[str, Any]) -> list[dict[str, Any]]:
    state = case.get("research_assurance") if isinstance(case.get("research_assurance"), dict) else {}
    evidence = _active_evidence(case)
    result = []
    for claim in state.get("assessed_claims") or []:
        if not claim.get("current") or claim.get("assessment") not in {"observation", "source_reported"}:
            continue
        refs = claim.get("references") if isinstance(claim.get("references"), list) else []
        active_refs = [ref for ref in refs if ref.get("evidence_id") in evidence]
        if not active_refs:
            continue
        result.append({**claim, "active_references": active_refs})
    return result


def _current_disposition(case: dict[str, Any], db_path=None) -> dict[str, Any] | None:
    from secopsai.research_assurance import case_fingerprint, digest, person

    for record in records("case_disposition", case_id=str(case.get("case_id") or ""), db_path=db_path):
        if record.get("fingerprint") != case_fingerprint(case):
            continue
        payload = record.get("payload") or {}
        test = payload.get("regression_test") if isinstance(payload.get("regression_test"), dict) else {}
        if payload.get("decision") not in {"benign", "duplicate"} or test.get("result") != "passed":
            continue
        try:
            reviewer = person(str(record.get("actor") or ""), role="technical_reviewer", db_path=db_path)
        except ValueError:
            continue
        if payload.get("reviewer_fingerprint") != digest(reviewer):
            continue
        return {"decision": payload["decision"], "reason": payload.get("explanation", ""), "duplicate_case_id": payload.get("duplicate_case_id", ""), "regression_test": test, "evidence_references": payload.get("references", [])}
    return None


def route_case(case: dict[str, Any], *, db_path=None) -> dict[str, Any]:
    """Assess review urgency separately from publication candidacy."""
    evidence = _active_evidence(case)
    claims = _current_claims(case)
    review = case.get("research_assurance") if isinstance(case.get("research_assurance"), dict) else {}
    publication = case.get("publication_readiness") if isinstance(case.get("publication_readiness"), dict) else {}
    observations = _observations([item.get("metadata") or {} for item in evidence.values()])
    blockers: list[str] = []
    if not claims:
        blockers.append("no current evidence-linked technical claim assessment")
    substantiated = [claim for claim in claims if claim.get("malicious_behavior") is True]
    if not substantiated:
        blockers.append("no current claim establishes a behavior or event within its stated scope")
    if not bool(case.get("potential_impact_explicit")):
        blockers.append("scope and impact have not been explicitly assessed for this case")
    if not review.get("prior_art_current"):
        blockers.append("dated prior-art searches and the specific contribution are not current")
    if not review.get("technical_review_current"):
        blockers.append("independent qualified technical review is not current")
    technical = (review.get("reviews") or {}).get("technical_reviewer") or {}
    checks = technical.get("checks") if isinstance(technical.get("checks"), dict) else {}
    if checks.get("reproduction") != "passed":
        blockers.append("reproduction or independent corroboration has not passed technical review")
    if checks.get("materiality") != "passed":
        blockers.append("material usefulness has not passed technical review")
    if case.get("disclosure_status") not in {"not_required", "disclosed", "closed"}:
        blockers.append("disclosure requirements are not complete")
    if not publication.get("ready"):
        blockers.extend(str(v) for v in publication.get("blockers") or [])
    if not review.get("editorial_review_current"):
        blockers.append("independent editorial approval of the exact draft is not current")
    blockers = list(dict.fromkeys(blockers))

    urgent_claims = [
        claim for claim in claims
        if claim.get("malicious_behavior") is True
        and set(claim.get("impact_indicators") or []) & IMPACT_INDICATORS
    ]
    urgent_indicators = sorted({indicator for claim in urgent_claims for indicator in claim.get("impact_indicators") or []})
    disposition = _current_disposition(case, db_path=db_path)
    gaps = []
    if not any(item.get("evidence_type") == "package_artifact" and item.get("sha256") for item in evidence.values()):
        gaps.append("hash-verified package or primary incident artifact")
    if observations and not case.get("assessment_calibration", {}).get("unique_observations"):
        gaps.append("structured behavior observations linked to the evidence ledger")
    if not claims:
        gaps.append("qualified claim-to-evidence assessment")
    if "reproduction or independent corroboration has not passed technical review" in blockers:
        gaps.append("reproduction output or independently corroborating primary evidence")
    if not review.get("prior_art_current"):
        gaps.append("dated prior-art searches and a precise contribution statement")

    if case.get("status") == "closed" and disposition:
        route = "close_or_suppress"
        review_required = False
        priority = "none"
        reasons = [f"closed by a current, qualified human {disposition['decision']} disposition", "documented evidence and a passing regression test are recorded"]
        next_actions = ["retain the audit record and reopen if material evidence changes"]
    elif urgent_claims:
        route = "urgent_review"
        review_required = True
        priority = "immediate"
        reasons = ["a qualified reviewer linked a scoped claim to an urgent impact indicator", *urgent_indicators]
        next_actions = ["notify the duty reviewer", "preserve cited evidence", "assess exposure and disclosure risk"]
    elif not blockers and substantiated and review.get("technical_review_current") and review.get("prior_art_current"):
        route = "publication_candidate"
        review_required = False
        priority = "publication"
        reasons = ["material claims are evidence-linked, scoped, technically reviewed, corroborated or reproduced, novel against current prior-art review, and disclosure-ready"]
        next_actions = ["retain final human release approval for the exact reviewed draft"]
    else:
        route = "validate"
        review_required = bool(substantiated or observations)
        priority = "routine" if review_required else "none"
        reasons = ["publication eligibility is a separate decision and has not passed", *blockers]
        next_actions = ["collect the missing evidence and complete the next independent review"] if review_required else ["run bounded artifact and source validation before requesting human review"]
        if case.get("status") == "closed" and not disposition:
            reasons.append("case is closed without a current documented benign/duplicate disposition and passing regression check")
            review_required = True
            priority = "routine"
    return {
        "policy_version": POLICY_VERSION,
        "route": route,
        "review_required": review_required,
        "review_priority": priority,
        "publication_candidate": route == "publication_candidate",
        "publication_blockers": blockers,
        "reasons": reasons,
        "evidence_gaps": list(dict.fromkeys(gaps)),
        "urgent_indicators": urgent_indicators,
        "urgent_evidence_ids": sorted({ref.get("evidence_id") for claim in urgent_claims for ref in claim.get("active_references") or [] if ref.get("evidence_id")}),
        "disposition": disposition,
        "next_actions": next_actions,
        "grouping": _grouping({"ecosystem": (case.get("subjects") or [{}])[0].get("ecosystem"), "package": (case.get("subjects") or [{}])[0].get("name"), "version": (case.get("subjects") or [{}])[0].get("version")}),
    }


def create_urgent_review_alert(case: dict[str, Any], claim: dict[str, Any], *, db_path=None) -> dict[str, Any] | None:
    """Persist an in-console urgent review alert from a qualified claim."""
    indicators = sorted(set(claim.get("impact_indicators") or []) & IMPACT_INDICATORS)
    evidence_ids = sorted({str(item.get("evidence_id")) for item in claim.get("references") or [] if item.get("evidence_id")})
    if not indicators or not evidence_ids:
        return None
    import soc_store
    from contextlib import closing
    from secopsai.research_discovery import _id, _json, _upsert_research_alert_finding
    from secopsai.sqlite_writer_lock import sqlite_writer_lock

    fingerprint = str(claim.get("fingerprint") or "")
    dedupe = "urgent-case-review:" + hashlib.sha256(f"{case['case_id']}|{fingerprint}|{'|'.join(indicators)}".encode()).hexdigest()
    severity = "critical" if set(indicators) & {"active_exploitation", "victim_exposure"} else "high"
    payload = {"case_id": case["case_id"], "indicators": indicators, "evidence_ids": evidence_ids, "claim_statement_hash": claim.get("statement_hash"), "route": "urgent_review", "publication_approved": False}
    subjects = case.get("subjects") or []
    subject = next((item for item in subjects if item.get("status", "active") == "active"), {})
    with sqlite_writer_lock(db_path):
        with closing(soc_store.connect(db_path)) as connection:
            connection.execute(
                """INSERT OR IGNORE INTO research_alerts
                   (alert_id, alert_type, severity, candidate_id, campaign_id, case_id, dedupe_key,
                    reason, evidence_json, status, owner, created_at, updated_at)
                   VALUES (?, 'urgent_case_review', ?, NULL, NULL, ?, ?, ?, ?, 'open', '', ?, ?)""",
                (_id("RAL"), severity, case["case_id"], dedupe,
                 f"Qualified technical review flagged urgent indicators: {', '.join(indicators)}. This is an escalation signal, not a final publication or maliciousness verdict.",
                 _json({**payload, "ecosystem": subject.get("ecosystem", ""), "package": subject.get("name", ""), "version": subject.get("version", "")}),
                 soc_store.utc_now(), soc_store.utc_now()),
            )
            row = connection.execute("SELECT * FROM research_alerts WHERE dedupe_key=?", (dedupe,)).fetchone()
            if row:
                candidate = {"ecosystem": subject.get("ecosystem", ""), "package": subject.get("name", ""), "version": subject.get("version", ""), "evidence": payload}
                _upsert_research_alert_finding(connection, dict(row), candidate=candidate)
            connection.commit()
    if not row:
        return None
    alert = dict(row)
    from secopsai.research_delivery import deliver_urgent_review_alert

    alert["notification_delivery"] = deliver_urgent_review_alert(str(row["alert_id"]), db_path=db_path)
    return alert


def record_case_disposition(case_id: str, payload: dict[str, Any], *, actor: str, db_path=None) -> dict[str, Any]:
    """Close a benign or duplicate case only with cited evidence and a regression check."""
    import ast
    from secopsai.research_assurance import case_fingerprint, digest, evidence_reference, person, text, timestamp, append
    from secopsai.research_cases import get_case

    case = get_case(case_id, db_path=db_path)
    reviewer = person(actor, role="technical_reviewer", db_path=db_path)
    if actor == case.get("owner"):
        raise ValueError("case disposition requires a qualified reviewer distinct from the author")
    decision = payload.get("decision")
    if decision not in {"benign", "duplicate"}:
        raise ValueError("case disposition must be benign or duplicate")
    explanation = text(payload.get("explanation"), "documented disposition explanation", limit=4000)
    if len(explanation) < 40:
        raise ValueError("document the positive benign explanation or exact duplicate relationship in at least 40 characters")
    references = payload.get("references")
    if not isinstance(references, list) or not references:
        raise ValueError("exact evidence references are required for case disposition")
    checked = [evidence_reference(case, item) for item in references]
    if decision == "benign" and not any(item["evidence_type"] in {"package_artifact", "static_analysis", "sandbox_analysis", "source"} for item in checked):
        raise ValueError("a benign disposition requires positive artifact, behavior, experiment, or primary-source evidence")
    duplicate_case_id = ""
    if decision == "duplicate":
        duplicate_case_id = text(payload.get("duplicate_case_id"), "duplicate case id", limit=32).upper()
        target = get_case(duplicate_case_id, db_path=db_path)
        if target["case_id"] == case["case_id"]:
            raise ValueError("a case cannot be marked duplicate of itself")
        source_hashes = {str(item.get("sha256") or "").lower() for item in case.get("evidence") or [] if item.get("status") == "active" and item.get("sha256")}
        target_hashes = {str(item.get("sha256") or "").lower() for item in target.get("evidence") or [] if item.get("status") == "active" and item.get("sha256")}
        source_subjects = {(item.get("subject_type"), str(item.get("ecosystem") or "").lower(), str(item.get("name") or "").lower(), str(item.get("version") or "").lower()) for item in case.get("subjects") or [] if item.get("status") == "active"}
        target_subjects = {(item.get("subject_type"), str(item.get("ecosystem") or "").lower(), str(item.get("name") or "").lower(), str(item.get("version") or "").lower()) for item in target.get("subjects") or [] if item.get("status") == "active"}
        if not (source_hashes & target_hashes or source_subjects & target_subjects):
            raise ValueError("duplicate cases must share an exact artifact hash or structured subject identity")

    regression = payload.get("regression_test")
    if not isinstance(regression, dict):
        raise ValueError("a passing matching-rule regression test and CI run are required")
    nodeid = text(regression.get("nodeid"), "regression test node id", limit=500)
    path_part, separator, test_part = nodeid.partition("::")
    if not separator or not path_part.startswith("tests/") or ".." in Path(path_part).parts or not path_part.endswith(".py"):
        raise ValueError("regression test must identify a test in the repository tests/ tree")
    test_path = (Path(__file__).resolve().parents[1] / path_part).resolve()
    tests_root = (Path(__file__).resolve().parents[1] / "tests").resolve()
    if tests_root not in test_path.parents or not test_path.is_file():
        raise ValueError("regression test file must exist inside the repository tests/ tree")
    tree = ast.parse(test_path.read_text(encoding="utf-8"))
    defined_names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
    for part in test_part.split("::"):
        if part not in defined_names:
            raise ValueError("regression test node id does not exist in the referenced test file")
    if regression.get("result") != "passed":
        raise ValueError("the matching-rule regression test must be recorded as passed")
    run_url = text(regression.get("run_url"), "regression run URL", limit=1000)
    if not run_url.startswith("https://"):
        raise ValueError("regression run URL must use HTTPS")
    commit_sha = text(regression.get("commit_sha"), "regression commit SHA", limit=40).lower()
    if not re.fullmatch(r"[a-f0-9]{7,40}", commit_sha):
        raise ValueError("regression commit SHA must be a hexadecimal Git revision")
    checked_at = timestamp(str(regression.get("checked_at") or ""))
    value = {"decision": decision, "explanation": explanation, "references": checked, "duplicate_case_id": duplicate_case_id,
             "regression_test": {"nodeid": nodeid, "result": "passed", "run_url": run_url, "commit_sha": commit_sha, "checked_at": checked_at},
             "reviewer_id": actor, "reviewer_fingerprint": digest(reviewer)}
    from secopsai.research_operation_store import transaction

    with transaction(db_path) as connection:
        latest = get_case(case["case_id"], db_path=db_path)
        if case_fingerprint(latest) != case_fingerprint(case):
            raise ValueError("case evidence changed while the disposition was being prepared; refresh and review again")
        record = append("case_disposition", value, actor=actor, case_id=case["case_id"], fingerprint=case_fingerprint(latest), connection=connection)
        if latest.get("status") != "closed":
            import soc_store

            now = soc_store.utc_now()
            connection.execute("UPDATE research_cases SET status='closed', closed_at=COALESCE(closed_at, ?), updated_at=? WHERE case_id=?", (now, now, case["case_id"]))
            connection.execute(
                "INSERT INTO research_case_events (case_id,event_type,actor,message,data_json,created_at) VALUES (?,?,?,?,?,?)",
                (case["case_id"], "case_disposition_recorded", actor,
                 f"Case closed after qualified {decision} disposition with evidence and regression test.",
                 json.dumps({"record_id": record["record_id"], "decision": decision, "duplicate_case_id": duplicate_case_id}, sort_keys=True, separators=(",", ":")), now),
            )
    return {"record": record, "case": get_case(case["case_id"], db_path=db_path)}
