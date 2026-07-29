"""Evidence-linked detection rule proposals for research cases.

The generator is deterministic. It creates reviewable defensive rules only from
stored evidence and validated IOCs; it never treats model output as evidence and
never activates a proposal without an explicit review decision.
"""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import closing
from typing import Any, Dict, Iterable, Optional

import soc_store
from secopsai.research_cases import add_rule, get_case
from secopsai.research_rules import evaluate_rule


SCHEMA_VERSION = "secopsai.research.rule-proposal.v1"
REVIEWABLE_STATUS = "review_required"
DECISIONS = {"accepted", "rejected"}


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _proposal_id(case_id: str, rule_type: str, name: str) -> str:
    digest = hashlib.sha256(f"{case_id}|{rule_type}|{name}".encode()).hexdigest()[:16].upper()
    return f"RRP-{digest}"


def _rule_name(*parts: str) -> str:
    value = "_".join(parts)
    value = re.sub(r"[^A-Za-z0-9_]", "_", value)
    value = re.sub(r"_+", "_", value).strip("_")
    if not value or value[0].isdigit():
        value = f"SecOpsAI_{value}"
    return value[:120]


def _yara_hash_rule(case_id: str, evidence: Dict[str, Any]) -> Dict[str, str]:
    digest = str(evidence["sha256"]).lower()
    rule_name = _rule_name("SecOpsAI", case_id, evidence["evidence_id"], "ArtifactHash")
    content = f'''import "hash"

rule {rule_name} {{
  meta:
    description = "Matches a reviewed SecOpsAI research artifact by SHA-256"
    case_id = "{case_id}"
    evidence_id = "{evidence['evidence_id']}"
    artifact_sha256 = "{digest}"
  condition:
    filesize > 0 and hash.sha256(0, filesize) == "{digest}"
}}
'''
    return {
        "rule_type": "yara",
        "name": rule_name,
        "purpose": "Detect the exact suspect artifact recorded in reviewed package evidence.",
        "content": content,
        "source_evidence_id": str(evidence["evidence_id"]),
        "source_kind": "suspect_artifact_sha256",
    }


def _eligible_artifact_evidence(case: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    seen: set[str] = set()
    for item in case.get("evidence") or []:
        digest = str(item.get("sha256") or "").lower()
        metadata = item.get("metadata") or {}
        if item.get("status") != "active" or item.get("evidence_type") != "package_artifact":
            continue
        if not re.fullmatch(r"[a-f0-9]{64}", digest):
            continue
        if str(metadata.get("comparison_role") or "suspect").lower() == "reference":
            continue
        if digest in seen:
            continue
        seen.add(digest)
        yield item


def _ioc_rules(case: Dict[str, Any]) -> Iterable[Dict[str, str]]:
    iocs = [
        item for item in (case.get("iocs") or [])
        if item.get("status") == "active" and int(item.get("confidence") or 0) >= 70
    ]
    network = [item for item in iocs if item.get("ioc_type") in {"domain", "ipv4", "ipv6"}]
    if network:
        source = next((item.get("source_evidence_id") for item in network if item.get("source_evidence_id")), None)
        host_values = [str(item["value"]) for item in network if item["ioc_type"] == "domain"]
        ip_values = [str(item["value"]) for item in network if item["ioc_type"] in {"ipv4", "ipv6"}]
        selections = []
        if host_values:
            selections.append("  selection_domain:\n    DestinationHostname:\n" + "".join(f"      - {json.dumps(value)}\n" for value in host_values))
        if ip_values:
            selections.append("  selection_ip:\n    DestinationIp:\n" + "".join(f"      - {json.dumps(value)}\n" for value in ip_values))
        name = _rule_name("secopsai", case["case_id"], "network_iocs").lower()
        yield {
            "rule_type": "sigma",
            "name": name,
            "purpose": "Detect network connections to high-confidence indicators linked to this research case.",
            "content": (
                f"title: SecOpsAI network indicators for {case['case_id']}\n"
                "status: experimental\n"
                "logsource:\n  category: network_connection\n"
                "detection:\n" + "".join(selections) + "  condition: 1 of selection_*\n"
                "falsepositives:\n  - Verify the destination against current threat intelligence and approved infrastructure.\n"
                "level: high\n"
            ),
            "source_evidence_id": str(source or ""),
            "source_kind": "validated_network_iocs",
        }

    source_iocs = [item for item in iocs if item.get("ioc_type") in {"domain", "url"}]
    if source_iocs:
        source = next((item.get("source_evidence_id") for item in source_iocs if item.get("source_evidence_id")), None)
        expression = "|".join(re.escape(str(item["value"])) for item in source_iocs)
        name = _rule_name("secopsai", case["case_id"], "hardcoded_iocs").lower()
        yield {
            "rule_type": "semgrep",
            "name": name,
            "purpose": "Find source code containing high-confidence domains or URLs linked to this case.",
            "content": (
                "rules:\n"
                f"  - id: {name}\n"
                "    message: Source contains a high-confidence SecOpsAI research indicator\n"
                "    severity: WARNING\n"
                f"    pattern-regex: {json.dumps(expression)}\n"
                "    metadata:\n"
                f"      secopsai_case_id: {case['case_id']}\n"
                "      evidence_boundary: static-indicator-match\n"
            ),
            "source_evidence_id": str(source or ""),
            "source_kind": "validated_source_iocs",
        }


def _store_proposal(case_id: str, proposal: Dict[str, str], *, db_path: Optional[str]) -> Dict[str, Any]:
    evaluation = evaluate_rule(rule_type=proposal["rule_type"], content=proposal["content"])
    validation = evaluation["validation"]
    status = REVIEWABLE_STATUS if validation.get("status") == "passed" else "failed_validation"
    proposal_id = _proposal_id(case_id, proposal["rule_type"], proposal["name"])
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """INSERT INTO research_rule_proposals
            (proposal_id, case_id, rule_type, name, purpose, content, source_evidence_id,
             source_kind, validation_status, validation_json, test_json, status, reviewer,
             review_note, active_rule_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '', NULL, ?, ?)
            ON CONFLICT(case_id, rule_type, name) DO UPDATE SET
              purpose = excluded.purpose, content = excluded.content,
              source_evidence_id = excluded.source_evidence_id, source_kind = excluded.source_kind,
              validation_status = excluded.validation_status, validation_json = excluded.validation_json,
              test_json = excluded.test_json,
              status = CASE WHEN research_rule_proposals.status IN ('accepted', 'rejected') THEN research_rule_proposals.status ELSE excluded.status END,
              updated_at = excluded.updated_at""",
            (
                proposal_id, case_id, proposal["rule_type"], proposal["name"], proposal["purpose"],
                proposal["content"], proposal.get("source_evidence_id") or None, proposal["source_kind"],
                validation.get("status") or "failed", _json(validation), _json(evaluation), status, now, now,
            ),
        )
        connection.commit()
    return {"proposal_id": proposal_id, "status": status, "validation": validation}


def list_rule_proposals(case_id: str, *, db_path: Optional[str] = None) -> list[Dict[str, Any]]:
    get_case(case_id, db_path=db_path)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            "SELECT * FROM research_rule_proposals WHERE case_id = ? ORDER BY created_at, proposal_id",
            (case_id,),
        ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["validation"] = json.loads(item.pop("validation_json") or "{}")
        item["test"] = json.loads(item.pop("test_json") or "{}")
        result.append(item)
    return result


def generate_rule_proposals(case_id: str, *, actor: str = "secopsai-rule-generator", db_path: Optional[str] = None) -> Dict[str, Any]:
    case = get_case(case_id, db_path=db_path)
    candidates = [_yara_hash_rule(case_id, item) for item in _eligible_artifact_evidence(case)]
    candidates.extend(_ioc_rules(case))
    generated = [_store_proposal(case_id, item, db_path=db_path) for item in candidates]
    proposals = list_rule_proposals(case_id, db_path=db_path)
    limitations = []
    if not any(item["rule_type"] == "sigma" for item in proposals):
        limitations.append("Sigma requires high-confidence domain or IP indicators linked to case evidence.")
    if not any(item["rule_type"] == "semgrep" for item in proposals):
        limitations.append("Semgrep requires high-confidence source indicators linked to case evidence.")
    if not proposals:
        limitations.append("No reviewed suspect artifact hash or validated IOC is available for rule generation.")
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            "INSERT INTO research_case_events (case_id, event_type, actor, message, data_json, created_at) VALUES (?, 'rule_proposals_generated', ?, ?, ?, ?)",
            (case_id, actor[:160], f"Generated or refreshed {len(generated)} evidence-linked rule proposal(s).", _json({"proposal_ids": [item["proposal_id"] for item in generated], "limitations": limitations}), now),
        )
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        connection.commit()
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "generated": len(generated),
        "review_required": sum(item["status"] == REVIEWABLE_STATUS for item in proposals),
        "failed_validation": sum(item["status"] == "failed_validation" for item in proposals),
        "limitations": limitations,
        "proposals": proposals,
    }


def review_rule_proposal(
    case_id: str,
    proposal_id: str,
    *,
    decision: str,
    actor: str = "analyst",
    review_note: str = "",
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    decision = str(decision or "").strip().lower()
    if decision not in DECISIONS:
        raise ValueError("rule proposal decision must be accepted or rejected")
    proposal = next((item for item in list_rule_proposals(case_id, db_path=db_path) if item["proposal_id"] == proposal_id), None)
    if proposal is None:
        raise ValueError("rule proposal does not belong to this case")
    if proposal["status"] in DECISIONS:
        return {"case": get_case(case_id, db_path=db_path), "proposal": proposal}
    if proposal["status"] != REVIEWABLE_STATUS:
        raise ValueError("only structurally valid rule proposals can be reviewed")
    active_rule_id = None
    if decision == "accepted":
        updated_case = add_rule(
            case_id,
            rule_type=proposal["rule_type"],
            name=proposal["name"],
            content=proposal["content"],
            purpose=proposal["purpose"],
            source_evidence_id=proposal.get("source_evidence_id"),
            actor=actor,
            db_path=db_path,
        )
        active_rule_id = next(
            item["rule_id"] for item in updated_case["rules"]
            if item["rule_type"] == proposal["rule_type"] and item["name"] == proposal["name"]
        )
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            "UPDATE research_rule_proposals SET status = ?, reviewer = ?, review_note = ?, active_rule_id = ?, updated_at = ? WHERE proposal_id = ?",
            (decision, actor[:160], str(review_note or "")[:2000], active_rule_id, now, proposal_id),
        )
        connection.execute(
            "INSERT INTO research_case_events (case_id, event_type, actor, message, data_json, created_at) VALUES (?, 'rule_proposal_reviewed', ?, ?, ?, ?)",
            (case_id, actor[:160], f"Rule proposal {proposal_id} was {decision}.", _json({"proposal_id": proposal_id, "decision": decision, "active_rule_id": active_rule_id}), now),
        )
        connection.execute("UPDATE research_cases SET updated_at = ? WHERE case_id = ?", (now, case_id))
        connection.commit()
    return {
        "case": get_case(case_id, db_path=db_path),
        "proposal": next(item for item in list_rule_proposals(case_id, db_path=db_path) if item["proposal_id"] == proposal_id),
    }
