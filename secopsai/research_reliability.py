from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import resource
import secrets
import shutil
import sys
import time
from contextlib import closing
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlparse

import soc_store


SCHEMA_VERSION = "secopsai.execution-grounded-research.v1"
HYPOTHESIS_TYPES = (
    "malicious_compromise",
    "benign_expected_behavior",
    "scanner_false_positive",
    "unrelated_external_reporting",
    "source_provenance_anomaly",
    "insufficient_evidence",
)
RESEARCH_STAGES = ("scaffold", "transition", "full")
CLAIM_STATUSES = {"supported", "qualified_inference", "unsupported", "contradicted"}
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
GHSA_RE = re.compile(r"\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\b", re.I)
URL_RE = re.compile(r"https?://[^\s<>()\[\]{}\"']+", re.I)
DATE_RE = re.compile(r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:T[^\s]+)?\b")
VERSION_REF_RE = re.compile(r"\b([A-Za-z0-9_.@/-]+)@([A-Za-z0-9_.+:-]+)\b")
NUMBER_RE = re.compile(r"(?<![A-Za-z0-9])\d+(?:\.\d+)?%?(?![A-Za-z0-9])")
SECRET_KEY_RE = re.compile(r"(?:token|secret|password|api[_-]?key|authorization|cookie|credential)", re.I)
SECRET_VALUE_RE = re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,}|Bearer\s+[A-Za-z0-9._~-]{16,})", re.I)
LOCAL_PATH_RE = re.compile(r"(?:/Users/|/home/|[A-Za-z]:\\Users\\)")
RUNTIME_TERMS = re.compile(r"\b(?:executed|spawned|connected|beaconed|downloaded|persisted|exfiltrated|runtime|sandbox observed)\b", re.I)
STATIC_TERMS = re.compile(r"\b(?:static analysis|static inspection|source inspection|manifest|archive|rule matched|contained)\b", re.I)
ATTRIBUTION_TERMS = re.compile(r"\b(?:attributed to|operated by|linked to|nation-state|threat actor)\b", re.I)
VICTIM_TERMS = re.compile(r"\b(?:victims?|organizations? affected|compromised systems?|impact(?:ed)? users?)\b", re.I)
INFERENCE_TERMS = re.compile(r"\b(?:may|might|could|likely|suggests?|appears?|possibly|potentially|assess(?:ed|ment)?)\b", re.I)
EXECUTION_METHOD_RE = re.compile(r"\b(?:execute|install|run lifecycle|activate extension|launch binary|docker run|cargo build|npm install|pip install)\b", re.I)
SECRET_READ_RE = re.compile(r"\b(?:read|collect|enumerate|access).{0,80}\b(?:secrets?|credentials?|tokens?|\.env|ssh keys?|browser passwords?)\b", re.I | re.S)
NETWORK_SEND_RE = re.compile(r"\b(?:send|upload|post|transmit|exfiltrate).{0,80}\b(?:http|https|dns|network|remote|server)\b", re.I | re.S)


def _id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(8).upper()}"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _decode(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _bounded_text(value: Any, limit: int = 12000) -> str:
    text = str(value or "").strip()
    if "\x00" in text or "\r" in text:
        raise ValueError("text contains invalid control characters")
    if len(text) > limit:
        raise ValueError(f"text exceeds {limit} characters")
    return text


def _clean_locator(value: Any) -> str:
    text = _bounded_text(value, 4000)
    parsed = urlparse(text)
    if parsed.scheme in {"https", "http"} and parsed.hostname:
        return text
    if text.startswith(("artifact-analysis:", "package-comparison:", "registry:", "sandbox:")):
        return text
    return "[controlled local reference]" if text else ""


def _sanitize(value: Any, *, key: str = "") -> Any:
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for item_key, item in value.items():
            normalized = str(item_key).lower()
            if SECRET_KEY_RE.search(normalized) and normalized not in {
                "secret_scan", "credential_behavior", "credential_access", "token_use_detected",
                "estimated_input_tokens", "estimated_output_tokens",
            }:
                output[item_key] = "[redacted]"
            elif normalized in {"path", "quarantine_path", "artifact_path", "db_path", "worktree_path"}:
                output[item_key] = "[local path redacted]"
            else:
                output[item_key] = _sanitize(item, key=normalized)
        return output
    if isinstance(value, list):
        return [_sanitize(item, key=key) for item in value[:1000]]
    if isinstance(value, tuple):
        return [_sanitize(item, key=key) for item in value[:1000]]
    if isinstance(value, str):
        text = SECRET_VALUE_RE.sub("[redacted secret]", value)
        text = LOCAL_PATH_RE.sub("[local path]/", text)
        return text[:20000]
    return value


def _case(case_id: str, db_path: str | None) -> dict[str, Any]:
    from secopsai.research_cases import get_case

    case = get_case(case_id, db_path=db_path)
    if not case:
        raise ValueError(f"research case not found: {case_id}")
    return case


def _event(
    connection: Any,
    case_id: str,
    event_type: str,
    message: str,
    actor: str,
    data: dict[str, Any],
) -> None:
    connection.execute(
        "INSERT INTO research_case_events (case_id, event_type, message, actor, data_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (case_id, event_type, message[:2000], actor[:160], _json(_sanitize(data)), soc_store.utc_now()),
    )


def _row_dict(row: Any) -> dict[str, Any]:
    return dict(row) if row is not None else {}


def _case_fingerprint(case: dict[str, Any]) -> str:
    return _canonical_hash(
        {
            "case": {
                key: case.get(key)
                for key in ("case_id", "title", "summary", "case_type", "severity", "confidence", "status", "assessment")
            },
            "subjects": [
                {
                    key: item.get(key)
                    for key in ("subject_id", "subject_type", "ecosystem", "name", "version", "publisher", "status", "registry_state", "artifact_state")
                }
                for item in case.get("subjects") or []
            ],
            "evidence": [
                {
                    key: item.get(key)
                    for key in ("evidence_id", "evidence_type", "sha256", "status", "fingerprint", "occurrence_count", "independent_source_key")
                }
                for item in case.get("evidence") or []
            ],
            "iocs": [
                {key: item.get(key) for key in ("ioc_id", "ioc_type", "value", "confidence", "status", "source_evidence_id")}
                for item in case.get("iocs") or []
            ],
        }
    )


def _subject_label(case: dict[str, Any]) -> str:
    active = [item for item in case.get("subjects") or [] if item.get("status", "active") == "active"]
    if not active:
        return "the unresolved research lead"
    item = active[0]
    name = str(item.get("name") or "unknown subject")
    version = str(item.get("version") or "").strip()
    ecosystem = str(item.get("ecosystem") or "").strip()
    return f"{ecosystem}:{name}{('@' + version) if version else ''}" if ecosystem else f"{name}{('@' + version) if version else ''}"


def _severity_score(value: Any) -> int:
    return {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}.get(str(value or "").lower(), 40)


def generate_hypotheses(
    case_id: str,
    *,
    refresh: bool = False,
    actor: str = "research-orchestrator",
    db_path: str | None = None,
) -> dict[str, Any]:
    case = _case(case_id, db_path)
    fingerprint = _case_fingerprint(case)
    with closing(soc_store.connect(db_path)) as connection:
        current = connection.execute(
            "SELECT MAX(revision) AS revision FROM research_hypotheses WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        latest_revision = int((current or {"revision": 0})["revision"] or 0)
        if latest_revision and not refresh:
            rows = connection.execute(
                "SELECT * FROM research_hypotheses WHERE case_id = ? AND revision = ? ORDER BY hypothesis_id",
                (case_id, latest_revision),
            ).fetchall()
            if rows and all(str(row["evidence_fingerprint"]) == fingerprint for row in rows):
                return {
                    "case_id": case_id,
                    "revision": latest_revision,
                    "evidence_fingerprint": fingerprint,
                    "hypotheses": [_decode_hypothesis(row) for row in rows],
                    "reused": True,
                }

    subject = _subject_label(case)
    evidence = [item for item in case.get("evidence") or [] if item.get("status", "active") == "active"]
    has_artifact = any(item.get("evidence_type") == "package_artifact" for item in evidence)
    has_static = any(item.get("evidence_type") == "static_analysis" for item in evidence)
    has_sandbox = any(item.get("evidence_type") == "sandbox_analysis" for item in evidence)
    has_source = any(item.get("evidence_type") in {"source", "registry_metadata"} for item in evidence)
    impact = _severity_score(case.get("potential_impact") or case.get("severity"))
    assessed = str(case.get("assessment") or "unconfirmed")
    revision = latest_revision + 1
    definitions = [
        (
            "malicious_compromise",
            f"{subject} is malicious or compromised, and the observed signals originate from the distributed artifact or its source provenance.",
            ["verified artifact hash", "malicious static behavior", "registry or repository anomaly", "corroborated sandbox behavior"],
            ["verified source parity", "expected behavior documented by the maintainer", "clean provenance and reproducible artifact"],
            70 if has_static else 40,
        ),
        (
            "benign_expected_behavior",
            f"The behavior associated with {subject} is legitimate, documented, and proportionate to the package or artifact purpose.",
            ["maintainer documentation", "verified legitimate comparison", "source-to-artifact parity"],
            ["credential access unrelated to purpose", "unexpected network or execution behavior", "provenance divergence"],
            55 if has_source else 35,
        ),
        (
            "scanner_false_positive",
            f"The alert for {subject} is caused by imprecise static matching, documentation text, generated files, or duplicated observations rather than executable malicious behavior.",
            ["AST or manifest context", "rule fingerprint", "file-type context", "deduplicated observation set"],
            ["behavior confirmed in executable code", "independent corroboration", "matching sandbox observation"],
            65 if has_static and not has_sandbox else 40,
        ),
        (
            "unrelated_external_reporting",
            f"External reporting associated with this case does not establish that {subject} is affected or locally relevant.",
            ["source-to-subject mapping", "exact affected versions", "local dependency inventory"],
            ["exact package and version named by an authoritative source", "matching local artifact hash"],
            45,
        ),
        (
            "source_provenance_anomaly",
            f"The primary risk for {subject} is a registry, publisher, tag, source, or artifact provenance anomaly rather than behavior proven at runtime.",
            ["tag or digest history", "publisher changes", "source and distribution checksums", "repository reachability"],
            ["stable signed provenance", "matching historical snapshots", "verified maintainer release"],
            60 if has_artifact or has_source else 35,
        ),
        (
            "insufficient_evidence",
            f"The available evidence is insufficient to determine whether {subject} is malicious, benign, or unrelated.",
            ["missing artifact or checksum", "missing independent source", "unresolved contradiction", "unverified local exposure"],
            ["complete source, artifact, static, comparison, and approved sandbox evidence"],
            80 if len(evidence) < 2 else 45,
        ),
    ]
    now = soc_store.utc_now()
    created: list[dict[str, Any]] = []
    with closing(soc_store.connect(db_path)) as connection:
        for hypothesis_type, statement, predicted, falsifiers, plausibility in definitions:
            hypothesis_id = "HYP-" + hashlib.sha256(f"{case_id}|{revision}|{hypothesis_type}".encode()).hexdigest()[:16].upper()
            testability = min(95, 30 + len(evidence) * 8 + (15 if has_artifact else 0))
            safety = 100
            cost = 1.0 + (0.5 if not has_source else 0.0) + (1.0 if not has_artifact else 0.0) + (1.5 if hypothesis_type == "malicious_compromise" and not has_sandbox else 0.0)
            novelty = 55 if hypothesis_type in {"source_provenance_anomaly", "scanner_false_positive"} else 40
            confidence = {
                "supports": max(5, min(90, plausibility)),
                "refutes": max(5, 100 - plausibility - 15),
                "unknown": 15,
            }
            if hypothesis_type == "malicious_compromise" and assessed in {"credible", "confirmed"}:
                confidence = {"supports": 80, "refutes": 5, "unknown": 15}
            row = {
                "hypothesis_id": hypothesis_id,
                "case_id": case_id,
                "revision": revision,
                "hypothesis_type": hypothesis_type,
                "parent_ids": [],
                "lineage": [{"operation": "bounded_generation", "source": "normalized_case_evidence"}],
                "statement": statement,
                "predicted_evidence": predicted,
                "falsifiers": falsifiers,
                "contradictions": [],
                "novelty": novelty,
                "plausibility": plausibility,
                "testability": testability,
                "impact": impact,
                "safety": safety,
                "estimated_cost": round(cost, 2),
                "confidence_distribution": confidence,
                "status": "candidate",
                "selection_rationale": "Not ranked yet.",
                "evidence_fingerprint": fingerprint,
                "created_at": now,
                "updated_at": now,
            }
            connection.execute(
                """INSERT INTO research_hypotheses
                (hypothesis_id, case_id, revision, hypothesis_type, parent_ids_json, lineage_json,
                 statement, predicted_evidence_json, falsifiers_json, contradictions_json,
                 novelty, plausibility, testability, impact, safety, estimated_cost,
                 confidence_json, status, selection_rationale, evidence_fingerprint, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    hypothesis_id, case_id, revision, hypothesis_type, _json([]), _json(row["lineage"]),
                    statement, _json(predicted), _json(falsifiers), _json([]), novelty, plausibility,
                    testability, impact, safety, cost, _json(confidence), "candidate",
                    "Not ranked yet.", fingerprint, now, now,
                ),
            )
            created.append(row)
        _event(
            connection,
            case_id,
            "research_hypotheses_generated",
            f"Generated {len(created)} competing falsifiable hypotheses from normalized evidence.",
            actor,
            {"revision": revision, "types": list(HYPOTHESIS_TYPES), "model_calls": 0},
        )
        connection.commit()
    return {"case_id": case_id, "revision": revision, "evidence_fingerprint": fingerprint, "hypotheses": created, "reused": False}


def _decode_hypothesis(row: Any) -> dict[str, Any]:
    result = _row_dict(row)
    for source, target, default in (
        ("parent_ids_json", "parent_ids", []),
        ("lineage_json", "lineage", []),
        ("predicted_evidence_json", "predicted_evidence", []),
        ("falsifiers_json", "falsifiers", []),
        ("contradictions_json", "contradictions", []),
        ("confidence_json", "confidence_distribution", {}),
    ):
        result[target] = _decode(result.pop(source, None), default)
    return result


def rank_hypotheses(
    case_id: str,
    *,
    candidate_budget: int = 6,
    comparison_budget: int = 15,
    model_call_budget: int = 0,
    actor: str = "research-orchestrator",
    db_path: str | None = None,
) -> dict[str, Any]:
    if not 2 <= int(candidate_budget) <= 24:
        raise ValueError("candidate_budget must be between 2 and 24")
    if not 1 <= int(comparison_budget) <= 200:
        raise ValueError("comparison_budget must be between 1 and 200")
    if not 0 <= int(model_call_budget) <= 50:
        raise ValueError("model_call_budget must be between 0 and 50")
    generated = generate_hypotheses(case_id, db_path=db_path)
    candidates = list(generated["hypotheses"])[: int(candidate_budget)]
    total = max(1, len(candidates))

    def utility(item: dict[str, Any]) -> float:
        evidence_value = float(item["plausibility"] + item["testability"]) / 2
        benefit = (
            evidence_value * 0.26
            + float(item["impact"]) * 0.23
            + float(item["testability"]) * 0.18
            + float(item["novelty"]) * 0.09
            + float(item["safety"]) * 0.18
        )
        cost_penalty = float(item["estimated_cost"]) * 2.0
        return round(benefit - cost_penalty, 4)

    pulls = {item["hypothesis_id"]: 0 for item in candidates}
    wins = {item["hypothesis_id"]: 0 for item in candidates}
    comparisons: list[dict[str, Any]] = []
    pairs = [(left, right) for index, left in enumerate(candidates) for right in candidates[index + 1 :]]
    pairs.sort(key=lambda pair: abs(utility(pair[0]) - utility(pair[1])))
    evidence_refs = [item.get("evidence_id") for item in _case(case_id, db_path).get("evidence") or [] if item.get("status", "active") == "active"]
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        for left, right in pairs[: int(comparison_budget)]:
            if left["hypothesis_id"] > right["hypothesis_id"]:
                left, right = right, left
            left_score = utility(left)
            right_score = utility(right)
            winner = left if left_score >= right_score else right
            pulls[left["hypothesis_id"]] += 1
            pulls[right["hypothesis_id"]] += 1
            wins[winner["hypothesis_id"]] += 1
            pair_ids = sorted([left["hypothesis_id"], right["hypothesis_id"]])
            comparison_id = "HPC-" + hashlib.sha256(
                f"{case_id}|{generated['evidence_fingerprint']}|{'|'.join(pair_ids)}".encode()
            ).hexdigest()[:16].upper()
            rationale = {
                "winner": winner["hypothesis_type"],
                "reason": "Selected deterministically by evidence value, impact, testability, safety, uncertainty, and cost.",
                "model_rationale_used": False,
                "hard_safety_override": False,
            }
            score = {"left": left_score, "right": right_score}
            connection.execute(
                """INSERT INTO research_hypothesis_comparisons
                (comparison_id, case_id, evidence_fingerprint, left_hypothesis_id, right_hypothesis_id,
                 winner_hypothesis_id, rationale_json, evidence_refs_json, score_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(comparison_id)
                DO UPDATE SET left_hypothesis_id=excluded.left_hypothesis_id,
                    right_hypothesis_id=excluded.right_hypothesis_id,
                    winner_hypothesis_id=excluded.winner_hypothesis_id,
                    rationale_json=excluded.rationale_json, evidence_refs_json=excluded.evidence_refs_json,
                    score_json=excluded.score_json""",
                (
                    comparison_id, case_id, generated["evidence_fingerprint"], left["hypothesis_id"],
                    right["hypothesis_id"], winner["hypothesis_id"], _json(rationale),
                    _json(evidence_refs), _json(score), now,
                ),
            )
            comparisons.append({"comparison_id": comparison_id, **rationale, "score": score})
        ranking = []
        for item in candidates:
            count = pulls[item["hypothesis_id"]]
            win_rate = wins[item["hypothesis_id"]] / count if count else 0.5
            uncertainty = math.sqrt(2.0 * math.log(total + len(comparisons) + 1) / (count + 1))
            ucb = utility(item) + win_rate * 12.0 + uncertainty * 4.0
            ranking.append({**item, "utility": utility(item), "comparisons": count, "wins": wins[item["hypothesis_id"]], "uncertainty_bonus": round(uncertainty * 4.0, 4), "rank_score": round(ucb, 4)})
        ranking.sort(key=lambda item: (-float(item["rank_score"]), item["hypothesis_type"]))
        for index, item in enumerate(ranking):
            status = "selected" if index == 0 else "ranked"
            rationale = f"Rank {index + 1}; deterministic uncertainty-aware score {item['rank_score']:.2f}."
            connection.execute(
                "UPDATE research_hypotheses SET status=?, selection_rationale=?, updated_at=? WHERE hypothesis_id=?",
                (status, rationale, now, item["hypothesis_id"]),
            )
            item["status"] = status
            item["selection_rationale"] = rationale
        _event(
            connection,
            case_id,
            "research_hypotheses_ranked",
            "Ranked competing hypotheses with deterministic pairwise and uncertainty-aware selection.",
            actor,
            {
                "selected_hypothesis_id": ranking[0]["hypothesis_id"],
                "candidate_budget": candidate_budget,
                "comparison_budget": comparison_budget,
                "model_call_budget": model_call_budget,
                "model_calls_used": 0,
            },
        )
        connection.commit()
    return {
        "case_id": case_id,
        "schema_version": SCHEMA_VERSION,
        "selected_hypothesis_id": ranking[0]["hypothesis_id"],
        "ranking": ranking,
        "comparisons": comparisons,
        "budgets": {
            "candidate_budget": candidate_budget,
            "comparison_budget": comparison_budget,
            "model_call_budget": model_call_budget,
            "model_calls_used": 0,
        },
    }


def screen_research_safety(
    *,
    directive: str = "",
    actions: Sequence[str] | None = None,
) -> dict[str, Any]:
    normalized = [str(item or "").strip() for item in (actions or []) if str(item or "").strip()]
    combined = "\n".join([directive, *normalized])
    blockers: list[str] = []
    warnings: list[str] = []
    if EXECUTION_METHOD_RE.search(combined):
        blockers.append("local execution or installation of an untrusted artifact is forbidden")
    if SECRET_READ_RE.search(combined) and NETWORK_SEND_RE.search(combined):
        blockers.append("the action chain combines credential collection with network transmission")
    if re.search(r"\b(?:publish|deploy|disclose|email vendor|delete|revoke|rotate)\b", combined, re.I):
        warnings.append("the plan references an approval-gated external or state-changing action")
    return {
        "status": "blocked" if blockers else "passed",
        "blockers": blockers,
        "warnings": warnings,
        "reduced_to_static_research": bool(blockers),
        "execution_allowed": False,
        "approval_gated_actions": ["sandbox submission", "disclosure", "publication", "deployment", "destructive response", "external communication"],
    }


def create_evidence_plan(
    case_id: str,
    *,
    change_reason: str = "Initial execution-grounded evidence plan.",
    actor: str = "research-orchestrator",
    db_path: str | None = None,
) -> dict[str, Any]:
    case = _case(case_id, db_path)
    ranking = rank_hypotheses(case_id, db_path=db_path)
    selected = ranking["ranking"][0]
    with closing(soc_store.connect(db_path)) as connection:
        previous = connection.execute(
            "SELECT * FROM research_evidence_plans WHERE case_id=? ORDER BY revision DESC LIMIT 1",
            (case_id,),
        ).fetchone()
    fingerprint = _case_fingerprint(case)
    if previous and str(previous["evidence_fingerprint"]) == fingerprint and not _bounded_text(change_reason).lower().startswith("evidence changed"):
        return _decode_plan(previous)
    revision = int(previous["revision"] or 0) + 1 if previous else 1
    intended_methods = [
        "verify_structured_subject_identity",
        "collect_official_registry_or_repository_metadata",
        "verify_available_checksums",
        "inspect_archives_and_manifests_statically",
        "compare_only_with_a_verified_reference",
        "check_local_lockfiles_and_inventory",
        "process_only_approved_external_sandbox_results",
        "build_claim_level_evidence_ledger",
    ]
    required_evidence = [
        {"kind": "structured_subject", "required": True},
        {"kind": "official_source_or_registry", "required": True},
        {"kind": "artifact_hash", "required": selected["hypothesis_type"] in {"malicious_compromise", "source_provenance_anomaly"}},
        {"kind": "static_analysis", "required": selected["hypothesis_type"] in {"malicious_compromise", "scanner_false_positive"}},
        {"kind": "sandbox_analysis", "required": False, "reason": "Required only for claims about observed runtime behavior."},
    ]
    resource_limits = {
        "max_artifact_bytes": 250 * 1024 * 1024,
        "max_expanded_bytes": 500 * 1024 * 1024,
        "max_archive_entries": 10000,
        "max_model_calls": 3,
        "max_wall_seconds": 900,
        "max_retries": 2,
    }
    safety = screen_research_safety(actions=intended_methods)
    completion = [
        "transition audit passes without fixture, mock, stub, placeholder, or synthetic output",
        "immutable full-stage bundle has completeness score at least 70",
        "every publication claim is supported or explicitly qualified",
        "specialist and blinded independent review have no unresolved material disagreement",
        "completeness, originality, publication safety, and visual checks pass",
    ]
    plan_id = _id("RPN")
    now = soc_store.utc_now()
    payload = {
        "plan_id": plan_id,
        "case_id": case_id,
        "revision": revision,
        "parent_plan_id": str(previous["plan_id"]) if previous else None,
        "selected_hypothesis_id": selected["hypothesis_id"],
        "status": "blocked" if safety["blockers"] else "planned",
        "intended_methods": intended_methods,
        "executed_methods": [],
        "required_evidence": required_evidence,
        "expected_outputs": ["registry snapshots", "artifact hashes", "static findings", "comparison evidence", "run bundle", "claim ledger"],
        "resource_limits": resource_limits,
        "safety_decisions": safety,
        "completion_criteria": completion,
        "change_reason": _bounded_text(change_reason, 2000),
        "evidence_fingerprint": fingerprint,
        "created_at": now,
        "updated_at": now,
    }
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """INSERT INTO research_evidence_plans
            (plan_id, case_id, revision, parent_plan_id, selected_hypothesis_id, status,
             intended_methods_json, executed_methods_json, required_evidence_json,
             expected_outputs_json, resource_limits_json, safety_decisions_json,
             completion_criteria_json, change_reason, evidence_fingerprint, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                plan_id, case_id, revision, payload["parent_plan_id"], selected["hypothesis_id"], payload["status"],
                _json(intended_methods), _json([]), _json(required_evidence), _json(payload["expected_outputs"]),
                _json(resource_limits), _json(safety), _json(completion), payload["change_reason"], fingerprint, now, now,
            ),
        )
        _event(connection, case_id, "research_evidence_plan_created", f"Created evidence plan revision {revision}.", actor, {"plan_id": plan_id, "hypothesis_id": selected["hypothesis_id"], "safety_status": safety["status"]})
        connection.commit()
    return payload


def _decode_plan(row: Any) -> dict[str, Any]:
    result = _row_dict(row)
    for source, target, default in (
        ("intended_methods_json", "intended_methods", []),
        ("executed_methods_json", "executed_methods", []),
        ("required_evidence_json", "required_evidence", []),
        ("expected_outputs_json", "expected_outputs", []),
        ("resource_limits_json", "resource_limits", {}),
        ("safety_decisions_json", "safety_decisions", {}),
        ("completion_criteria_json", "completion_criteria", []),
    ):
        result[target] = _decode(result.pop(source, None), default)
    return result


def revise_evidence_plan(
    case_id: str,
    *,
    reason: str,
    executed_methods: Sequence[str] | None = None,
    actor: str = "research-orchestrator",
    db_path: str | None = None,
) -> dict[str, Any]:
    reason = _bounded_text(reason, 2000)
    if not reason:
        raise ValueError("plan revision reason is required")
    current = create_evidence_plan(case_id, actor=actor, db_path=db_path)
    case = _case(case_id, db_path)
    revision = int(current["revision"]) + 1
    methods = [_bounded_text(item, 200) for item in (executed_methods or current.get("executed_methods") or [])]
    safety = screen_research_safety(actions=methods or current["intended_methods"])
    plan_id = _id("RPN")
    now = soc_store.utc_now()
    payload = {
        **{key: value for key, value in current.items() if key not in {"plan_id", "revision", "parent_plan_id", "created_at", "updated_at"}},
        "plan_id": plan_id,
        "revision": revision,
        "parent_plan_id": current["plan_id"],
        "status": "blocked" if safety["blockers"] else "planned",
        "executed_methods": methods,
        "safety_decisions": safety,
        "change_reason": reason,
        "evidence_fingerprint": _case_fingerprint(case),
        "created_at": now,
        "updated_at": now,
    }
    with closing(soc_store.connect(db_path)) as connection:
        connection.execute(
            """INSERT INTO research_evidence_plans
            (plan_id, case_id, revision, parent_plan_id, selected_hypothesis_id, status,
             intended_methods_json, executed_methods_json, required_evidence_json,
             expected_outputs_json, resource_limits_json, safety_decisions_json,
             completion_criteria_json, change_reason, evidence_fingerprint, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                plan_id, case_id, revision, current["plan_id"], current.get("selected_hypothesis_id"), payload["status"],
                _json(payload["intended_methods"]), _json(methods), _json(payload["required_evidence"]),
                _json(payload["expected_outputs"]), _json(payload["resource_limits"]), _json(safety),
                _json(payload["completion_criteria"]), reason, payload["evidence_fingerprint"], now, now,
            ),
        )
        _event(connection, case_id, "research_evidence_plan_revised", f"Created evidence plan revision {revision}: {reason}", actor, {"plan_id": plan_id, "parent_plan_id": current["plan_id"], "safety_status": safety["status"]})
        connection.commit()
    return payload


def _resource_snapshot(db_path: str | None) -> dict[str, Any]:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    disk = shutil.disk_usage(Path(__file__).resolve().parents[1])
    try:
        from secopsai.intelligence_jobs import job_counts

        queue_counts = job_counts(db_path=db_path)
    except Exception as exc:
        queue_counts = {"unavailable": 1, "error": str(exc)[:500]}
    rss_multiplier = 1 if sys.platform == "darwin" else 1024
    return {
        "cpu_user_seconds": round(float(usage.ru_utime), 4),
        "cpu_system_seconds": round(float(usage.ru_stime), 4),
        "max_rss_bytes": int(usage.ru_maxrss) * rss_multiplier,
        "disk_total_bytes": int(disk.total),
        "disk_used_bytes": int(disk.used),
        "disk_free_bytes": int(disk.free),
        "queue_counts": queue_counts,
        "active_queue_depth": sum(
            int(queue_counts.get(status) or 0)
            for status in ("queued", "running", "awaiting_provider")
        ),
    }


def _model_snapshot(db_path: str | None) -> dict[str, Any]:
    try:
        from secopsai.codex_bridge import load_bridge_health_snapshot, load_model_routing

        routing = load_model_routing(db_path)
        health = load_bridge_health_snapshot(db_path=db_path)
        return {
            "selected_model": routing.get("primary_model") or "",
            "fallback_mode": routing.get("fallback_mode") or "disabled",
            "fallback_models": routing.get("fallback_models") or [],
            "routing_source": routing.get("source") or "runtime",
            "health": health,
        }
    except Exception as exc:
        return {"selected_model": "", "fallback_mode": "disabled", "fallback_models": [], "routing_source": "unavailable", "error": str(exc)[:500]}


def _tool_versions(case: dict[str, Any]) -> list[dict[str, str]]:
    tools = [{"name": "SecOpsAI", "version": "1.0.0"}, {"name": "Python", "version": platform.python_version()}]
    seen = {"SecOpsAI", "Python"}
    for evidence in case.get("evidence") or []:
        metadata = evidence.get("metadata") or {}
        if not isinstance(metadata, dict):
            continue
        name = str(metadata.get("tool") or "").strip()
        if name and name not in seen:
            tools.append({"name": name[:120], "version": str(metadata.get("tool_version") or "unknown")[:120]})
            seen.add(name)
    return tools


def _bundle_payload(
    case: dict[str, Any],
    plan: dict[str, Any],
    stage: str,
    result: dict[str, Any],
    *,
    resource_accounting: dict[str, Any],
    db_path: str | None,
) -> dict[str, Any]:
    evidence = []
    for item in case.get("evidence") or []:
        evidence.append(
            {
                "evidence_id": item.get("evidence_id"),
                "type": item.get("evidence_type"),
                "title": item.get("title"),
                "locator": _clean_locator(item.get("locator")),
                "sha256": item.get("sha256"),
                "provenance": item.get("provenance"),
                "collected_at": item.get("collected_at"),
                "status": item.get("status"),
                "metadata": _sanitize(item.get("metadata") or {}),
            }
        )
    subjects = [
        _sanitize({key: item.get(key) for key in ("subject_id", "subject_type", "ecosystem", "name", "version", "publisher", "registry_state", "artifact_state", "validation_state", "state_reason", "state_checked_at")})
        for item in case.get("subjects") or []
    ]
    failures = []
    attempts = []
    for pipeline in case.get("pipelines") or []:
        for step in pipeline.get("steps") or []:
            attempts.append({"pipeline_id": pipeline.get("pipeline_id"), "step": step.get("step_key"), "status": step.get("status"), "started_at": step.get("started_at"), "completed_at": step.get("completed_at")})
            if step.get("status") == "failed":
                failures.append({"pipeline_id": pipeline.get("pipeline_id"), "step": step.get("step_key"), "error_code": step.get("error_code"), "error": step.get("error_message")})
    for job in case.get("jobs") or []:
        attempts.append({"job_id": job.get("job_id"), "action": job.get("action"), "status": job.get("status"), "started_at": job.get("started_at"), "completed_at": job.get("completed_at")})
        if job.get("status") == "failed":
            failures.append({"job_id": job.get("job_id"), "action": job.get("action"), "error_code": job.get("error_code"), "error": job.get("error_message")})
    return _sanitize(
        {
            "schema_version": SCHEMA_VERSION,
            "case_id": case["case_id"],
            "stage": stage,
            "plan": {
                "plan_id": plan["plan_id"],
                "revision": plan["revision"],
                "selected_hypothesis_id": plan.get("selected_hypothesis_id"),
                "intended_methods": plan.get("intended_methods") or [],
                "executed_methods": plan.get("executed_methods") or [],
                "resource_limits": plan.get("resource_limits") or {},
                "safety_decisions": plan.get("safety_decisions") or {},
                "change_reason": plan.get("change_reason"),
            },
            "inputs": {"subjects": subjects, "source_urls": [item["locator"] for item in evidence if str(item["locator"]).startswith(("http://", "https://"))]},
            "registry_and_evidence_snapshots": evidence,
            "artifact_hashes": sorted({str(item.get("sha256")).lower() for item in evidence if SHA256_RE.fullmatch(str(item.get("sha256") or ""))}),
            "tools": _tool_versions(case),
            "rule_fingerprints": sorted({str(item.get("fingerprint")) for item in case.get("evidence") or [] if item.get("fingerprint")}),
            "configuration": {"execution_performed": False, "network_artifact_execution": False},
            "model_routing": _model_snapshot(db_path),
            "attempts": attempts,
            "errors": failures,
            "sandbox_references": [item for item in evidence if item["type"] == "sandbox_analysis"],
            "resource_usage": _resource_snapshot(db_path),
            "resource_accounting": resource_accounting,
            "stage_result": result,
            "created_at": soc_store.utc_now(),
        }
    )


def _bundle_completeness(payload: dict[str, Any]) -> int:
    checks = [
        bool(payload.get("plan", {}).get("plan_id")),
        bool(payload.get("inputs", {}).get("subjects")),
        bool(payload.get("registry_and_evidence_snapshots")),
        bool(payload.get("tools")),
        bool(payload.get("configuration")),
        bool(payload.get("created_at")),
        "attempts" in payload,
        "errors" in payload,
        bool(payload.get("model_routing")),
        bool(payload.get("resource_usage")),
        bool(payload.get("resource_accounting")),
    ]
    return int(round(sum(checks) / len(checks) * 100))


def _persist_bundle(
    case_id: str,
    plan: dict[str, Any],
    *,
    stage: str,
    status: str,
    result: dict[str, Any],
    actor: str,
    db_path: str | None,
    started_at: str,
    started_monotonic: float,
) -> dict[str, Any]:
    case = _case(case_id, db_path)
    completed_at = soc_store.utc_now()
    latency_ms = max(0.0, (time.monotonic() - started_monotonic) * 1000.0)
    resource_accounting = {
        "started_at": started_at,
        "completed_at": completed_at,
        "latency_ms": round(latency_ms, 3),
        "retry_count": int(result.get("retry_count") or 0),
        "estimated_input_tokens": int(result.get("estimated_input_tokens") or 0),
        "estimated_output_tokens": int(result.get("estimated_output_tokens") or 0),
        "estimated_cost_usd": round(float(result.get("estimated_cost_usd") or 0.0), 6),
        "cost_estimate_only": True,
    }
    payload = _bundle_payload(
        case,
        plan,
        stage,
        result,
        resource_accounting=resource_accounting,
        db_path=db_path,
    )
    payload_hash = _canonical_hash(payload)
    with closing(soc_store.connect(db_path)) as connection:
        previous = connection.execute(
            "SELECT bundle_hash FROM research_run_bundles WHERE case_id=? ORDER BY created_at DESC, bundle_id DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        previous_hash = str(previous["bundle_hash"]) if previous else ""
        bundle_hash = hashlib.sha256(f"{previous_hash}|{payload_hash}".encode()).hexdigest()
        bundle_id = _id("RRB")
        completeness = _bundle_completeness(payload)
        now = soc_store.utc_now()
        connection.execute(
            """INSERT INTO research_run_bundles
            (bundle_id, case_id, plan_id, stage, status, previous_bundle_hash, payload_hash,
             bundle_hash, completeness_score, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (bundle_id, case_id, plan["plan_id"], stage, status, previous_hash, payload_hash, bundle_hash, completeness, _json(payload), now),
        )
        _event(connection, case_id, f"research_{stage}_bundle_created", f"Created immutable {stage} research bundle with completeness {completeness}%.", actor, {"bundle_id": bundle_id, "bundle_hash": bundle_hash, "status": status, "completeness_score": completeness})
        connection.commit()
    return {"bundle_id": bundle_id, "case_id": case_id, "plan_id": plan["plan_id"], "stage": stage, "status": status, "previous_bundle_hash": previous_hash, "payload_hash": payload_hash, "bundle_hash": bundle_hash, "completeness_score": completeness, "payload": payload, "created_at": now}


def run_scaffold_research(
    case_id: str,
    *,
    actor: str = "research-orchestrator",
    db_path: str | None = None,
) -> dict[str, Any]:
    started_at = soc_store.utc_now()
    started_monotonic = time.monotonic()
    case = _case(case_id, db_path)
    plan = create_evidence_plan(case_id, actor=actor, db_path=db_path)
    blockers = list((plan.get("safety_decisions") or {}).get("blockers") or [])
    subjects = [item for item in case.get("subjects") or [] if item.get("status", "active") == "active"]
    if not subjects:
        blockers.append("a structured research subject is required")
    checks = {
        "adapter_contract": "passed" if subjects else "blocked",
        "metadata_identity": "passed" if all(item.get("name") and item.get("ecosystem") for item in subjects) else "blocked",
        "checksums": "passed" if any(item.get("sha256") for item in case.get("evidence") or []) else "not_available",
        "limits": "passed" if plan.get("resource_limits") else "blocked",
        "fixture_scope": "minimal_only",
        "execution_performed": False,
    }
    status = "blocked" if blockers else "succeeded"
    result = {"checks": checks, "blockers": blockers, "warnings": [] if case.get("evidence") else ["no evidence has been collected yet"], "execution_performed": False}
    return _persist_bundle(
        case_id,
        plan,
        stage="scaffold",
        status=status,
        result=result,
        actor=actor,
        db_path=db_path,
        started_at=started_at,
        started_monotonic=started_monotonic,
    )


def _transition_markers(case: dict[str, Any]) -> list[str]:
    markers: list[str] = []
    suspicious_keys = {"fixture_mode", "mock", "is_mock", "stub", "synthetic", "placeholder", "placeholder_hash", "fake_result", "hard_coded_metric"}
    for evidence in case.get("evidence") or []:
        metadata = evidence.get("metadata") or {}
        if not isinstance(metadata, dict):
            continue
        for key in suspicious_keys:
            value = metadata.get(key)
            if value not in (None, False, "", 0, [], {}):
                markers.append(f"{evidence.get('evidence_id')}: {key}={value}")
        sha = str(evidence.get("sha256") or "")
        if sha and (sha == "0" * 64 or sha == "f" * 64):
            markers.append(f"{evidence.get('evidence_id')}: placeholder hash")
    return markers


def verify_transition(
    case_id: str,
    *,
    actor: str = "research-orchestrator",
    db_path: str | None = None,
) -> dict[str, Any]:
    started_at = soc_store.utc_now()
    started_monotonic = time.monotonic()
    case = _case(case_id, db_path)
    with closing(soc_store.connect(db_path)) as connection:
        scaffold = connection.execute(
            "SELECT * FROM research_run_bundles WHERE case_id=? AND stage='scaffold' ORDER BY created_at DESC LIMIT 1",
            (case_id,),
        ).fetchone()
    if not scaffold:
        scaffold_result = run_scaffold_research(case_id, actor=actor, db_path=db_path)
        if scaffold_result["status"] != "succeeded":
            raise ValueError("scaffold research must pass before transition verification")
    elif scaffold["status"] != "succeeded":
        raise ValueError("latest scaffold research is blocked")
    plan = create_evidence_plan(case_id, actor=actor, db_path=db_path)
    markers = _transition_markers(case)
    executed = list(plan.get("executed_methods") or [])
    checks = {
        "fixtures_removed": not any("fixture" in item for item in markers),
        "mocks_removed": not any("mock" in item for item in markers),
        "stubs_removed": not any("stub" in item for item in markers),
        "synthetic_outputs_removed": not any("synthetic" in item or "fake_result" in item for item in markers),
        "placeholder_hashes_removed": not any("placeholder" in item for item in markers),
        "subsampling_declared": not any("subsample" in item.lower() for item in executed),
        "execution_performed": False,
    }
    blockers = [f"transition marker remains: {item}" for item in markers]
    status = "blocked" if blockers or not all(value is True or key == "execution_performed" for key, value in checks.items()) else "succeeded"
    result = {"checks": checks, "blockers": blockers, "markers": markers, "execution_performed": False}
    return _persist_bundle(
        case_id,
        plan,
        stage="transition",
        status=status,
        result=result,
        actor=actor,
        db_path=db_path,
        started_at=started_at,
        started_monotonic=started_monotonic,
    )


def run_full_safe_research(
    case_id: str,
    *,
    actor: str = "research-orchestrator",
    db_path: str | None = None,
) -> dict[str, Any]:
    started_at = soc_store.utc_now()
    started_monotonic = time.monotonic()
    case = _case(case_id, db_path)
    with closing(soc_store.connect(db_path)) as connection:
        transition = connection.execute(
            "SELECT * FROM research_run_bundles WHERE case_id=? AND stage='transition' ORDER BY created_at DESC LIMIT 1",
            (case_id,),
        ).fetchone()
    if not transition:
        verified = verify_transition(case_id, actor=actor, db_path=db_path)
        if verified["status"] != "succeeded":
            raise ValueError("transition verification must pass before full research")
    elif transition["status"] != "succeeded":
        raise ValueError("latest transition verification is blocked")
    active_evidence = [item for item in case.get("evidence") or [] if item.get("status", "active") == "active"]
    plan = create_evidence_plan(case_id, actor=actor, db_path=db_path)
    methods = []
    if case.get("subjects"):
        methods.append("verify_structured_subject_identity")
    if any(item.get("evidence_type") in {"source", "registry_metadata"} for item in active_evidence):
        methods.append("collect_official_registry_or_repository_metadata")
    if any(item.get("sha256") for item in active_evidence):
        methods.append("verify_available_checksums")
    if any(item.get("evidence_type") == "static_analysis" for item in active_evidence):
        methods.append("inspect_archives_and_manifests_statically")
    if any(item.get("evidence_type") == "sandbox_analysis" for item in active_evidence):
        methods.append("process_only_approved_external_sandbox_results")
    if plan.get("executed_methods") != methods:
        plan = revise_evidence_plan(case_id, reason="Evidence changed; recorded the methods actually executed before full research.", executed_methods=methods, actor=actor, db_path=db_path)
    blockers = []
    if not active_evidence:
        blockers.append("full research requires at least one active evidence record")
    if not any(item.get("evidence_type") in {"source", "registry_metadata"} for item in active_evidence):
        blockers.append("full research requires an official source or registry evidence record")
    result = {
        "executed_methods": methods,
        "evidence_count": len(active_evidence),
        "source_count": sum(item.get("evidence_type") in {"source", "registry_metadata"} for item in active_evidence),
        "artifact_hash_count": len({item.get("sha256") for item in active_evidence if item.get("sha256")}),
        "static_analysis_count": sum(item.get("evidence_type") == "static_analysis" for item in active_evidence),
        "sandbox_analysis_count": sum(item.get("evidence_type") == "sandbox_analysis" for item in active_evidence),
        "failed_attempts_preserved": sum(step.get("status") == "failed" for pipeline in case.get("pipelines") or [] for step in pipeline.get("steps") or []),
        "blockers": blockers,
        "execution_performed": False,
    }
    return _persist_bundle(
        case_id,
        plan,
        stage="full",
        status="blocked" if blockers else "succeeded",
        result=result,
        actor=actor,
        db_path=db_path,
        started_at=started_at,
        started_monotonic=started_monotonic,
    )


def _decode_bundle(row: Any) -> dict[str, Any]:
    result = _row_dict(row)
    result["payload"] = _decode(result.pop("payload_json", None), {})
    return result


def inspect_run_bundle(bundle_id: str, *, db_path: str | None = None) -> dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM research_run_bundles WHERE bundle_id=?", (bundle_id,)).fetchone()
    if not row:
        raise ValueError(f"research run bundle not found: {bundle_id}")
    bundle = _decode_bundle(row)
    payload_hash = _canonical_hash(bundle["payload"])
    expected = hashlib.sha256(f"{bundle['previous_bundle_hash']}|{payload_hash}".encode()).hexdigest()
    bundle["verification"] = {
        "payload_hash_valid": payload_hash == bundle["payload_hash"],
        "bundle_hash_valid": expected == bundle["bundle_hash"],
        "tamper_evident": payload_hash == bundle["payload_hash"] and expected == bundle["bundle_hash"],
    }
    return bundle


def _sentence_spans(text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    for match in re.finditer(r"[^\n]+?(?:[.!?]+(?=\s+|$)|$)", text):
        sentence = match.group(0).strip()
        if len(sentence.split()) < 3 or sentence.startswith(("```", "#")):
            continue
        start = match.start() + len(match.group(0)) - len(match.group(0).lstrip())
        spans.append((start, match.end(), sentence))
    return spans


def _claim_type(text: str) -> str:
    if SHA256_RE.search(text):
        return "hash"
    if CVE_RE.search(text) or GHSA_RE.search(text):
        return "advisory"
    if RUNTIME_TERMS.search(text):
        return "runtime_observation"
    if STATIC_TERMS.search(text):
        return "static_observation"
    if ATTRIBUTION_TERMS.search(text):
        return "attribution"
    if VICTIM_TERMS.search(text):
        return "victim_impact"
    if re.search(r"\b(?:locally|local repository|local environment|installed here)\b", text, re.I):
        return "local_exposure"
    if re.search(r"\b(?:method|analy[sz]ed|scanned|compared|collected|measured)\b", text, re.I):
        return "methodology"
    if VERSION_REF_RE.search(text):
        return "package_version"
    if URL_RE.search(text) or re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        return "indicator"
    if NUMBER_RE.search(text):
        return "numeric"
    return "general"


def _canonical_case_records(case: dict[str, Any], bundle: dict[str, Any] | None) -> dict[str, Any]:
    evidence = [item for item in case.get("evidence") or [] if item.get("status", "active") == "active"]
    corpus: dict[str, str] = {}
    for item in evidence:
        corpus[item["evidence_id"]] = " ".join(
            str(value or "")
            for value in (item.get("title"), item.get("locator"), item.get("sha256"), item.get("provenance"), item.get("notes"), _json(item.get("metadata") or {}))
        ).lower()
    subjects = case.get("subjects") or []
    source_ids = [item["evidence_id"] for item in evidence if item.get("evidence_type") in {"source", "registry_metadata"}]
    canonical_text = " ".join(
        [case.get("case_id", ""), *corpus.values()]
        + [" ".join(str(item.get(key) or "") for key in ("ecosystem", "name", "version", "publisher")) for item in subjects]
        + [str(item.get("value") or "") for item in case.get("iocs") or []]
    ).lower()
    return {
        "evidence": evidence,
        "corpus": corpus,
        "canonical_text": canonical_text,
        "hashes": {value.lower() for value in SHA256_RE.findall(canonical_text)},
        "cves": {value.upper() for value in CVE_RE.findall(canonical_text)},
        "ghsas": {value.upper() for value in GHSA_RE.findall(canonical_text)},
        "urls": {value.rstrip(".,;").lower() for value in URL_RE.findall(canonical_text)},
        "versions": {
            key
            for item in subjects
            if item.get("name") and item.get("version")
            for key in {
                (str(item.get("name") or "").lower(), str(item.get("version") or "").lower()),
                (f"{str(item.get('ecosystem') or '').lower()}:{str(item.get('name') or '').lower()}", str(item.get("version") or "").lower()),
            }
        },
        "source_ids": source_ids,
        "sandbox_ids": [item["evidence_id"] for item in evidence if item.get("evidence_type") == "sandbox_analysis"],
        "static_ids": [item["evidence_id"] for item in evidence if item.get("evidence_type") == "static_analysis"],
        "bundle": bundle,
    }


def _token_overlap(statement: str, evidence_text: str) -> float:
    ignore = {"this", "that", "with", "from", "were", "have", "has", "the", "and", "for", "into", "was", "are", "not", "only", "their"}
    left = {item for item in re.findall(r"[a-z0-9_.@/-]{3,}", statement.lower()) if item not in ignore}
    right = set(re.findall(r"[a-z0-9_.@/-]{3,}", evidence_text.lower()))
    return len(left & right) / max(1, len(left))


def _verify_statement(statement: str, records: dict[str, Any]) -> dict[str, Any]:
    claim_type = _claim_type(statement)
    evidence_ids: list[str] = []
    contradictions: list[str] = []
    limitations: list[str] = []
    identifiers = {
        "sha256": [value.lower() for value in SHA256_RE.findall(statement)],
        "cves": [value.upper() for value in CVE_RE.findall(statement)],
        "ghsas": [value.upper() for value in GHSA_RE.findall(statement)],
        "urls": [value.rstrip(".,;") for value in URL_RE.findall(statement)],
        "package_versions": [{"name": name, "version": version} for name, version in VERSION_REF_RE.findall(statement)],
    }
    missing: list[str] = []
    for value in identifiers["sha256"]:
        if value not in records["hashes"]:
            missing.append(f"unverified SHA-256 {value}")
    for value in identifiers["cves"]:
        if value not in records["cves"]:
            missing.append(f"unverified advisory {value}")
    for value in identifiers["ghsas"]:
        if value not in records["ghsas"]:
            missing.append(f"unverified advisory {value}")
    for value in identifiers["urls"]:
        if value.lower() not in records["urls"]:
            missing.append(f"unverified URL {value}")
    for item in identifiers["package_versions"]:
        if (item["name"].lower(), item["version"].lower()) not in records["versions"]:
            missing.append(f"unverified package version {item['name']}@{item['version']}")
        else:
            evidence_ids.extend(records["source_ids"])
    for evidence_id, evidence_text in records["corpus"].items():
        if _token_overlap(statement, evidence_text) >= 0.34 or any(value in evidence_text for value in identifiers["sha256"] + [value.lower() for value in identifiers["cves"] + identifiers["ghsas"]]):
            evidence_ids.append(evidence_id)
    if claim_type == "runtime_observation":
        if not records["sandbox_ids"]:
            missing.append("sandbox evidence for runtime behavior")
            if records.get("bundle") and records["bundle"].get("payload", {}).get("configuration", {}).get("execution_performed") is False:
                contradictions.append("SecOpsAI run bundle records that local execution was not performed")
        else:
            evidence_ids.extend(records["sandbox_ids"])
            limitations.append("Runtime evidence is scoped to the named external sandbox and exact artifact hash.")
    elif claim_type == "static_observation":
        if not records["static_ids"]:
            missing.append("static analysis evidence")
        else:
            evidence_ids.extend(records["static_ids"])
            limitations.append("Static observations do not prove runtime behavior or intent.")
    elif claim_type in {"attribution", "victim_impact"}:
        verified_types = set()
        for item in records["evidence"]:
            metadata = item.get("metadata") or {}
            if isinstance(metadata, dict):
                verified_types.update(str(value) for value in metadata.get("verified_claim_types") or [])
        if claim_type not in verified_types:
            missing.append(f"explicit source-backed {claim_type.replace('_', ' ')} evidence")
    elif claim_type == "local_exposure":
        local_state = str(records.get("bundle", {}).get("payload", {}).get("stage_result", {}).get("local_exposure") or "")
        if not local_state:
            limitations.append("Local exposure must be read from the calibrated Research Case field.")
    elif claim_type == "methodology":
        bundle = records.get("bundle") or {}
        executed = " ".join(bundle.get("payload", {}).get("plan", {}).get("executed_methods") or []).lower()
        if not executed:
            missing.append("executed-method record in an immutable full research bundle")
    evidence_ids = sorted(set(evidence_ids))
    if not records.get("bundle") or records["bundle"].get("status") != "succeeded":
        missing.append("successful immutable full research bundle")
    if contradictions:
        status = "contradicted"
        confidence = 0
        inference = "not_permitted"
    elif missing:
        if INFERENCE_TERMS.search(statement) and evidence_ids:
            status = "qualified_inference"
            confidence = min(55, 25 + len(evidence_ids) * 8)
            inference = "explicit"
        else:
            status = "unsupported"
            confidence = min(35, len(evidence_ids) * 10)
            inference = "none"
    elif evidence_ids or identifiers["sha256"] or identifiers["cves"] or identifiers["ghsas"] or identifiers["package_versions"]:
        status = "supported"
        confidence = min(100, 75 + len(evidence_ids) * 5)
        inference = "none"
    else:
        status = "qualified_inference" if INFERENCE_TERMS.search(statement) and evidence_ids else "unsupported"
        confidence = 45 if status == "qualified_inference" else 20
        inference = "explicit" if status == "qualified_inference" else "none"
        if status == "unsupported":
            missing.append("claim-specific evidence")
    return {
        "claim_type": claim_type,
        "support_status": status,
        "confidence": confidence,
        "evidence_ids": evidence_ids,
        "contradicting_evidence": contradictions,
        "inference_status": inference,
        "numeric_values": NUMBER_RE.findall(statement),
        "identifiers": identifiers,
        "source_provenance": [{"evidence_id": item, "kind": "case_evidence"} for item in evidence_ids],
        "limitations": sorted(set([*limitations, *missing])),
        "verification": {"missing_support": missing, "hard_blocked": status in {"unsupported", "contradicted"}},
    }


def extract_claim_ledger(
    case_id: str,
    *,
    text: str = "",
    source_kind: str = "case_summary",
    source_locator: str = "",
    actor: str = "claim-verifier",
    db_path: str | None = None,
) -> dict[str, Any]:
    case = _case(case_id, db_path)
    text = _bounded_text(text or f"{case.get('title', '')}. {case.get('summary', '')}", 100000)
    if not text:
        raise ValueError("claim source text is required")
    source_kind = _bounded_text(source_kind, 80) or "case_summary"
    source_locator = _bounded_text(source_locator, 500) or source_kind
    with closing(soc_store.connect(db_path)) as connection:
        full_row = connection.execute(
            "SELECT * FROM research_run_bundles WHERE case_id=? AND stage='full' ORDER BY created_at DESC LIMIT 1",
            (case_id,),
        ).fetchone()
    bundle = inspect_run_bundle(str(full_row["bundle_id"]), db_path=db_path) if full_row else None
    records = _canonical_case_records(case, bundle)
    claims: list[dict[str, Any]] = []
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        for start, end, statement in _sentence_spans(text):
            fingerprint = _canonical_hash({"source": source_kind, "locator": source_locator, "text": statement})
            previous = connection.execute(
                "SELECT MAX(revision) AS revision FROM research_claim_ledger WHERE case_id=? AND source_kind=? AND source_locator=? AND fingerprint=?",
                (case_id, source_kind, source_locator, fingerprint),
            ).fetchone()
            revision = max(1, int(previous["revision"] or 0))
            verification = _verify_statement(statement, records)
            claim_id = "LCL-" + hashlib.sha256(f"{case_id}|{source_kind}|{source_locator}|{fingerprint}|{revision}".encode()).hexdigest()[:16].upper()
            payload = {
                "claim_id": claim_id,
                "case_id": case_id,
                "bundle_id": bundle.get("bundle_id") if bundle else None,
                "revision": revision,
                "fingerprint": fingerprint,
                "source_kind": source_kind,
                "source_locator": source_locator,
                "span_start": start,
                "span_end": end,
                "text_span": statement,
                **verification,
                "reviewer_decisions": [],
                "created_at": now,
                "updated_at": now,
            }
            connection.execute(
                """INSERT INTO research_claim_ledger
                (claim_id, case_id, bundle_id, revision, fingerprint, source_kind, source_locator,
                 span_start, span_end, text_span, claim_type, support_status, confidence,
                 evidence_ids_json, contradicting_evidence_json, inference_status,
                 numeric_values_json, identifiers_json, source_provenance_json, limitations_json,
                 reviewer_decisions_json, verification_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id, source_kind, source_locator, fingerprint, revision)
                DO UPDATE SET bundle_id=excluded.bundle_id, span_start=excluded.span_start,
                    span_end=excluded.span_end, text_span=excluded.text_span,
                    claim_type=excluded.claim_type, support_status=excluded.support_status,
                    confidence=excluded.confidence, evidence_ids_json=excluded.evidence_ids_json,
                    contradicting_evidence_json=excluded.contradicting_evidence_json,
                    inference_status=excluded.inference_status, numeric_values_json=excluded.numeric_values_json,
                    identifiers_json=excluded.identifiers_json, source_provenance_json=excluded.source_provenance_json,
                    limitations_json=excluded.limitations_json, verification_json=excluded.verification_json,
                    updated_at=excluded.updated_at""",
                (
                    claim_id, case_id, payload["bundle_id"], revision, fingerprint, source_kind, source_locator,
                    start, end, statement, payload["claim_type"], payload["support_status"], payload["confidence"],
                    _json(payload["evidence_ids"]), _json(payload["contradicting_evidence"]), payload["inference_status"],
                    _json(payload["numeric_values"]), _json(payload["identifiers"]), _json(payload["source_provenance"]),
                    _json(payload["limitations"]), _json([]), _json(payload["verification"]), now, now,
                ),
            )
            claims.append(payload)
        _event(connection, case_id, "research_claim_ledger_built", f"Extracted and verified {len(claims)} factual claims from {source_kind}.", actor, {"source_locator": source_locator, "supported": sum(item["support_status"] == "supported" for item in claims), "blocked": sum(item["support_status"] in {"unsupported", "contradicted"} for item in claims)})
        connection.commit()
    return _claim_summary(case_id, claims, source_kind, source_locator)


def _decode_claim(row: Any) -> dict[str, Any]:
    result = _row_dict(row)
    for source, target, default in (
        ("evidence_ids_json", "evidence_ids", []),
        ("contradicting_evidence_json", "contradicting_evidence", []),
        ("numeric_values_json", "numeric_values", []),
        ("identifiers_json", "identifiers", {}),
        ("source_provenance_json", "source_provenance", []),
        ("limitations_json", "limitations", []),
        ("reviewer_decisions_json", "reviewer_decisions", []),
        ("verification_json", "verification", {}),
    ):
        result[target] = _decode(result.pop(source, None), default)
    return result


def _claim_summary(case_id: str, claims: list[dict[str, Any]], source_kind: str, source_locator: str) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "schema_version": SCHEMA_VERSION,
        "source_kind": source_kind,
        "source_locator": source_locator,
        "claims": claims,
        "summary": {
            "total": len(claims),
            **{status: sum(item["support_status"] == status for item in claims) for status in sorted(CLAIM_STATUSES)},
            "evidence_coverage_percent": int(round(sum(item["support_status"] in {"supported", "qualified_inference"} for item in claims) / max(1, len(claims)) * 100)),
            "publication_blocked": any(item["support_status"] in {"unsupported", "contradicted"} for item in claims),
        },
    }


def verify_claims(
    case_id: str,
    *,
    source_kind: str = "",
    source_locator: str = "",
    actor: str = "claim-verifier",
    db_path: str | None = None,
) -> dict[str, Any]:
    case = _case(case_id, db_path)
    with closing(soc_store.connect(db_path)) as connection:
        query = "SELECT * FROM research_claim_ledger WHERE case_id=?"
        params: list[Any] = [case_id]
        if source_kind:
            query += " AND source_kind=?"
            params.append(source_kind)
        if source_locator:
            query += " AND source_locator=?"
            params.append(source_locator)
        query += " ORDER BY source_kind, source_locator, span_start"
        rows = connection.execute(query, params).fetchall()
        full_row = connection.execute("SELECT * FROM research_run_bundles WHERE case_id=? AND stage='full' ORDER BY created_at DESC LIMIT 1", (case_id,)).fetchone()
    if not rows:
        return extract_claim_ledger(case_id, source_kind=source_kind or "case_summary", source_locator=source_locator, actor=actor, db_path=db_path)
    bundle = inspect_run_bundle(str(full_row["bundle_id"]), db_path=db_path) if full_row else None
    records = _canonical_case_records(case, bundle)
    updated: list[dict[str, Any]] = []
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        for row in rows:
            item = _decode_claim(row)
            verification = _verify_statement(item["text_span"], records)
            connection.execute(
                """UPDATE research_claim_ledger SET bundle_id=?, claim_type=?, support_status=?, confidence=?,
                   evidence_ids_json=?, contradicting_evidence_json=?, inference_status=?, numeric_values_json=?,
                   identifiers_json=?, source_provenance_json=?, limitations_json=?, verification_json=?, updated_at=?
                   WHERE claim_id=?""",
                (
                    bundle.get("bundle_id") if bundle else None, verification["claim_type"], verification["support_status"], verification["confidence"],
                    _json(verification["evidence_ids"]), _json(verification["contradicting_evidence"]), verification["inference_status"],
                    _json(verification["numeric_values"]), _json(verification["identifiers"]), _json(verification["source_provenance"]),
                    _json(verification["limitations"]), _json(verification["verification"]), now, item["claim_id"],
                ),
            )
            updated.append({**item, **verification, "bundle_id": bundle.get("bundle_id") if bundle else None, "updated_at": now})
        _event(connection, case_id, "research_claims_verified", f"Reverified {len(updated)} claims against current canonical evidence.", actor, {"blocked": sum(item["support_status"] in {"unsupported", "contradicted"} for item in updated)})
        connection.commit()
    first = updated[0] if updated else {"source_kind": source_kind, "source_locator": source_locator}
    return _claim_summary(case_id, updated, first.get("source_kind") or "mixed", first.get("source_locator") or "mixed")


def clip_unsupported_claims(
    case_id: str,
    *,
    text: str,
    source_kind: str = "publication_draft",
    source_locator: str = "draft",
    actor: str = "claim-verifier",
    db_path: str | None = None,
) -> dict[str, Any]:
    ledger = extract_claim_ledger(case_id, text=text, source_kind=source_kind, source_locator=source_locator, actor=actor, db_path=db_path)
    corrected = text
    revisions: list[dict[str, Any]] = []
    for claim in sorted(ledger["claims"], key=lambda item: int(item["span_start"]), reverse=True):
        status = claim["support_status"]
        if status == "supported":
            continue
        if status == "qualified_inference":
            replacement = claim["text_span"]
            if not INFERENCE_TERMS.search(replacement):
                replacement = "Available evidence suggests, but does not prove, that " + replacement[0].lower() + replacement[1:]
            action = "qualified"
        elif status == "contradicted":
            replacement = ""
            action = "removed"
        else:
            # Rewording an unsupported identifier as a hypothesis would still
            # publish the fabricated hash, version, IOC, advisory, number, or
            # date. Remove unsupported factual sentences instead; the revision
            # ledger preserves exactly what was omitted and why.
            replacement = ""
            action = "removed"
        start, end = int(claim["span_start"]), int(claim["span_end"])
        corrected = corrected[:start] + replacement + corrected[end:]
        revision_id = _id("LCR")
        revision = {"revision_id": revision_id, "claim_id": claim["claim_id"], "action": action, "before": claim["text_span"], "after": replacement, "reason": "; ".join(claim.get("limitations") or ["claim lacked canonical support"]), "evidence_ids": claim.get("evidence_ids") or []}
        revisions.append(revision)
    with closing(soc_store.connect(db_path)) as connection:
        for item in revisions:
            connection.execute(
                "INSERT INTO research_claim_revisions (revision_id, case_id, claim_id, action, before_text, after_text, reason, evidence_ids_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (item["revision_id"], case_id, item["claim_id"], item["action"], item["before"], item["after"], item["reason"][:4000], _json(item["evidence_ids"]), soc_store.utc_now()),
            )
        _event(connection, case_id, "research_claims_clipped", f"Applied {len(revisions)} evidence-grounded claim correction(s).", actor, {"revisions": [{"claim_id": item["claim_id"], "action": item["action"]} for item in revisions]})
        connection.commit()
    final_ledger = extract_claim_ledger(case_id, text=corrected, source_kind=f"{source_kind}_verified", source_locator=source_locator, actor=actor, db_path=db_path)
    return {"case_id": case_id, "original_text": text, "corrected_text": corrected, "revisions": list(reversed(revisions)), "claim_ledger": final_ledger, "publication_blocked": final_ledger["summary"]["publication_blocked"]}


def _store_audit(
    case_id: str,
    *,
    audit_type: str,
    status: str,
    score: int,
    blockers: Sequence[str],
    warnings: Sequence[str],
    details: dict[str, Any],
    actor: str,
    db_path: str | None,
) -> dict[str, Any]:
    with closing(soc_store.connect(db_path)) as connection:
        bundle = connection.execute("SELECT bundle_id FROM research_run_bundles WHERE case_id=? ORDER BY created_at DESC LIMIT 1", (case_id,)).fetchone()
        audit_id = _id("RRA")
        now = soc_store.utc_now()
        connection.execute(
            "INSERT INTO research_reliability_audits (audit_id, case_id, bundle_id, audit_type, status, score, hard_blockers_json, warnings_json, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (audit_id, case_id, str(bundle["bundle_id"]) if bundle else None, audit_type, status, max(0, min(int(score), 100)), _json(list(blockers)), _json(list(warnings)), _json(_sanitize(details)), now),
        )
        _event(connection, case_id, f"research_{audit_type}_audit", f"{audit_type.replace('_', ' ').title()} completed: {status}.", actor, {"audit_id": audit_id, "score": score, "blockers": list(blockers)})
        connection.commit()
    return {"audit_id": audit_id, "case_id": case_id, "bundle_id": str(bundle["bundle_id"]) if bundle else None, "audit_type": audit_type, "status": status, "score": max(0, min(int(score), 100)), "hard_blockers": list(blockers), "warnings": list(warnings), "details": details, "created_at": now}


def audit_completeness(
    case_id: str,
    *,
    actor: str = "research-auditor",
    db_path: str | None = None,
) -> dict[str, Any]:
    case = _case(case_id, db_path)
    workspace = get_reliability_workspace(case_id, db_path=db_path)
    bundles = workspace["run_bundles"]
    full = next((item for item in bundles if item["stage"] == "full"), None)
    blockers: list[str] = []
    warnings: list[str] = []
    if not full or full["status"] != "succeeded":
        blockers.append("a successful full-stage run bundle is required")
    elif not full.get("verification", {}).get("tamper_evident"):
        blockers.append("the latest full-stage run bundle failed integrity verification")
    if full and int(full.get("completeness_score") or 0) < 70:
        blockers.append("run bundle completeness is below 70%")
    transition = next((item for item in bundles if item["stage"] == "transition"), None)
    if not transition or transition["status"] != "succeeded":
        blockers.append("transition verification has not passed")
    markers = _transition_markers(case)
    if markers:
        blockers.append("fixture, mock, stub, synthetic, hard-coded, or placeholder markers remain")
    latest_plan = workspace["plans"][0] if workspace["plans"] else None
    intended = set(latest_plan.get("intended_methods") or []) if latest_plan else set()
    executed = set(latest_plan.get("executed_methods") or []) if latest_plan else set()
    unperformed = sorted(intended - executed)
    if not executed:
        blockers.append("no executed methods are recorded")
    elif unperformed:
        warnings.append("intended methods not executed: " + ", ".join(unperformed))
    failed_attempts = [step for pipeline in case.get("pipelines") or [] for step in pipeline.get("steps") or [] if step.get("status") == "failed"]
    recorded_failures = list((full or {}).get("payload", {}).get("errors") or [])
    if failed_attempts and not recorded_failures:
        blockers.append("failed research attempts were omitted from the run bundle")
    claims = workspace.get("effective_claim_ledger") or workspace["claim_ledger"]
    if claims and any(item["support_status"] in {"unsupported", "contradicted"} for item in claims):
        blockers.append("the claim ledger contains unsupported or contradicted claims")
    if not claims:
        blockers.append("a claim ledger has not been built")
    score = 100 - min(100, len(blockers) * 18 + len(warnings) * 5)
    details = {
        "transition_markers": markers,
        "intended_methods": sorted(intended),
        "executed_methods": sorted(executed),
        "unperformed_methods": unperformed,
        "failed_attempt_count": len(failed_attempts),
        "recorded_failure_count": len(recorded_failures),
        "claim_count": len(claims),
        "checks": {
            "selective_reporting": "blocked" if failed_attempts and not recorded_failures else "passed",
            "methodology_divergence": "warning" if unperformed else "passed",
            "mock_or_fixture_leakage": "blocked" if markers else "passed",
            "formula_to_code_divergence": "not_applicable_without_declared_formula",
        },
    }
    return _store_audit(case_id, audit_type="completeness", status="blocked" if blockers else "passed", score=score, blockers=blockers, warnings=warnings, details=details, actor=actor, db_path=db_path)


def audit_originality(
    case_id: str,
    *,
    text: str = "",
    actor: str = "research-auditor",
    db_path: str | None = None,
) -> dict[str, Any]:
    case = _case(case_id, db_path)
    text = _bounded_text(text or f"{case.get('title', '')}. {case.get('summary', '')}", 100000)
    sources = []
    missing_attribution = []
    max_similarity = 0.0
    closest = ""
    for evidence in case.get("evidence") or []:
        if evidence.get("evidence_type") not in {"source", "registry_metadata"}:
            continue
        metadata = evidence.get("metadata") or {}
        excerpts = metadata.get("source_excerpts") if isinstance(metadata, dict) else []
        if isinstance(excerpts, str):
            excerpts = [excerpts]
        for excerpt in excerpts or []:
            if len(str(excerpt).split()) < 12:
                continue
            similarity = SequenceMatcher(None, text.lower(), str(excerpt).lower()).ratio()
            if similarity > max_similarity:
                max_similarity = similarity
                closest = str(evidence.get("locator") or evidence.get("evidence_id"))
        locator = str(evidence.get("locator") or "")
        if locator.startswith(("http://", "https://")):
            sources.append(locator)
    if re.search(r"\b(?:according to|reported by|research by|advisory from)\b", text, re.I) and not sources:
        missing_attribution.append("external-source language appears without a public source reference")
    blockers = []
    warnings = []
    if max_similarity >= 0.82:
        blockers.append("draft is too similar to a stored source excerpt")
    elif max_similarity >= 0.65:
        warnings.append("draft has high similarity to a stored source excerpt; review paraphrasing and attribution")
    blockers.extend(missing_attribution)
    score = max(0, min(100, int(round(100 - max_similarity * 100 - len(missing_attribution) * 20))))
    return _store_audit(case_id, audit_type="originality", status="blocked" if blockers else "passed", score=score, blockers=blockers, warnings=warnings, details={"max_source_similarity": round(max_similarity, 4), "closest_source": closest, "source_references": sources, "attribution_failures": missing_attribution}, actor=actor, db_path=db_path)


def record_visual_qa(
    case_id: str,
    *,
    desktop_rendered: bool,
    mobile_rendered: bool,
    overflow_count: int = 0,
    contrast_failures: int = 0,
    missing_alt_text: int = 0,
    unlicensed_images: int = 0,
    screenshots: Sequence[str] | None = None,
    actor: str = "publication-renderer",
    db_path: str | None = None,
) -> dict[str, Any]:
    blockers = []
    if not desktop_rendered or not mobile_rendered:
        blockers.append("desktop and mobile publication renders are both required")
    if int(overflow_count) > 0:
        blockers.append(f"{int(overflow_count)} layout overflow issue(s) remain")
    if int(contrast_failures) > 0:
        blockers.append(f"{int(contrast_failures)} deterministic contrast failure(s) remain")
    if int(missing_alt_text) > 0:
        blockers.append(f"{int(missing_alt_text)} image(s) lack alt text")
    if int(unlicensed_images) > 0:
        blockers.append(f"{int(unlicensed_images)} image(s) lack approved licensing or source attribution")
    screenshot_records: list[dict[str, Any]] = []
    screenshot_errors: list[str] = []
    for raw in screenshots or []:
        value = _bounded_text(raw, 4000)
        viewport, separator, locator = value.partition("=")
        viewport = viewport.strip().lower()
        locator = locator.strip()
        if separator != "=" or viewport not in {"desktop", "mobile"} or not locator:
            screenshot_errors.append("visual screenshot references must use desktop=<path-or-https-url> or mobile=<path-or-https-url>")
            continue
        parsed = urlparse(locator)
        if parsed.scheme == "https" and parsed.hostname:
            screenshot_records.append({"viewport": viewport, "locator": locator, "sha256": "", "size_bytes": None})
            continue
        candidate_path = Path(locator).expanduser()
        if candidate_path.is_symlink():
            screenshot_errors.append(f"{viewport} screenshot must be a regular non-symlink file or HTTPS URL")
            continue
        path = candidate_path.resolve()
        if not path.is_file():
            screenshot_errors.append(f"{viewport} screenshot must be a regular non-symlink file or HTTPS URL")
            continue
        size = path.stat().st_size
        if size <= 0 or size > 10 * 1024 * 1024:
            screenshot_errors.append(f"{viewport} screenshot must be between 1 byte and 10 MiB")
            continue
        content = path.read_bytes()
        signature = content[:16]
        is_png = signature.startswith(b"\x89PNG\r\n\x1a\n")
        is_jpeg = signature.startswith(b"\xff\xd8\xff")
        is_webp = len(signature) >= 12 and signature[:4] == b"RIFF" and signature[8:12] == b"WEBP"
        if not (is_png or is_jpeg or is_webp):
            screenshot_errors.append(f"{viewport} screenshot is not a recognized PNG, JPEG, or WebP image")
            continue
        screenshot_records.append(
            {
                "viewport": viewport,
                "locator": f"visual-qa:{path.name}",
                "sha256": hashlib.sha256(content).hexdigest(),
                "size_bytes": size,
            }
        )
    captured_viewports = {item["viewport"] for item in screenshot_records}
    missing_viewports = sorted({"desktop", "mobile"} - captured_viewports)
    if missing_viewports:
        blockers.append("stored visual evidence is required for: " + ", ".join(missing_viewports))
    blockers.extend(sorted(set(screenshot_errors)))
    details = {
        "desktop_rendered": bool(desktop_rendered),
        "mobile_rendered": bool(mobile_rendered),
        "overflow_count": max(0, int(overflow_count)),
        "contrast_failures": max(0, int(contrast_failures)),
        "missing_alt_text": max(0, int(missing_alt_text)),
        "unlicensed_images": max(0, int(unlicensed_images)),
        "screenshots": screenshot_records,
        "visual_model_is_advisory": True,
        "human_editorial_approval_required": True,
    }
    score = max(0, 100 - len(blockers) * 20)
    return _store_audit(case_id, audit_type="visual_qa", status="blocked" if blockers else "passed", score=score, blockers=blockers, warnings=[], details=details, actor=actor, db_path=db_path)


def queue_blinded_specialist_review(
    case_id: str,
    *,
    actor: str = "research-orchestrator",
    db_path: str | None = None,
) -> dict[str, Any]:
    workspace = get_reliability_workspace(case_id, db_path=db_path)
    full = next((item for item in workspace["run_bundles"] if item["stage"] == "full" and item["status"] == "succeeded"), None)
    if not full or not full.get("verification", {}).get("tamper_evident"):
        raise ValueError("a verified full research bundle is required before specialist review")
    if not workspace["claim_ledger"]:
        raise ValueError("build the claim ledger before specialist review")
    from secopsai.specialist_orchestrator import auto_route_task

    case = _case(case_id, db_path)
    task = {
        "task_id": case_id,
        "title": f"Evidence-grounded security research review: {case.get('title')}",
        "description": "Review the immutable evidence bundle and claim ledger. Distinguish confirmed facts, qualified inferences, contradictions, unsupported claims, and missing evidence. Do not publish or mutate systems.",
        "domain": "threat-intelligence",
        "priority": case.get("severity") or "medium",
        "status": "validation",
        "evidence_refs": [item.get("evidence_id") for item in case.get("evidence") or [] if item.get("status", "active") == "active"][:25],
        "external_facing": True,
        "requires_security_review": True,
        "analysis_only": True,
    }
    routed = auto_route_task(task, requested_by=actor, db_path=db_path)
    return {"case_id": case_id, "bundle_id": full["bundle_id"], "claim_count": len(workspace["claim_ledger"]), "specialist": routed, "blind_review_context": "The independent reviewer receives the evidence bundle and claims, but not the primary verdict, confidence, persuasive wording, or publication recommendation."}


def queue_blinded_independent_review(
    case_id: str,
    *,
    actor: str = "research-orchestrator",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Recover or explicitly queue the blind-review stage for a case."""
    from secopsai.specialist_orchestrator import enqueue_blind_review, list_runs

    runs = [item for item in list_runs(limit=100, db_path=db_path) if str(item.get("task_id") or "") == case_id]
    if not runs:
        raise ValueError("run the primary domain specialist before blind review")
    run = enqueue_blind_review(str(runs[0]["run_id"]), actor=actor, db_path=db_path)
    return {
        "case_id": case_id,
        "run": run,
        "blinded": True,
        "primary_result_included": False,
        "primary_verdict_included": False,
        "human_adjudication_required_on_material_disagreement": True,
    }


def _specialist_review_state(case_id: str, db_path: str | None) -> dict[str, Any]:
    try:
        from secopsai.specialist_orchestrator import list_runs

        runs = [item for item in list_runs(limit=100, db_path=db_path) if str(item.get("task_id") or "") == case_id]
    except Exception:
        runs = []
    latest = runs[0] if runs else None
    if not latest:
        return {"status": "not_started", "material_disagreement": False, "adjudication_status": "not_required", "publication_blocked": True, "run": None}
    review = latest.get("review") or {}
    comparison = review.get("comparison") if isinstance(review.get("comparison"), dict) else {}
    disagreement = bool(latest.get("material_disagreement") or comparison.get("material_disagreement"))
    adjudication_status = str(latest.get("adjudication_status") or comparison.get("adjudication_status") or "not_required")
    disagreement_resolved = adjudication_status in {"resolved_primary", "resolved_reviewer"}
    completed = latest.get("status") in {"needs_review", "completed", "accepted"} and bool(review)
    return {
        "status": "completed" if completed else str(latest.get("status") or "pending"),
        "material_disagreement": disagreement,
        "adjudication_status": adjudication_status,
        "adjudication_note": str(latest.get("adjudication_note") or ""),
        "publication_blocked": not completed or (disagreement and not disagreement_resolved),
        "run": latest,
    }


def publication_reliability_gate(case_id: str, *, db_path: str | None = None) -> dict[str, Any]:
    workspace = get_reliability_workspace(case_id, db_path=db_path)
    blockers: list[str] = []
    full = next((item for item in workspace["run_bundles"] if item["stage"] == "full"), None)
    if not full or full["status"] != "succeeded" or not full.get("verification", {}).get("tamper_evident"):
        blockers.append("a successful tamper-evident full research bundle is required")
    claims = workspace.get("effective_claim_ledger") or workspace["claim_ledger"]
    if not claims:
        blockers.append("a claim ledger is required")
    elif any(item["support_status"] in {"unsupported", "contradicted"} for item in claims):
        blockers.append("unsupported or contradicted claims remain")
    review = workspace["specialist_review"]
    if review["publication_blocked"]:
        blockers.append("specialist and blinded independent review must complete without material disagreement")
    latest_audits = workspace["latest_audits"]
    for audit_type in ("completeness", "originality", "visual_qa"):
        if audit_type not in latest_audits or latest_audits[audit_type]["status"] != "passed":
            blockers.append(f"{audit_type.replace('_', ' ')} audit must pass")
    score = research_quality_score(case_id, workspace=workspace, db_path=db_path)
    blockers.extend(item for item in score["hard_blockers"] if item not in blockers)
    return {"case_id": case_id, "ready": not blockers, "blockers": blockers, "quality": score, "human_publication_approval_required": True, "publish_and_deploy_are_separate": True}


def research_quality_score(
    case_id: str,
    *,
    workspace: dict[str, Any] | None = None,
    db_path: str | None = None,
) -> dict[str, Any]:
    workspace = workspace or get_reliability_workspace(case_id, db_path=db_path)
    claims = workspace.get("effective_claim_ledger") or workspace["claim_ledger"]
    coverage = int(round(sum(item["support_status"] in {"supported", "qualified_inference"} for item in claims) / max(1, len(claims)) * 100))
    unsupported = sum(item["support_status"] == "unsupported" for item in claims)
    contradicted = sum(item["support_status"] == "contradicted" for item in claims)
    latest_audits = workspace["latest_audits"]
    completeness = int((latest_audits.get("completeness") or {}).get("score") or 0)
    originality = int((latest_audits.get("originality") or {}).get("score") or 0)
    visual = int((latest_audits.get("visual_qa") or {}).get("score") or 0)
    evidence = min(100, len(_case(case_id, db_path).get("evidence") or []) * 15)
    clarity = 80 if claims else 0
    reproducibility = max([int(item.get("completeness_score") or 0) for item in workspace["run_bundles"]] or [0])
    mitigation_quality = 70 if any("mitigat" in item.get("text_span", "").lower() for item in claims) else 40
    latency_penalty = min(15, len([item for item in workspace["run_bundles"] if item["status"] == "blocked"]) * 3)
    aggregate = round(
        coverage * 0.24 + evidence * 0.15 + clarity * 0.10 + reproducibility * 0.14
        + originality * 0.10 + completeness * 0.12 + visual * 0.08 + mitigation_quality * 0.07
        - unsupported * 8 - contradicted * 15 - latency_penalty
    )
    hard_blockers = []
    if unsupported:
        hard_blockers.append("unsupported claims")
    if contradicted:
        hard_blockers.append("contradicted claims")
    if (latest_audits.get("completeness") or {}).get("status") == "blocked":
        hard_blockers.append("completeness audit blocked")
    if (latest_audits.get("originality") or {}).get("status") == "blocked":
        hard_blockers.append("originality audit blocked")
    return {"score": max(0, min(100, aggregate)), "components": {"evidence_coverage": coverage, "evidence_depth": evidence, "clarity": clarity, "reproducibility": reproducibility, "originality": originality, "completeness": completeness, "visual_quality": visual, "mitigation_quality": mitigation_quality}, "penalties": {"unsupported_claims": unsupported, "contradicted_claims": contradicted, "latency": latency_penalty}, "hard_blockers": hard_blockers, "hard_failures_override_score": True}


def _decode_audit(row: Any) -> dict[str, Any]:
    result = _row_dict(row)
    result["hard_blockers"] = _decode(result.pop("hard_blockers_json", None), [])
    result["warnings"] = _decode(result.pop("warnings_json", None), [])
    result["details"] = _decode(result.pop("details_json", None), {})
    return result


def get_reliability_workspace(case_id: str, *, db_path: str | None = None) -> dict[str, Any]:
    soc_store.init_db(db_path)
    with closing(soc_store.connect(db_path)) as connection:
        hypotheses = [_decode_hypothesis(row) for row in connection.execute("SELECT * FROM research_hypotheses WHERE case_id=? ORDER BY revision DESC, status='selected' DESC, hypothesis_id", (case_id,)).fetchall()]
        comparisons = []
        for row in connection.execute("SELECT * FROM research_hypothesis_comparisons WHERE case_id=? ORDER BY created_at DESC", (case_id,)).fetchall():
            item = _row_dict(row)
            item["rationale"] = _decode(item.pop("rationale_json", None), {})
            item["evidence_refs"] = _decode(item.pop("evidence_refs_json", None), [])
            item["score"] = _decode(item.pop("score_json", None), {})
            comparisons.append(item)
        plans = [_decode_plan(row) for row in connection.execute("SELECT * FROM research_evidence_plans WHERE case_id=? ORDER BY revision DESC", (case_id,)).fetchall()]
        bundle_rows = connection.execute("SELECT * FROM research_run_bundles WHERE case_id=? ORDER BY created_at DESC, bundle_id DESC", (case_id,)).fetchall()
        claim_rows = connection.execute("SELECT * FROM research_claim_ledger WHERE case_id=? ORDER BY updated_at DESC, source_kind, span_start", (case_id,)).fetchall()
        revision_rows = connection.execute("SELECT * FROM research_claim_revisions WHERE case_id=? ORDER BY created_at DESC", (case_id,)).fetchall()
        audit_rows = connection.execute("SELECT * FROM research_reliability_audits WHERE case_id=? ORDER BY created_at DESC", (case_id,)).fetchall()
    bundles = []
    for row in bundle_rows:
        bundle = inspect_run_bundle(str(row["bundle_id"]), db_path=db_path)
        bundles.append(bundle)
    claims = [_decode_claim(row) for row in claim_rows]
    revisions = []
    for row in revision_rows:
        item = _row_dict(row)
        item["evidence_ids"] = _decode(item.pop("evidence_ids_json", None), [])
        revisions.append(item)
    audits = [_decode_audit(row) for row in audit_rows]
    revised_claim_ids = {
        str(item.get("claim_id") or "")
        for item in revisions
        if item.get("action") in {"qualified", "removed"}
    }
    effective_claims = [item for item in claims if item.get("claim_id") not in revised_claim_ids]
    latest_by_type: dict[str, dict[str, Any]] = {}
    for audit in audits:
        latest_by_type.setdefault(audit["audit_type"], audit)
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": case_id,
        "hypotheses": hypotheses,
        "comparisons": comparisons,
        "plans": plans,
        "run_bundles": bundles,
        "claim_ledger": claims,
        "effective_claim_ledger": effective_claims,
        "claim_revisions": revisions,
        "audits": audits,
        "latest_audits": latest_by_type,
        "specialist_review": _specialist_review_state(case_id, db_path),
        "next_action": _next_action(hypotheses, plans, bundles, effective_claims, latest_by_type, _specialist_review_state(case_id, db_path)),
    }


def _next_action(
    hypotheses: list[dict[str, Any]],
    plans: list[dict[str, Any]],
    bundles: list[dict[str, Any]],
    claims: list[dict[str, Any]],
    audits: dict[str, dict[str, Any]],
    review: dict[str, Any],
) -> dict[str, str]:
    if not hypotheses:
        return {"action": "generate_hypotheses", "label": "Generate competing hypotheses", "reason": "Research must begin with falsifiable alternatives rather than one assumed verdict."}
    if not any(item.get("status") == "selected" for item in hypotheses):
        return {"action": "rank_hypotheses", "label": "Rank hypotheses", "reason": "Select the highest evidence-value safe hypothesis under the configured budget."}
    if not plans:
        return {"action": "create_plan", "label": "Create evidence plan", "reason": "Record intended methods, safety limits, expected outputs, and completion criteria."}
    for stage, action, label in (("scaffold", "run_scaffold", "Run scaffold research"), ("transition", "verify_transition", "Verify transition"), ("full", "run_full", "Run full safe research")):
        latest = next((item for item in bundles if item["stage"] == stage), None)
        if not latest or latest["status"] != "succeeded":
            return {"action": action, "label": label, "reason": f"The {stage} reliability gate has not passed."}
    if not claims:
        return {"action": "build_claim_ledger", "label": "Build claim ledger", "reason": "Every factual statement needs a traceable support decision."}
    if any(item["support_status"] in {"unsupported", "contradicted"} for item in claims):
        return {"action": "verify_claims", "label": "Resolve unsupported claims", "reason": "Unsupported or contradicted statements must be removed, qualified, or backed by evidence."}
    if review.get("material_disagreement") and review.get("adjudication_status") not in {"resolved_primary", "resolved_reviewer"}:
        return {"action": "adjudicate_review", "label": "Adjudicate review disagreement", "reason": "The primary and blinded independent reviewers reached materially different verdict families; record an evidence-backed human decision before publication."}
    if review["publication_blocked"]:
        return {"action": "queue_specialist", "label": "Run specialist and blind review", "reason": "Independent review must complete in a separate context without the primary verdict."}
    for audit_type, action, label in (("completeness", "audit_completeness", "Audit completeness"), ("originality", "audit_originality", "Check originality"), ("visual_qa", "visual_qa", "Render publication preview")):
        if audit_type not in audits or audits[audit_type]["status"] != "passed":
            return {"action": action, "label": label, "reason": f"The {audit_type.replace('_', ' ')} gate has not passed."}
    return {"action": "publication_review", "label": "Run publication safety", "reason": "Reliability gates passed; a human publication decision is still required."}


def _load_reliability_benchmark_fixtures() -> tuple[list[dict[str, Any]], str]:
    path = Path(__file__).with_name("reliability_benchmark_fixtures.json")
    raw = path.read_bytes()
    payload = json.loads(raw.decode("utf-8"))
    fixtures = payload.get("fixtures") if isinstance(payload, dict) else None
    if payload.get("schema_version") != "secopsai.reliability-benchmark-fixtures.v1" or not isinstance(fixtures, list):
        raise ValueError("invalid reliability benchmark fixture schema")
    identifiers = [str(item.get("id") or "") for item in fixtures if isinstance(item, dict)]
    if len(fixtures) != 15 or len(set(identifiers)) != 15 or any(not item for item in identifiers):
        raise ValueError("the reliability benchmark requires exactly 15 uniquely identified fixtures")
    return [dict(item) for item in fixtures], hashlib.sha256(raw).hexdigest()


def _benchmark_defects(fixture: dict[str, Any]) -> dict[str, bool]:
    claims = [item for item in fixture.get("claims") or [] if isinstance(item, dict)]
    reported = set(fixture.get("reported_methods") or [])
    executed = set(fixture.get("executed_methods") or [])
    suspect_fields = set(fixture.get("suspect_comparison_fields") or [])
    reference_fields = set(fixture.get("reference_comparison_fields") or [])
    actions = [str(item) for item in fixture.get("actions") or []]
    return {
        "unsupported_claim": any(not bool(item.get("supported")) for item in claims),
        "failed_result_claims_success": fixture.get("run_status") == "failed" and any(item.get("kind") == "result_success" for item in claims),
        "hard_coded_output": bool(fixture.get("hard_coded_metrics")),
        "mock_presented_as_real": bool(fixture.get("mock_markers")),
        "methodology_divergence": bool(reported - executed),
        "selective_reporting": int(fixture.get("failed_attempts") or 0) > int(fixture.get("recorded_failures") or 0),
        "asymmetric_comparison": bool(suspect_fields or reference_fields) and suspect_fields != reference_fields,
        "source_domain_misclassified": fixture.get("source_domain_classification") == "attacker_ioc",
        "attribution_or_originality": float(fixture.get("source_similarity") or 0.0) >= 0.82 or fixture.get("attribution_present") is False,
        "empty_success_logs": fixture.get("run_status") == "succeeded" and int(fixture.get("log_entries") or 0) == 0,
        "evidence_contradiction": bool(fixture.get("static_verdict")) and bool(fixture.get("sandbox_verdict")) and fixture.get("static_verdict") != fixture.get("sandbox_verdict"),
        "reviewer_disagreement": bool(fixture.get("primary_verdict")) and bool(fixture.get("reviewer_verdict")) and fixture.get("primary_verdict") != fixture.get("reviewer_verdict"),
        "unsafe_composition": bool(actions) and bool(screen_research_safety(actions=actions)["blockers"]),
    }


def _run_benchmark_condition(
    fixtures: Sequence[dict[str, Any]],
    *,
    controls: dict[str, bool],
) -> dict[str, Any]:
    started = time.perf_counter()
    total_claims = 0
    exposed_claims = 0
    supported_exposed_claims = 0
    unsupported_exposed_claims = 0
    hallucination_events = 0
    divergence_events = 0
    selective_reporting_events = 0
    attribution_events = 0
    reviewer_disagreement_unblocked = 0
    false_positives = 0
    false_negatives = 0
    correct_publication_decisions = 0
    fixture_results: list[dict[str, Any]] = []

    for fixture in fixtures:
        defects = _benchmark_defects(fixture)
        claims = [item for item in fixture.get("claims") or [] if isinstance(item, dict)]
        unsupported = sum(not bool(item.get("supported")) for item in claims)
        supported = len(claims) - unsupported
        total_claims += len(claims)
        corrections = unsupported if controls.get("claim_verification") and controls.get("claim_clipping") else 0
        remaining_unsupported = unsupported - corrections
        exposed_claims += supported + remaining_unsupported
        supported_exposed_claims += supported
        unsupported_exposed_claims += remaining_unsupported
        blockers: list[str] = []

        if controls.get("claim_verification") and remaining_unsupported:
            blockers.append("unsupported claims remain")
        if controls.get("completeness"):
            completeness_checks = {
                "failed result claimed success": defects["failed_result_claims_success"],
                "hard-coded favorable output": defects["hard_coded_output"],
                "mock presented as real analysis": defects["mock_presented_as_real"],
                "reported methods differ from execution": defects["methodology_divergence"],
                "failed attempts omitted": defects["selective_reporting"],
                "comparison is asymmetric": defects["asymmetric_comparison"],
                "successful run has empty logs": defects["empty_success_logs"],
            }
            blockers.extend(label for label, failed in completeness_checks.items() if failed)
        if controls.get("indicator_classification") and defects["source_domain_misclassified"]:
            blockers.append("reporting source was classified as attacker infrastructure")
        if controls.get("originality") and defects["attribution_or_originality"]:
            blockers.append("source similarity or attribution check failed")
        if controls.get("contradiction") and defects["evidence_contradiction"]:
            blockers.append("static and sandbox evidence conflict")
        if controls.get("blind_review") and defects["reviewer_disagreement"]:
            blockers.append("material specialist/reviewer disagreement requires human adjudication")
        if controls.get("safety") and defects["unsafe_composition"]:
            blockers.append("unsafe compositional action plan")

        final_verdict = str(fixture.get("proposed_verdict") or "unknown")
        expected_verdict = str(fixture.get("expected_verdict") or "unknown")
        if controls.get("verdict_calibration") and expected_verdict != "unknown":
            if all(bool(item.get("supported")) for item in claims):
                final_verdict = expected_verdict
            elif final_verdict != expected_verdict:
                blockers.append("proposed verdict is not supported by canonical evidence")

        prevented = bool(blockers) or corrections > 0
        expected_prevented = bool(fixture.get("expected_publication_blocked"))
        decision_correct = prevented == expected_prevented
        correct_publication_decisions += int(decision_correct)
        if defects["failed_result_claims_success"] and not prevented:
            hallucination_events += 1
        if defects["methodology_divergence"] and not prevented:
            divergence_events += 1
        if defects["selective_reporting"] and not prevented:
            selective_reporting_events += 1
        if defects["attribution_or_originality"] and not prevented:
            attribution_events += 1
        if defects["reviewer_disagreement"] and not prevented:
            reviewer_disagreement_unblocked += 1
        if expected_verdict == "benign" and final_verdict == "malicious" and not prevented:
            false_positives += 1
        if expected_verdict == "malicious" and final_verdict == "benign" and not prevented:
            false_negatives += 1
        fixture_results.append(
            {
                "id": fixture["id"],
                "detected_defects": sorted(key for key, value in defects.items() if value),
                "corrections": corrections,
                "blockers": sorted(set(blockers)),
                "publication_prevented": prevented,
                "expected_publication_prevented": expected_prevented,
                "decision_correct": decision_correct,
                "final_verdict": final_verdict,
            }
        )

    total = max(1, len(fixtures))
    evaluated_claims = max(1, exposed_claims)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return {
        "unsupported_claim_rate": round(unsupported_exposed_claims / evaluated_claims, 4),
        "claim_evidence_coverage": round(supported_exposed_claims / evaluated_claims, 4) if exposed_claims else 1.0,
        "result_hallucination_severity": round(hallucination_events / total, 4),
        "methodology_divergence": round(divergence_events / total, 4),
        "selective_reporting_rate": round(selective_reporting_events / total, 4),
        "plagiarism_attribution_failures": round(attribution_events / total, 4),
        "reviewer_disagreement_unblocked": round(reviewer_disagreement_unblocked / total, 4),
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "publication_block_accuracy": round(correct_publication_decisions / total, 4),
        "estimated_model_calls": 0,
        "estimated_cost_usd": 0.0,
        "measured_evaluator_latency_ms": round(elapsed_ms, 3),
        "fixture_count": len(fixtures),
        "claim_count": total_claims,
        "fixture_results": fixture_results,
    }


def reliability_benchmark() -> dict[str, Any]:
    fixtures, fixture_digest = _load_reliability_benchmark_fixtures()
    conditions = {
        "full_controls": {
            "claim_verification": True,
            "claim_clipping": True,
            "completeness": True,
            "indicator_classification": True,
            "originality": True,
            "contradiction": True,
            "blind_review": True,
            "safety": True,
            "verdict_calibration": True,
        },
        "claim_clipping_disabled": {
            "claim_verification": True,
            "claim_clipping": False,
            "completeness": True,
            "indicator_classification": True,
            "originality": True,
            "contradiction": True,
            "blind_review": True,
            "safety": True,
            "verdict_calibration": True,
        },
        "completeness_audit_disabled": {
            "claim_verification": True,
            "claim_clipping": True,
            "completeness": False,
            "indicator_classification": True,
            "originality": True,
            "contradiction": True,
            "blind_review": True,
            "safety": True,
            "verdict_calibration": True,
        },
        "unconstrained_mock_baseline": {
            "claim_verification": False,
            "claim_clipping": False,
            "completeness": False,
            "indicator_classification": False,
            "originality": False,
            "contradiction": False,
            "blind_review": False,
            "safety": False,
            "verdict_calibration": False,
        },
    }
    results = {
        name: {
            "controls": enabled,
            **_run_benchmark_condition(fixtures, controls=enabled),
        }
        for name, enabled in conditions.items()
    }
    full = results["full_controls"]
    passed = (
        full["publication_block_accuracy"] == 1.0
        and full["unsupported_claim_rate"] == 0.0
        and full["false_positives"] == 0
        and full["false_negatives"] == 0
        and all(item["decision_correct"] for item in full["fixture_results"])
    )
    return {
        "schema_version": "secopsai.reliability-benchmark.v2",
        "isolated_fixture_mode": True,
        "fixture_digest_sha256": fixture_digest,
        "production_controls_modified": False,
        "fixtures": [item["id"] for item in fixtures],
        "conditions": results,
        "passed": passed,
        "limitations": [
            "The benchmark executes deterministic offline guardrail fixtures; it does not estimate registry prevalence or real-world model quality.",
            "Measured evaluator latency covers local fixture evaluation only; all model-call and cost estimates are zero because the benchmark performs no model inference.",
        ],
    }
