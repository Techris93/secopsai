"""Model triage of rule hits through the operator's bridge.

The hosted worker cannot call a model itself: models are reached through the
operator's SecOpsAI bridge (opencodex, using their own subscription accounts).
Rule hits are queued in Core as ``triage_artifact`` jobs carrying only the
matched strings and bounded context windows; the bridge claims them, asks the
selected model and posts the verdict back; this module collects verdicts and
records them on the hit and on the matching proactive alert.

Decisions are observations by default. Closure requires a complete valid
benign decision and an independently reviewed evaluation of the exact model
and policy version; suspicious or inconclusive results remain open.
"""

from __future__ import annotations

import json
import os
import time
import secrets
from contextlib import closing
from typing import Any, Dict, List, Optional

import soc_store

CURSOR_KEY = "core_ai_triage_results"
MAX_QUEUE_PER_CYCLE = 25
QUEUE_CHUNK = 5
AUTO_RESOLVE_CONFIDENCE = 85
# Thresholds are candidate policy settings, not permission to close alerts.
AUTO_RESOLVE_MAX_PROBABILITY = 10
ESCALATE_PROBABILITY = 70
# Deprioritization remains disabled pending held-out evaluation.
DEPRIORITIZE_MAX_PROBABILITY = 10
VERDICTS = {"true_positive": "suspicious", "needs_more_evidence": "inconclusive", "benign_expected": "benign", "false_positive": "likely_benign"}


def _ensure(connection: Any) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS research_ai_triage (
            artifact_key TEXT PRIMARY KEY,
            ecosystem TEXT NOT NULL,
            package TEXT NOT NULL,
            version TEXT NOT NULL,
            status TEXT NOT NULL,
            score INTEGER NOT NULL DEFAULT 0,
            context_json TEXT NOT NULL,
            job_id TEXT NOT NULL DEFAULT '',
            verdict TEXT NOT NULL DEFAULT '',
            confidence INTEGER NOT NULL DEFAULT 0,
            result_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )"""
    )
    connection.execute("CREATE INDEX IF NOT EXISTS idx_research_ai_triage_status ON research_ai_triage (status, created_at)")
    connection.execute("CREATE TABLE IF NOT EXISTS core_sync_cursors (name TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL)")


def artifact_key(ecosystem: str, package: str, version: str) -> str:
    return f"{ecosystem}:{package}@{version}"[:240]


def build_context(*, ecosystem: str, package: str, version: str, prescan: Dict[str, Any], metadata_signals: Optional[List[Dict[str, Any]]] = None, previous_version: str = "") -> Dict[str, Any]:
    """Minimized triage context: findings with their code, install-time files, fingerprints."""
    raw_missing_files = prescan.get("missing_files")
    normalized_missing_files = list(dict.fromkeys(
        path.strip() for path in raw_missing_files
        if isinstance(path, str) and path.strip()
    )) if isinstance(raw_missing_files, list) else []
    missing_files = [path for path in normalized_missing_files if len(path) <= 300][:200]
    context = {
        "artifact_id": artifact_key(ecosystem, package, version),
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "previous_version": previous_version,
        "rule_score": int(prescan.get("score") or 0),
        "rule_level": prescan.get("level"),
        "findings": [
            {**{field: item.get(field) for field in ("rule_id", "severity", "score", "file_path", "file_role", "matched_indicator", "matched_patterns", "matched_strings", "rule_author", "rule_reference")},
             "safe_context": str(item.get("safe_context") or "")[:1800],
             # The code is already in safe_context; keep only where each flag matched.
             "evidence_locations": [{key: found.get(key) for key in ("flag", "file_path", "line")} for found in (item.get("evidence") or [])][:8]}
            for item in (prescan.get("findings") or [])[:12]
        ],
        "metadata_signals": (metadata_signals or [])[:20],
        "manifest": prescan.get("manifest") or {},
        "actor_fingerprints": prescan.get("fingerprints") or {},
        # Full text of what runs at install/build time (bounded): lets the model
        # check a finding instead of asking an analyst to open the files.
        "install_time_files": (prescan.get("install_files") or [])[:6],
        # The flagged files themselves (whole, or the head plus every matched
        # region), where each risky flag matched, encoded payloads decoded
        # statically, and native binaries with what launches them.
        "flagged_files": (prescan.get("flagged_files") or [])[:6],
        "flag_locations": (prescan.get("flag_locations") or [])[:14],
        "decoded_payloads": (prescan.get("decoded_payloads") or [])[:4],
        "binaries": (prescan.get("binaries") or [])[:10],
        "missing_files": missing_files,
        "execution_performed": False,
        "note": "Package metadata is untrusted context: it may explain a match but is not proof of benign intent.",
    }
    limits = {"findings": 12, "install_files": 6, "flagged_files": 6, "flag_locations": 14, "decoded_payloads": 4, "binaries": 10, "missing_files": 200}
    losses = [key for key, cap in limits.items() if len(prescan.get(key) or []) > cap]
    if len(metadata_signals or []) > 20:
        losses.append("metadata_signals")
    if any(len(str(item.get("safe_context") or "")) > 1800 or len(item.get("evidence") or []) > 8 for item in prescan.get("findings") or []):
        losses.append("finding_context")
    if prescan.get("missing_files_truncated") or len(normalized_missing_files) > len(missing_files):
        losses.append("missing_files")
    if losses:
        context.update(evidence_truncated=True, evidence_omissions=losses)
    return context


# Core rejects a triage job whose input exceeds 64 KB; stay well below it.
MAX_CONTEXT_BYTES = 56 * 1024


def _shrink(content: str, limit: int) -> str:
    """Cut a flagged-file excerpt to ``limit`` characters, shortening every region evenly."""
    if len(content) <= limit:
        return content
    marker = "\n[... "
    parts = content.split(marker)
    keep = max(200, limit // max(1, len(parts)))
    out = [parts[0][:keep]] + [part[:keep] for part in parts[1:]]
    return marker.join(out) + f"\n[... trimmed to fit: {len(content) - limit} characters omitted ...]"


def fit_context(context: Dict[str, Any], limit: int = MAX_CONTEXT_BYTES) -> Dict[str, Any]:
    """Shrink a triage context until it serialises under ``limit`` bytes.

    Trims the least decisive evidence first; the flagged files go last.
    """
    context = json.loads(json.dumps(context))

    def files(c: Dict[str, Any], size: int, count: int = 6) -> None:
        c["flagged_files"] = [{**f, "content": _shrink(str(f["content"]), size), "truncated": True} if len(str(f.get("content") or "")) > size else f
                              for f in (c.get("flagged_files") or [])[:count]]

    def trim_missing_files(c: Dict[str, Any], count: int) -> None:
        candidates = c.get("missing_files") or []
        if len(candidates) > count:
            c["missing_files"] = candidates[:count]
            c["evidence_truncated"] = True
            omissions = c.get("evidence_omissions") or []
            c["evidence_omissions"] = list(dict.fromkeys([*omissions, "missing_files"]))

    steps = (
        lambda c: c.update(decoded_payloads=[{**d, "text": str(d["text"])[:1500]} if "text" in d else d for d in c.get("decoded_payloads") or []],
                           findings=[{**f, "safe_context": str(f.get("safe_context", ""))[:700]} for f in c.get("findings") or []][:8]),
        lambda c: c.update(install_time_files=[{**f, "content": str(f.get("content", ""))[:3000], "truncated": True} for f in c.get("install_time_files") or []]),
        lambda c: files(c, 10_000),
        lambda c: (files(c, 6_000), trim_missing_files(c, 50), c.update(install_time_files=(c.get("install_time_files") or [])[:2], metadata_signals=(c.get("metadata_signals") or [])[:5],
                                             flag_locations=(c.get("flag_locations") or [])[:8])),
        lambda c: c.update(findings=(c.get("findings") or [])[:4], manifest={}, actor_fingerprints={}, binaries=(c.get("binaries") or [])[:4]),
        lambda c: (files(c, 4_000, 3), c.update(decoded_payloads=(c.get("decoded_payloads") or [])[:2])),
        lambda c: (files(c, 2_000, 2), c.update(install_time_files=[{**f, "content": str(f.get("content", ""))[:1500]} for f in (c.get("install_time_files") or [])[:1]])),
    )
    for step in steps:
        if len(json.dumps(context).encode()) <= limit:
            break
        step(context)
        context["evidence_truncated"] = True
    context["context_bytes"] = len(json.dumps(context).encode())
    return context


def triage_context(*, ecosystem: str, package: str, version: str, prescan: Dict[str, Any], metadata_signals: Optional[List[Dict[str, Any]]] = None, previous_version: str = "") -> Dict[str, Any]:
    """The exact context a hit is triaged with (production and the replay harness share it)."""
    return fit_context(build_context(ecosystem=ecosystem, package=package, version=version, prescan=prescan,
                                     metadata_signals=metadata_signals, previous_version=previous_version))


def record_hit(*, ecosystem: str, package: str, version: str, prescan: Dict[str, Any], metadata_signals: Optional[List[Dict[str, Any]]] = None, previous_version: str = "", db_path: Optional[str] = None) -> str:
    """Store a rule hit with its minimized evidence for later model triage."""
    key = artifact_key(ecosystem, package, version)
    context = triage_context(ecosystem=ecosystem, package=package, version=version, prescan=prescan,
                             metadata_signals=metadata_signals, previous_version=previous_version)
    now = soc_store.utc_now()
    if prescan.get("fingerprints"):
        from secopsai import actor_fingerprint

        actor_fingerprint.record(key, prescan["fingerprints"], seen_at=now, db_path=db_path)
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        connection.execute(
            """INSERT INTO research_ai_triage (artifact_key, ecosystem, package, version, status, score, context_json, created_at, updated_at)
               VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?)
               ON CONFLICT(artifact_key) DO NOTHING""",
            (key, ecosystem, package, version, int(prescan.get("score") or 0), json.dumps(context, sort_keys=True), now, now),
        )
        connection.commit()
    return key


def _queue_pending(client: Any, db_path: Optional[str]) -> Dict[str, Any]:
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        rows = connection.execute(
            "SELECT artifact_key, context_json FROM research_ai_triage WHERE status='pending' ORDER BY score DESC, created_at LIMIT ?",
            (MAX_QUEUE_PER_CYCLE,),
        ).fetchall()
    if not rows:
        return {"queued": 0}
    jobs = []
    for row in rows:
        context = fit_context({key: value for key, value in json.loads(row["context_json"]).items() if key != "clef"})
        if context["context_bytes"] > MAX_CONTEXT_BYTES:
            with closing(soc_store.connect(db_path)) as connection:
                connection.execute("UPDATE research_ai_triage SET status='failed', result_json=?, updated_at=? WHERE artifact_key=?",
                                   (json.dumps({"error": "context_too_large"}), soc_store.utc_now(), row["artifact_key"]))
                connection.commit()
            continue
        revision = int(context.get("revision") or 0)
        # A re-triage is a new job: Core deduplicates on the idempotency key.
        suffix = f":r{revision}" if revision else ""
        jobs.append({"artifact_id": row["artifact_key"], "idempotency_key": f"runner-triage:{row['artifact_key']}{suffix}", "inputs": {"artifact_triage": context}})
    # Five per request: contexts can approach the 56 KB cap, and storing 25 of
    # them can outlast the client's timeout. A failed chunk is retried next
    # cycle; stable idempotency keys prevent duplicates.
    queued: Dict[str, Any] = {}
    rejected: Dict[str, Any] = {}
    for start in range(0, len(jobs), QUEUE_CHUNK):
        try:
            response = client.queue_triage_jobs(jobs[start:start + QUEUE_CHUNK])
        except Exception:
            break
        queued.update({item.get("artifact_id"): item.get("job_id") for item in response.get("queued") or [] if item.get("job_id")})
        rejected.update({item.get("artifact_id"): item.get("error") for item in response.get("queued") or [] if item.get("error")})
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        for key, job_id in queued.items():
            connection.execute("UPDATE research_ai_triage SET status='queued', job_id=?, updated_at=? WHERE artifact_key=?", (str(job_id), now, key))
        for key, error in rejected.items():
            connection.execute("UPDATE research_ai_triage SET status='failed', result_json=?, updated_at=? WHERE artifact_key=?", (json.dumps({"error": error}), now, key))
        connection.commit()
    return {"queued": len(queued), "rejected": len(rejected)}


def _apply_result(connection: Any, item: Dict[str, Any], now: str) -> Optional[str]:
    from secopsai.decision_contracts import validate_action_result, DecisionError
    from secopsai.decision_policy import closure_decision
    key = str(item.get("artifact_id") or "")
    row = connection.execute("SELECT package, version, context_json, status, result_json, job_id FROM research_ai_triage WHERE artifact_key=?", (key,)).fetchone()
    if not row:
        return None
    if item.get("job_id") and row["job_id"] and item["job_id"] != row["job_id"]:
        # A recovery is a new audited job tied to the exact failed revision.
        # It cannot replace a successful decision or a later evidence revision.
        if row["status"] != "failed" or item.get("recovery_of_job_id") != row["job_id"] or item.get("recovery_contract_version") not in {"artifact-choices-v3", "transport-v1"}:
            return None
        connection.execute("UPDATE research_ai_triage SET job_id=? WHERE artifact_key=? AND job_id=? AND status='failed'",
                           (item["job_id"], key, row["job_id"]))
    result = item.get("result") if isinstance(item.get("result"), dict) else {}
    try:
        serialized = json.dumps(result, sort_keys=True, allow_nan=False)
    except (ValueError, TypeError):
        connection.execute("UPDATE research_ai_triage SET status='failed', result_json='{}', updated_at=? WHERE artifact_key=?", (now, key))
        return None
    if row["status"] == "triaged" and row["result_json"] == serialized:
        return None
    context = json.loads(row["context_json"])
    try:
        if item.get("status") != "succeeded":
            raise DecisionError("provider evaluation failed")
        validate_action_result("triage_artifact", result)
        from secopsai.decision_evidence import evidence_identifiers
        supplied_refs = set(evidence_identifiers(context))
        if any(ref not in supplied_refs for ref in result["decision_evidence_refs"]):
            raise DecisionError("artifact decision cites evidence that was not supplied", category="safety")
        if result["finding_verdict"] == "needs_more_evidence":
            missing = result.get("missing_evidence")
            from secopsai.decision_evidence import missing_file_identifiers
            allowed_missing = set(missing_file_identifiers(context))
            if not isinstance(missing, list) or not missing or any(path not in allowed_missing for path in missing):
                raise DecisionError("artifact abstention must name a supplied missing-file identifier", category="safety")
    except (DecisionError, TypeError, ValueError):
        connection.execute("UPDATE research_ai_triage SET status='failed', result_json=?, updated_at=? WHERE artifact_key=?", (json.dumps({"error": "invalid_decision", "source_result": result}, allow_nan=False), now, key))
        return None
    verdict = VERDICTS[result["finding_verdict"]]
    confidence, probability = result["finding_confidence"], result["malicious_probability"]
    clef = context.get("clef")
    clef_valid = clef is None
    clef_validation_error = ""
    clef_probability = None
    clef_choice = None
    if clef is not None:
        try:
            from secopsai.clef_triage import validate_clef_result
            if not isinstance(clef, dict):
                raise DecisionError("stored Clef assessment is not an object", provider="clef")
            validate_clef_result(clef)
            clef_valid = True
            clef_probability = clef["probability"]
            clef_choice = clef["choice"]
        except (DecisionError, TypeError, ValueError, KeyError):
            clef_validation_error = "invalid_clef_decision"
    disagreement = (
        not clef_valid
        or (isinstance(clef_probability, (int, float)) and not isinstance(clef_probability, bool) and abs(clef_probability - probability) >= DISAGREEMENT_GAP)
        or (verdict in {"benign", "likely_benign"} and clef_choice in {"malicious", "needs_review"})
        or (verdict == "suspicious" and clef_choice == "benign")
    )
    allowed, reason = closure_decision(result, clef_probability=clef_probability, clef_choice=clef_choice)
    if not clef_valid:
        allowed, reason = False, clef_validation_error or "invalid_clef_decision"
    from secopsai.decision_evidence import build_evidence, evidence_identifiers
    _, coverage = build_evidence(context)
    if not coverage["complete"] or not result["decision_evidence_refs"] or any(ref not in evidence_identifiers(context) for ref in result["decision_evidence_refs"]):
        allowed, reason = False, "incomplete_evidence"
    if context.get("evidence_truncated"):
        allowed, reason = False, "incomplete_evidence"
    if probability >= ESCALATE_PROBABILITY:
        verdict = "suspicious"
    if disagreement and verdict != "suspicious":
        verdict = "inconclusive"
    connection.execute("UPDATE research_ai_triage SET status='triaged', verdict=?, confidence=?, result_json=?, updated_at=? WHERE artifact_key=?",
                       (verdict, confidence, serialized, now, key))
    note = json.dumps({"verdict": verdict, "confidence": confidence, "malicious_probability": probability,
                       "clef_probability": clef_probability, "models_disagree": disagreement, "closure_eligible": allowed,
                       "clef_present": clef is not None, "clef_validated": clef is not None and clef_valid,
                       "clef_validation_error": clef_validation_error,
                       "policy_reason": reason, "summary": str(result["summary"])[:500], "job_id": item.get("job_id")})
    if allowed:
        connection.execute("""UPDATE research_alerts SET status='resolved', owner='ai-triage', updated_at=?, evidence_json=json_set(evidence_json, '$.ai_triage', json(?))
                           WHERE status='open' AND json_extract(evidence_json, '$.package')=? AND json_extract(evidence_json, '$.version')=?""",
                           (now, note, row["package"], row["version"]))
        return "resolved"
    connection.execute("""UPDATE research_alerts SET updated_at=?, evidence_json=json_set(evidence_json, '$.ai_triage', json(?))
                       WHERE json_extract(evidence_json, '$.package')=? AND json_extract(evidence_json, '$.version')=?""", (now, note, row["package"], row["version"]))
    return "escalated"


NOISY_MIN_TRIAGED = 5
NOISY_BENIGN_SHARE = 0.8


def rule_health(*, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Per-rule model verdicts; raise a 'rule_noisy' alert for rules that mostly fire on benign code.

    Rules are never disabled automatically: a package author can influence
    the model's verdict, so turning a rule off stays an operator decision.
    """
    stats: Dict[str, Dict[str, Any]] = {}
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        rows = connection.execute("SELECT artifact_key, verdict, context_json FROM research_ai_triage WHERE status = 'triaged'").fetchall()
    for row in rows:
        context = json.loads(row["context_json"] or "{}")
        for rule in {str(item.get("rule_id") or "") for item in context.get("findings") or [] if item.get("rule_id")}:
            entry = stats.setdefault(rule, {"triaged": 0, "benign": 0, "examples": []})
            entry["triaged"] += 1
            if row["verdict"] in {"benign", "likely_benign"}:
                entry["benign"] += 1
                if len(entry["examples"]) < 5:
                    entry["examples"].append(row["artifact_key"])
    noisy = {rule: entry for rule, entry in stats.items()
             if entry["triaged"] >= NOISY_MIN_TRIAGED and entry["benign"] / entry["triaged"] >= NOISY_BENIGN_SHARE}
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        for rule, entry in noisy.items():
            evidence = {"rule": rule, **entry, "benign_share": round(entry["benign"] / entry["triaged"], 2),
                        "action": "Review the rule; tighten it or list it in rules/yara/disabled-rules.txt (YARA) or package_features.py (behaviour)."}
            connection.execute(
                """INSERT INTO research_alerts (alert_id, alert_type, severity, candidate_id, campaign_id, case_id, dedupe_key,
                       reason, evidence_json, status, owner, created_at, updated_at)
                   VALUES (?, 'rule_noisy', 'low', NULL, NULL, NULL, ?, ?, ?, 'open', '', ?, ?)
                   ON CONFLICT(dedupe_key) DO UPDATE SET evidence_json = excluded.evidence_json, reason = excluded.reason, updated_at = excluded.updated_at""",
                (f"RAL-{secrets.token_hex(8).upper()}", f"rule-noisy:{rule}",
                 f"Rule {rule}: {entry['benign']} of {entry['triaged']} triaged hits judged benign", json.dumps(evidence, sort_keys=True), now, now),
            )
        connection.commit()
    return {"rules": len(stats), "noisy": sorted(noisy)}


# Clef remains opt-in. Scores are observations until a reviewed evaluation
# approves the current evidence builder, model identity, and closure policy.
CLEF_CLOSE_MAX = 10
CLEF_PER_CYCLE = 50
DISAGREEMENT_GAP = 80


def clef_enabled() -> bool:
    return (os.environ.get("SECOPSAI_CLEF_PRESCREEN", "0").strip().lower() in {"1", "true", "yes", "on"} and bool(os.environ.get("CLOUDFLARE_ACCOUNT_ID"))
            and bool(os.environ.get("CLOUDFLARE_WORKERS_AI_TOKEN") or os.environ.get("CLOUDFLARE_AI_TOKEN") or os.environ.get("CLOUDFLARE_API_TOKEN")))


def clef_prescreen(*, db_path: Optional[str] = None, classify: Optional[Any] = None, limit: int = CLEF_PER_CYCLE) -> Dict[str, Any]:
    """Record Clef judgments; closure requires the shared calibrated policy."""
    from concurrent.futures import ThreadPoolExecutor

    from secopsai import clef_triage

    token = os.environ.get("CLOUDFLARE_WORKERS_AI_TOKEN") or os.environ.get("CLOUDFLARE_AI_TOKEN") or os.environ.get("CLOUDFLARE_API_TOKEN")
    run = classify or (lambda context: clef_triage.classify(context, api_token=token))
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        rows = [dict(row) for row in connection.execute(
            """SELECT artifact_key, package, version, context_json FROM research_ai_triage
               WHERE status = 'pending' AND json_extract(context_json, '$.clef') IS NULL ORDER BY score DESC, created_at LIMIT ?""",
            (limit,),
        ).fetchall()]
        connection.commit()

    def one(row: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return run(json.loads(row["context_json"] or "{}"))
        except Exception as exc:  # Clef unavailable: the hit simply goes to the chat model
            return {"error": type(exc).__name__}

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(one, rows))
    stats = {"scored": 0, "closed": 0, "to_chat": 0, "errors": 0, "tokens": 0}
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        for row, result in zip(rows, results):
            from secopsai.decision_contracts import DecisionError
            from secopsai.decision_policy import closure_decision
            try:
                clef_triage.validate_clef_result(result)
            except DecisionError:
                stats["errors"] += 1
                continue
            stats["scored"] += 1
            stats["tokens"] += int(result.get("input_tokens") or 0)
            from secopsai.decision_evidence import build_evidence
            original = json.loads(row["context_json"] or "{}")
            _, coverage = build_evidence(original)
            result = {**result, "malicious_probability": result["probability"], "finding_confidence": result["confidence"],
                      "evidence_coverage": coverage, "automatic_closure_eligible": coverage["complete"]}
            allowed, reason = closure_decision(result)
            clef = {**result, "at": now, "closure_eligible": allowed, "policy_reason": reason}
            context = {**original, "clef": clef}
            if context.get("evidence_truncated"):
                allowed = False
                clef.update(closure_eligible=False, policy_reason="incomplete_evidence")
            alert_note = json.dumps(clef)
            if allowed:
                stats["closed"] += 1
                connection.execute("UPDATE research_ai_triage SET status='triaged', verdict='likely_benign', confidence=?, context_json=?, updated_at=? WHERE artifact_key=?",
                                   (result["confidence"], json.dumps(context, sort_keys=True), now, row["artifact_key"]))
                connection.execute("""UPDATE research_alerts SET status='resolved', owner='clef', updated_at=?, evidence_json=json_set(evidence_json, '$.clef', json(?))
                                   WHERE status='open' AND json_extract(evidence_json, '$.package')=? AND json_extract(evidence_json, '$.version')=?""",
                                   (now, alert_note, row["package"], row["version"]))
            else:
                stats["to_chat"] += 1
                connection.execute("UPDATE research_ai_triage SET context_json=?, updated_at=? WHERE artifact_key=?", (json.dumps(context, sort_keys=True), now, row["artifact_key"]))
                connection.execute("""UPDATE research_alerts SET updated_at=?, evidence_json=json_set(evidence_json, '$.clef', json(?))
                                   WHERE json_extract(evidence_json, '$.package')=? AND json_extract(evidence_json, '$.version')=?""",
                                   (now, alert_note, row["package"], row["version"]))
        connection.commit()
    return stats


def sync(client: Any, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Pre-screen with Clef, queue the rest, apply finished verdicts.  Safe to call every cycle."""
    if not getattr(client, "enabled", False):
        return {"status": "disabled"}
    prescreen = clef_prescreen(db_path=db_path) if clef_enabled() else {"status": "disabled"}
    queued = _queue_pending(client, db_path)
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        row = connection.execute("SELECT value FROM core_sync_cursors WHERE name=?", (CURSOR_KEY,)).fetchone()
        connection.commit()
    since = str(row["value"]) if row else ""
    response = client.triage_results(since=since)
    results = response.get("results") or []
    outcomes = {"resolved": 0, "deprioritized": 0, "escalated": 0}
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        for item in results:
            outcome = _apply_result(connection, item, now)
            if outcome:
                outcomes[outcome] += 1
        if results:
            last = str(results[-1].get("updated_at") or since)
            connection.execute(
                "INSERT INTO core_sync_cursors (name, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (CURSOR_KEY, last, now),
            )
        connection.commit()
    health = rule_health(db_path=db_path)
    return {"status": "ok", "clef": prescreen, **queued, "results": len(results), "pending_at_bridge": response.get("pending"), **outcomes, "rule_health": health}


RETRIAGE_ECOSYSTEMS = {"npm", "pypi", "crates", "open-vsx", "vscode-marketplace"}


def _ensure_training(connection: Any) -> None:
    connection.execute(
        """CREATE TABLE IF NOT EXISTS rule_training_labels (
            artifact_key TEXT NOT NULL,
            source TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            features_json TEXT NOT NULL,
            rules_json TEXT NOT NULL,
            score INTEGER NOT NULL,
            label TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (artifact_key, source)
        )"""
    )


def retriage(*, db_path: Optional[str] = None, min_score: int = 80, limit: int = 60, before: str = "",
             scanner: Optional[Any] = None, workers: int = 8, budget_seconds: int = 300) -> Dict[str, Any]:
    """Re-scan inconclusive hits with the current rules and requeue the strong ones.

    Scanning runs on the worker (no model use). Outcomes:
    - no longer flagged: the alert is resolved as retired by a rule update;
    - flagged at ``min_score`` or more: requeued for model triage with the
      current evidence (install-time files, per-flag code and lines);
    - flagged below ``min_score``: context refreshed, not requeued.
    Every outcome is kept in ``rule_training_labels`` for the rule lab.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from secopsai.research_content_funnel import scan_release
    from secopsai.research_intake import SafeFetcher

    scan = scanner or scan_release
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        _ensure_training(connection)
        rows = [dict(row) for row in connection.execute(
            """SELECT artifact_key, ecosystem, package, version, context_json, verdict FROM research_ai_triage
               WHERE status IN ('triaged', 'failed') AND verdict IN ('inconclusive', '')
                 AND json_extract(context_json, '$.rescanned_at') IS NULL
                 AND (? = '' OR created_at < ?)
               ORDER BY score DESC, created_at LIMIT ?""",
            (before, before, limit),
        ).fetchall()]
        connection.commit()
    rows = [row for row in rows if row["ecosystem"] in RETRIAGE_ECOSYSTEMS]
    fetcher = SafeFetcher(timeout=30)
    stats = {"rescanned": 0, "retired": 0, "requeued": 0, "refreshed": 0, "unavailable": 0}
    started = time.monotonic()
    # Each result is written as soon as its scan finishes, so a run stopped by
    # its time budget keeps the progress it made instead of redoing it.
    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, 16)))
    futures = {pool.submit(scan, fetcher, row["ecosystem"], row["package"], row["version"]): row for row in rows}
    with closing(soc_store.connect(db_path)) as connection:
        for future in as_completed(futures):
            row = futures[future]
            try:
                result = future.result()
            except Exception as exc:  # one bad artifact must not stop the pass
                result = {"status": "error", "reason": str(exc)[:200]}
            now = soc_store.utc_now()
            stats["rescanned"] += 1
            old = json.loads(row["context_json"] or "{}")
            status = result.get("status")
            if status not in {"hit", "clean"}:
                stats["unavailable"] += 1
                connection.execute("UPDATE research_ai_triage SET context_json = ?, updated_at = ? WHERE artifact_key = ?",
                                   (json.dumps({**old, "rescanned_at": now, "rescan": status or "error"}, sort_keys=True), now, row["artifact_key"]))
                connection.commit()
                continue
            label = "retired" if status == "clean" else "pending_model"
            connection.execute(
                """INSERT INTO rule_training_labels (artifact_key, source, ecosystem, features_json, rules_json, score, label, created_at)
                   VALUES (?, 'retriage', ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(artifact_key, source) DO UPDATE SET features_json = excluded.features_json, rules_json = excluded.rules_json,
                   score = excluded.score, label = excluded.label, created_at = excluded.created_at""",
                (row["artifact_key"], row["ecosystem"], json.dumps(result.get("features") or []), json.dumps(result.get("rules_matched") or []),
                 int(result.get("score") or 0), label, now),
            )
            if status == "clean":
                stats["retired"] += 1
                connection.execute("UPDATE research_ai_triage SET status = 'retired', verdict = 'rule_retired', context_json = ?, updated_at = ? WHERE artifact_key = ?",
                                   (json.dumps({**old, "rescanned_at": now, "rescan": "clean"}, sort_keys=True), now, row["artifact_key"]))
                note = json.dumps({"verdict": "rule_retired", "summary": "No longer flagged by the current rules after a rule update."})
                connection.execute(
                    """UPDATE research_alerts SET status = 'resolved', owner = 'rule-update', updated_at = ?,
                          evidence_json = json_set(evidence_json, '$.ai_triage', json(?))
                       WHERE status = 'open' AND json_extract(evidence_json, '$.package') = ? AND json_extract(evidence_json, '$.version') = ?""",
                    (now, note, row["package"], row["version"]),
                )
                connection.commit()
                continue
            context = fit_context(build_context(ecosystem=row["ecosystem"], package=row["package"], version=row["version"], prescan=result,
                                                metadata_signals=old.get("metadata_signals") or [], previous_version=old.get("previous_version") or ""))
            context.update({"rescanned_at": now, "rescan": "hit", "revision": int(old.get("revision") or 0) + 1})
            requeue = int(result.get("score") or 0) >= min_score
            stats["requeued" if requeue else "refreshed"] += 1
            connection.execute(
                "UPDATE research_ai_triage SET status = ?, score = ?, context_json = ?, job_id = CASE WHEN ? THEN '' ELSE job_id END, updated_at = ? WHERE artifact_key = ?",
                ("pending" if requeue else "triaged", int(result.get("score") or 0), json.dumps(context, sort_keys=True), int(requeue), now, row["artifact_key"]),
            )
            connection.commit()
            if time.monotonic() - started > budget_seconds:
                for pending in futures:
                    pending.cancel()
                stats["stopped_on_budget"] = True
                break
    pool.shutdown(wait=False, cancel_futures=True)
    return stats
