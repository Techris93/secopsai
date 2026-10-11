"""Model triage of rule hits through the operator's bridge.

The hosted worker cannot call a model itself: models are reached through the
operator's SecOpsAI bridge (opencodex, using their own subscription accounts).
Rule hits are queued in Core as ``triage_artifact`` jobs carrying only the
matched strings and bounded context windows; the bridge claims them, asks the
selected model and posts the verdict back; this module collects verdicts and
records them on the hit and on the matching proactive alert.

Benign verdicts at high confidence resolve the alert (as Nextron's triage
does for ~98% of hits); suspicious or inconclusive ones stay open for an
analyst.
"""

from __future__ import annotations

import json
import secrets
from contextlib import closing
from typing import Any, Dict, List, Optional

import soc_store

CURSOR_KEY = "core_ai_triage_results"
MAX_QUEUE_PER_CYCLE = 25
AUTO_RESOLVE_CONFIDENCE = 85
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
    return {
        "artifact_id": artifact_key(ecosystem, package, version),
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "previous_version": previous_version,
        "rule_score": int(prescan.get("score") or 0),
        "rule_level": prescan.get("level"),
        "findings": [
            {field: item.get(field) for field in ("rule_id", "severity", "score", "file_path", "file_role", "matched_indicator", "matched_patterns", "safe_context", "evidence", "rule_author", "rule_reference")}
            for item in (prescan.get("findings") or [])[:20]
        ],
        "metadata_signals": (metadata_signals or [])[:20],
        "manifest": prescan.get("manifest") or {},
        "actor_fingerprints": prescan.get("fingerprints") or {},
        # Full text of what runs at install/build time (bounded): lets the model
        # check a finding instead of asking an analyst to open the files.
        "install_time_files": (prescan.get("install_files") or [])[:6],
        "execution_performed": False,
        "note": "Package metadata is untrusted context: it may explain a match but is not proof of benign intent.",
    }


def record_hit(*, ecosystem: str, package: str, version: str, prescan: Dict[str, Any], metadata_signals: Optional[List[Dict[str, Any]]] = None, previous_version: str = "", db_path: Optional[str] = None) -> str:
    """Store a rule hit with its minimized evidence for later model triage."""
    key = artifact_key(ecosystem, package, version)
    context = build_context(ecosystem=ecosystem, package=package, version=version, prescan=prescan,
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
        context = json.loads(row["context_json"])
        revision = int(context.get("revision") or 0)
        # A re-triage is a new job: Core deduplicates on the idempotency key.
        suffix = f":r{revision}" if revision else ""
        jobs.append({"artifact_id": row["artifact_key"], "idempotency_key": f"runner-triage:{row['artifact_key']}{suffix}", "inputs": {"artifact_triage": context}})
    response = client.queue_triage_jobs(jobs)
    queued = {item.get("artifact_id"): item.get("job_id") for item in response.get("queued") or [] if item.get("job_id")}
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        for key, job_id in queued.items():
            connection.execute("UPDATE research_ai_triage SET status='queued', job_id=?, updated_at=? WHERE artifact_key=?", (str(job_id), now, key))
        connection.commit()
    return {"queued": len(queued)}


def _apply_result(connection: Any, item: Dict[str, Any], now: str) -> Optional[str]:
    key = str(item.get("artifact_id") or "")
    result = item.get("result") if isinstance(item.get("result"), dict) else {}
    if item.get("status") != "succeeded":
        connection.execute("UPDATE research_ai_triage SET status='failed', result_json=?, updated_at=? WHERE artifact_key=?", (json.dumps({"error": item.get("error_code")}), now, key))
        return None
    raw = str(result.get("finding_verdict") or result.get("artifact_verdict") or result.get("verdict_recommendation") or "").lower()
    verdict = VERDICTS.get(raw, raw if raw in {"benign", "likely_benign", "suspicious", "inconclusive"} else "inconclusive")
    try:
        confidence = max(0, min(int(result.get("finding_confidence") or result.get("artifact_confidence") or 0), 100))
    except (TypeError, ValueError):
        confidence = 0
    connection.execute(
        "UPDATE research_ai_triage SET status='triaged', verdict=?, confidence=?, result_json=?, updated_at=? WHERE artifact_key=?",
        (verdict, confidence, json.dumps(result, sort_keys=True)[:60000], now, key),
    )
    row = connection.execute("SELECT package, version FROM research_ai_triage WHERE artifact_key=?", (key,)).fetchone()
    if not row:
        return None
    note = json.dumps({"verdict": verdict, "confidence": confidence, "summary": str(result.get("summary") or "")[:500], "job_id": item.get("job_id")})
    if verdict in {"benign", "likely_benign"} and confidence >= AUTO_RESOLVE_CONFIDENCE:
        connection.execute(
            """UPDATE research_alerts SET status='resolved', owner='ai-triage', updated_at=?,
                  evidence_json=json_set(evidence_json, '$.ai_triage', json(?))
               WHERE status='open' AND json_extract(evidence_json, '$.package')=? AND json_extract(evidence_json, '$.version')=?""",
            (now, note, row["package"], row["version"]),
        )
        return "resolved"
    connection.execute(
        """UPDATE research_alerts SET updated_at=?, evidence_json=json_set(evidence_json, '$.ai_triage', json(?))
           WHERE json_extract(evidence_json, '$.package')=? AND json_extract(evidence_json, '$.version')=?""",
        (now, note, row["package"], row["version"]),
    )
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


def sync(client: Any, *, db_path: Optional[str] = None) -> Dict[str, Any]:
    """Queue pending hits and apply finished verdicts.  Safe to call every cycle."""
    if not getattr(client, "enabled", False):
        return {"status": "disabled"}
    queued = _queue_pending(client, db_path)
    with closing(soc_store.connect(db_path)) as connection:
        _ensure(connection)
        row = connection.execute("SELECT value FROM core_sync_cursors WHERE name=?", (CURSOR_KEY,)).fetchone()
        connection.commit()
    since = str(row["value"]) if row else ""
    response = client.triage_results(since=since)
    results = response.get("results") or []
    outcomes = {"resolved": 0, "escalated": 0}
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
    return {"status": "ok", **queued, "results": len(results), "pending_at_bridge": response.get("pending"), **outcomes, "rule_health": health}


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


def retriage(*, db_path: Optional[str] = None, min_score: int = 80, limit: int = 300,
             scanner: Optional[Any] = None, workers: int = 8) -> Dict[str, Any]:
    """Re-scan inconclusive hits with the current rules and requeue the strong ones.

    Scanning runs on the worker (no model use). Outcomes:
    - no longer flagged: the alert is resolved as retired by a rule update;
    - flagged at ``min_score`` or more: requeued for model triage with the
      current evidence (install-time files, per-flag code and lines);
    - flagged below ``min_score``: context refreshed, not requeued.
    Every outcome is kept in ``rule_training_labels`` for the rule lab.
    """
    from concurrent.futures import ThreadPoolExecutor

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
               ORDER BY score DESC, created_at LIMIT ?""",
            (limit,),
        ).fetchall()]
        connection.commit()
    rows = [row for row in rows if row["ecosystem"] in RETRIAGE_ECOSYSTEMS]
    fetcher = SafeFetcher(timeout=30)
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 16))) as pool:
        results = list(pool.map(lambda row: scan(fetcher, row["ecosystem"], row["package"], row["version"]), rows))
    stats = {"rescanned": len(rows), "retired": 0, "requeued": 0, "refreshed": 0, "unavailable": 0}
    now = soc_store.utc_now()
    with closing(soc_store.connect(db_path)) as connection:
        for row, result in zip(rows, results):
            old = json.loads(row["context_json"] or "{}")
            status = result.get("status")
            if status not in {"hit", "clean"}:
                stats["unavailable"] += 1
                connection.execute("UPDATE research_ai_triage SET context_json = ?, updated_at = ? WHERE artifact_key = ?",
                                   (json.dumps({**old, "rescanned_at": now, "rescan": status or "error"}, sort_keys=True), now, row["artifact_key"]))
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
                continue
            context = build_context(ecosystem=row["ecosystem"], package=row["package"], version=row["version"], prescan=result,
                                    metadata_signals=old.get("metadata_signals") or [], previous_version=old.get("previous_version") or "")
            context.update({"rescanned_at": now, "rescan": "hit", "revision": int(old.get("revision") or 0) + 1})
            requeue = int(result.get("score") or 0) >= min_score
            stats["requeued" if requeue else "refreshed"] += 1
            connection.execute(
                "UPDATE research_ai_triage SET status = ?, score = ?, context_json = ?, job_id = CASE WHEN ? THEN '' ELSE job_id END, updated_at = ? WHERE artifact_key = ?",
                ("pending" if requeue else "triaged", int(result.get("score") or 0), json.dumps(context, sort_keys=True), int(requeue), now, row["artifact_key"]),
            )
        connection.commit()
    return stats
