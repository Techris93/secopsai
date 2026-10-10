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


def record_hit(*, ecosystem: str, package: str, version: str, prescan: Dict[str, Any], metadata_signals: Optional[List[Dict[str, Any]]] = None, previous_version: str = "", db_path: Optional[str] = None) -> str:
    """Store a rule hit with its minimized evidence for later model triage."""
    key = artifact_key(ecosystem, package, version)
    context = {
        "artifact_id": key,
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "previous_version": previous_version,
        "rule_score": int(prescan.get("score") or 0),
        "rule_level": prescan.get("level"),
        "findings": [
            {field: item.get(field) for field in ("rule_id", "severity", "score", "file_path", "file_role", "matched_indicator", "matched_patterns", "safe_context", "rule_author", "rule_reference")}
            for item in (prescan.get("findings") or [])[:20]
        ],
        "metadata_signals": (metadata_signals or [])[:20],
        "manifest": prescan.get("manifest") or {},
        "execution_performed": False,
        "note": "Package metadata is untrusted context: it may explain a match but is not proof of benign intent.",
    }
    now = soc_store.utc_now()
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
    jobs = [{"artifact_id": row["artifact_key"], "idempotency_key": f"runner-triage:{row['artifact_key']}", "inputs": {"artifact_triage": json.loads(row["context_json"])}} for row in rows]
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
    return {"status": "ok", **queued, "results": len(results), "pending_at_bridge": response.get("pending"), **outcomes}
