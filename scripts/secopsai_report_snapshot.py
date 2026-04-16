#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
import subprocess
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


def _safe_json_load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _git(repo: Path, *args: str) -> str:
    cmd = ["git", "-C", str(repo), *args]
    try:
        proc = subprocess.run(cmd, check=True, capture_output=True, text=True)
        return proc.stdout.strip()
    except Exception:
        return ""


def _git_count_since(repo: Path, since_dt: datetime) -> int:
    since = since_dt.isoformat()
    out = _git(repo, "rev-list", "--count", f"--since={since}", "HEAD")
    try:
        return int(out)
    except Exception:
        return 0


def _git_metrics(repo: Path) -> Dict[str, Any]:
    local_now = datetime.now().astimezone()
    local_midnight = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    since_24h = local_now - timedelta(hours=24)

    status_porcelain = _git(repo, "status", "--porcelain")
    tracked = 0
    untracked = 0
    for line in status_porcelain.splitlines():
        if not line.strip():
            continue
        if line.startswith("??"):
            untracked += 1
        else:
            tracked += 1

    last_commit_sha = _git(repo, "log", "-1", "--pretty=format:%H")
    last_commit_subject = _git(repo, "log", "-1", "--pretty=format:%s")
    last_commit_iso = _git(repo, "log", "-1", "--pretty=format:%cI")

    return {
        "path": str(repo),
        "branch": _git(repo, "rev-parse", "--abbrev-ref", "HEAD") or None,
        "last_commit": {
            "sha": last_commit_sha or None,
            "subject": last_commit_subject or None,
            "committed_at": last_commit_iso or None,
        },
        "commit_counts": {
            "since_local_midnight": _git_count_since(repo, local_midnight),
            "last_24h": _git_count_since(repo, since_24h),
        },
        "worktree": {
            "dirty": bool(status_porcelain.strip()),
            "tracked_changes": tracked,
            "untracked_changes": untracked,
            "total_changes": tracked + untracked,
        },
    }


def _counter_dict(counter: Counter, limit: int = 10) -> Dict[str, int]:
    items = counter.most_common(limit)
    return {k: int(v) for k, v in items}


def _intel_metrics(repo: Path, now_utc: datetime) -> Dict[str, Any]:
    iocs_path = repo / "data" / "intel" / "iocs.json"
    out: Dict[str, Any] = {
        "path": str(iocs_path),
        "exists": iocs_path.exists(),
    }
    if not iocs_path.exists():
        out["error"] = "missing_iocs_json"
        return out

    payload = _safe_json_load(iocs_path)
    if not isinstance(payload, dict):
        out["error"] = "invalid_iocs_json"
        return out

    iocs = payload.get("iocs") or []
    if not isinstance(iocs, list):
        iocs = []

    generated_at = _parse_dt(payload.get("generated_at"))
    src = Counter()
    typ = Counter()
    tags = Counter()
    for ioc in iocs:
        if not isinstance(ioc, dict):
            continue
        src[str(ioc.get("source") or "unknown")] += 1
        typ[str(ioc.get("ioc_type") or "unknown")] += 1
        for tag in ioc.get("tags") or []:
            tags[str(tag)] += 1

    out.update(
        {
            "generated_at": _iso(generated_at),
            "age_hours": round((now_utc - generated_at).total_seconds() / 3600.0, 2) if generated_at else None,
            "total_iocs": len(iocs),
            "source_counts": _counter_dict(src, 10),
            "ioc_type_counts": _counter_dict(typ, 10),
            "top_tags": _counter_dict(tags, 10),
        }
    )
    return out


def _replay_metrics(path: Path, now_utc: datetime) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
    }
    if not path.exists():
        out["error"] = "missing_replay_file"
        return out

    payload = _safe_json_load(path)
    if not isinstance(payload, list):
        out["error"] = "invalid_replay_json"
        return out

    status = Counter()
    event_type = Counter()
    timestamps: list[datetime] = []

    for event in payload:
        if not isinstance(event, dict):
            continue
        status[str(event.get("status") or "unknown").lower()] += 1
        event_type[str(event.get("event_type") or "unknown").lower()] += 1
        ts = _parse_dt(event.get("timestamp") or event.get("ts"))
        if ts:
            timestamps.append(ts)

    latest_ts = max(timestamps) if timestamps else None

    out.update(
        {
            "total_events": len(payload),
            "status_counts": _counter_dict(status, 20),
            "event_type_counts": _counter_dict(event_type, 20),
            "latest_event_ts": _iso(latest_ts),
            "age_hours_since_latest_event": round((now_utc - latest_ts).total_seconds() / 3600.0, 2) if latest_ts else None,
        }
    )
    return out


def _latest_openclaw_bundle(repo: Path, now_utc: datetime) -> Dict[str, Any]:
    findings_dir = repo / "data" / "openclaw" / "findings"
    bundles = sorted(findings_dir.glob("openclaw-findings-*.json"), key=lambda p: p.stat().st_mtime)
    out: Dict[str, Any] = {
        "findings_dir": str(findings_dir),
        "latest_bundle_path": str(bundles[-1]) if bundles else None,
    }
    if not bundles:
        out["error"] = "no_openclaw_findings_bundle"
        return out

    path = bundles[-1]
    payload = _safe_json_load(path)
    if not isinstance(payload, dict):
        out["error"] = "invalid_openclaw_findings_bundle"
        return out

    generated_at = _parse_dt(payload.get("generated_at"))
    out.update(
        {
            "generated_at": _iso(generated_at),
            "age_hours": round((now_utc - generated_at).total_seconds() / 3600.0, 2) if generated_at else None,
            "total_events": int(payload.get("total_events") or 0),
            "total_detections": int(payload.get("total_detections") or 0),
            "total_candidate_findings": int(payload.get("total_candidate_findings") or 0),
            "total_findings": int(payload.get("total_findings") or 0),
        }
    )
    return out


def _soc_store_metrics(repo: Path) -> Dict[str, Any]:
    db_path = repo / "data" / "openclaw" / "findings" / "openclaw_soc.db"
    out: Dict[str, Any] = {
        "db_path": str(db_path),
        "exists": db_path.exists(),
    }
    if not db_path.exists():
        out["error"] = "missing_soc_store_db"
        return out

    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            total = conn.execute("SELECT COUNT(*) AS c FROM findings").fetchone()["c"]
            open_total = conn.execute(
                "SELECT COUNT(*) AS c FROM findings WHERE lower(status) IN ('open','in_review')"
            ).fetchone()["c"]
            last_seen = conn.execute("SELECT MAX(last_seen) AS v FROM findings").fetchone()["v"]

            status_rows = conn.execute(
                "SELECT lower(status) AS status, COUNT(*) AS c FROM findings GROUP BY lower(status)"
            ).fetchall()
            severity_rows = conn.execute(
                "SELECT lower(severity) AS severity, COUNT(*) AS c FROM findings GROUP BY lower(severity)"
            ).fetchall()
            open_sev_rows = conn.execute(
                "SELECT lower(severity) AS severity, COUNT(*) AS c FROM findings WHERE lower(status) IN ('open','in_review') GROUP BY lower(severity)"
            ).fetchall()
            source_rows = conn.execute(
                "SELECT source, COUNT(*) AS c FROM findings GROUP BY source ORDER BY c DESC"
            ).fetchall()

            top_open_rows = conn.execute(
                """
                SELECT finding_id, severity, status, title, first_seen, last_seen
                FROM findings
                WHERE lower(status) IN ('open','in_review')
                ORDER BY severity_score DESC, first_seen ASC
                LIMIT 15
                """
            ).fetchall()

        out.update(
            {
                "total_findings": int(total),
                "open_or_in_review": int(open_total),
                "status_counts": {str(r["status"]): int(r["c"]) for r in status_rows},
                "severity_counts": {str(r["severity"]): int(r["c"]) for r in severity_rows},
                "open_severity_counts": {str(r["severity"]): int(r["c"]) for r in open_sev_rows},
                "source_counts": {str(r["source"]): int(r["c"]) for r in source_rows},
                "latest_last_seen": str(last_seen) if last_seen else None,
                "top_open_findings": [dict(r) for r in top_open_rows],
            }
        )
    except Exception as exc:
        out["error"] = f"soc_store_query_failed: {exc}"

    return out


def _adaptive_metrics(workspace_logs: Path, now_utc: datetime) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "logs_dir": str(workspace_logs),
        "exists": workspace_logs.exists(),
    }
    if not workspace_logs.exists():
        out["error"] = "missing_workspace_logs"
        return out

    results_path = workspace_logs / "adaptive_results.json"
    if results_path.exists():
        payload = _safe_json_load(results_path)
        if isinstance(payload, dict):
            started = _parse_dt(payload.get("started_at"))
            ended = _parse_dt(payload.get("ended_at"))
            baseline = payload.get("f1_baseline")
            new = payload.get("f1_new")
            improvement = None
            if isinstance(baseline, (int, float)) and isinstance(new, (int, float)):
                improvement = float(new) - float(baseline)

            out["latest_results"] = {
                "path": str(results_path),
                "started_at": _iso(started),
                "ended_at": _iso(ended),
                "age_hours_since_end": round((now_utc - ended).total_seconds() / 3600.0, 2) if ended else None,
                "indicators_fetched": int(payload.get("indicators_fetched") or 0),
                "rules_generated": int(payload.get("rules_generated") or 0),
                "f1_baseline": float(baseline) if isinstance(baseline, (int, float)) else None,
                "f1_new": float(new) if isinstance(new, (int, float)) else None,
                "f1_improvement": improvement,
                "deployed": bool(payload.get("deployed")),
                "errors": payload.get("errors") if isinstance(payload.get("errors"), list) else [],
            }

    pipeline_logs = sorted(workspace_logs.glob("adaptive_intel_*.log"), key=lambda p: p.stat().st_mtime)
    if pipeline_logs:
        latest = pipeline_logs[-1]
        out["latest_pipeline_log"] = {
            "path": str(latest),
            "modified_at": _iso(datetime.fromtimestamp(latest.stat().st_mtime, tz=timezone.utc)),
            "age_hours": round((now_utc - datetime.fromtimestamp(latest.stat().st_mtime, tz=timezone.utc)).total_seconds() / 3600.0, 2),
        }

    return out


def _correlation_metrics(repo: Path) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        import sys

        sys.path.insert(0, str(repo))
        import soc_store  # type: ignore
        from correlation import run_correlation  # type: ignore

        findings = soc_store.list_findings()
        results = run_correlation(findings, time_window_minutes=60)
        out = {
            "total_correlations": int(results.get("total_correlations") or 0),
            "cross_platform_ip": len(results.get("cross_platform_ip") or []),
            "cross_platform_user": len(results.get("cross_platform_user") or []),
            "time_cluster": len(results.get("time_cluster") or []),
            "cross_platform_file": len(results.get("cross_platform_file") or []),
        }
    except Exception as exc:
        out = {"error": f"correlation_failed: {exc}"}
    return out


def build_snapshot(repo: Path, workspace_logs: Path) -> Dict[str, Any]:
    now_utc = _now_utc()
    replay_labeled = repo / "data" / "openclaw" / "replay" / "labeled" / "current.json"
    replay_unlabeled = repo / "data" / "openclaw" / "replay" / "unlabeled" / "current.json"

    snapshot: Dict[str, Any] = {
        "generated_at": _iso(now_utc),
        "repo": _git_metrics(repo),
        "intel": _intel_metrics(repo, now_utc),
        "telemetry": {
            "labeled_replay": _replay_metrics(replay_labeled, now_utc),
            "unlabeled_replay": _replay_metrics(replay_unlabeled, now_utc),
            "openclaw_latest_bundle": _latest_openclaw_bundle(repo, now_utc),
        },
        "findings": {
            "soc_store": _soc_store_metrics(repo),
        },
        "adaptive_intel": _adaptive_metrics(workspace_logs, now_utc),
        "correlation": _correlation_metrics(repo),
    }

    stale_flags: list[str] = []
    intel_age = snapshot.get("intel", {}).get("age_hours")
    if isinstance(intel_age, (int, float)) and intel_age > 24:
        stale_flags.append("intel_older_than_24h")

    replay_age = snapshot.get("telemetry", {}).get("labeled_replay", {}).get("age_hours_since_latest_event")
    if isinstance(replay_age, (int, float)) and replay_age > 24:
        stale_flags.append("telemetry_older_than_24h")

    adaptive_age = (
        snapshot.get("adaptive_intel", {})
        .get("latest_results", {})
        .get("age_hours_since_end")
    )
    if isinstance(adaptive_age, (int, float)) and adaptive_age > 24:
        stale_flags.append("adaptive_intel_older_than_24h")

    snapshot["staleness_flags"] = stale_flags
    return snapshot


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build canonical SecOpsAI reporting snapshot")
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[1]), help="SecOpsAI repository root")
    parser.add_argument(
        "--workspace-logs",
        default=str(Path.home() / ".openclaw" / "workspace" / "logs"),
        help="Workspace logs directory for adaptive-intel outputs",
    )
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo = Path(args.repo).expanduser().resolve()
    workspace_logs = Path(args.workspace_logs).expanduser().resolve()

    snapshot = build_snapshot(repo, workspace_logs)
    if args.compact:
        print(json.dumps(snapshot, separators=(",", ":"), sort_keys=True))
    else:
        print(json.dumps(snapshot, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
