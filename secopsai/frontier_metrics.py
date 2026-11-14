"""Frontier programme metrics: benchmark recall (all and held-out) and live coverage.

Two questions decide whether SecOpsAI is at the frontier, and every phase of
the programme is judged on them against targets fixed in advance
(``eval/frontier/targets.json``):

* How much known malware does it catch? ``benchmark_scores`` turns Recall
  Benchmark rows into recall per ecosystem and category, on all samples and on
  the held-out samples discovered on or after the cutoff that rule selection
  never sees, plus the false-positive rate on popular clean packages.
* How much of the live registry stream does it look at, and how fast?
  ``live_coverage`` measures, per ecosystem, the share of newly published
  releases that reached a content verdict and the time from publish to verdict.
"""
from __future__ import annotations

import json
from collections import defaultdict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

HELD_OUT_CUTOFF = "2026-01-01"
LEVEL_RANK = {"none": 0, "notice": 1, "warning": 2, "alert": 3}
LEVELS = (("hit", 1), ("warning", 2), ("alert", 3))
# A release published in the last hour may simply not have been reached yet;
# coverage is judged on releases at least this old.
SETTLE_MINUTES = 60
SKIPPED_EVENT_TYPES = ("unknown", "delete", "unpublish", "deprecat")


def _rate(rows: List[Dict[str, Any]], rank: int) -> Optional[float]:
    scored = [row for row in rows if row.get("status") not in {"error", "skipped", "unavailable"} and "level" in row]
    if not scored:
        return None
    return round(sum(1 for row in scored if LEVEL_RANK.get(row.get("level"), 0) >= rank) / len(scored), 4)


def _block(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {"samples": len(rows), "errors": sum(1 for row in rows if row.get("status") == "error"),
            **{name: _rate(rows, rank) for name, rank in LEVELS}}


def benchmark_scores(rows: Iterable[Dict[str, Any]], *, cutoff: str = HELD_OUT_CUTOFF) -> Dict[str, Any]:
    """Recall per ecosystem and category (all and held-out) and clean false positives."""
    rows = list(rows)
    malicious = [row for row in rows if row.get("set") == "malicious"]
    clean = [row for row in rows if row.get("set") == "clean"]
    recall: Dict[str, Dict[str, Any]] = {}
    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in malicious:
        groups[f"{row.get('ecosystem')}/{row.get('category')}"].append(row)
        groups[f"{row.get('ecosystem')}/all"].append(row)
        # Each corpus is also reported on its own, so a new corpus never hides a change in another.
        groups[f"{row.get('ecosystem')}/{row.get('category')}@{row.get('corpus') or 'datadog'}"].append(row)
    groups["all/all"] = malicious
    for key, group in sorted(groups.items()):
        held = [row for row in group if str(row.get("discovered") or "") >= cutoff]
        recall[key] = {"all": _block(group), "held_out": _block(held)}
    false_positives = {}
    for ecosystem in sorted({row.get("ecosystem") for row in clean}):
        false_positives[ecosystem] = _block([row for row in clean if row.get("ecosystem") == ecosystem])
    return {"held_out_cutoff": cutoff, "recall": recall, "false_positive_rate": false_positives}


def _parse(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _percentile(values: List[float], fraction: float) -> Optional[float]:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return round(ordered[index], 1)


def live_coverage(*, db_path: Optional[str] = None, hours: int = 24, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Share of new releases that reached a content verdict, and publish-to-verdict minutes.

    A release counts as scanned when its archive was scanned to a verdict: a
    ``content_prescan`` of hit or clean on the feed event (PyPI, Open VSX,
    MCP and others), or an npm release analysis created after it was published.
    """
    import soc_store

    current = now or datetime.now(timezone.utc)
    start = current - timedelta(hours=hours)
    settled = current - timedelta(minutes=SETTLE_MINUTES)
    with closing(soc_store.connect(db_path)) as connection:
        events = connection.execute(
            """SELECT ecosystem, package, version, event_type, registry_timestamp, metadata_json
               FROM registry_feed_events WHERE registry_timestamp >= ? AND registry_timestamp < ?""",
            (start.strftime("%Y-%m-%dT%H:%M:%S"), settled.strftime("%Y-%m-%dT%H:%M:%S.999999Z")),
        ).fetchall()
        npm_seen: Dict[str, List[datetime]] = defaultdict(list)
        for row in connection.execute(
                "SELECT package, created_at FROM research_npm_release_analyses WHERE created_at >= ? AND status != 'error'",
                (start.strftime("%Y-%m-%dT%H:%M:%S"),)):
            stamp = _parse(row[1])
            if stamp:
                npm_seen[str(row[0])].append(stamp)
    per: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"published": 0, "scanned": 0, "latencies": []})
    for ecosystem, package, _version, event_type, registry_timestamp, metadata_json in events:
        if any(marker in str(event_type or "").lower() for marker in SKIPPED_EVENT_TYPES):
            continue
        published = _parse(registry_timestamp)
        if not published:
            continue
        bucket = per[str(ecosystem)]
        bucket["published"] += 1
        verdict_at: Optional[datetime] = None
        try:
            prescan = (json.loads(metadata_json or "{}") or {}).get("content_prescan") or {}
        except (TypeError, ValueError):
            prescan = {}
        if prescan.get("status") in {"hit", "clean"}:
            verdict_at = _parse(prescan.get("at"))
        elif ecosystem == "npm":
            later = [stamp for stamp in npm_seen.get(str(package), []) if stamp >= published]
            verdict_at = min(later) if later else None
        if verdict_at:
            bucket["scanned"] += 1
            bucket["latencies"].append(max(0.0, (verdict_at - published).total_seconds() / 60))
    report: Dict[str, Any] = {"window_hours": hours, "settle_minutes": SETTLE_MINUTES, "ecosystems": {}}
    total_published = total_scanned = 0
    all_latencies: List[float] = []
    for ecosystem, bucket in sorted(per.items()):
        total_published += bucket["published"]
        total_scanned += bucket["scanned"]
        all_latencies += bucket["latencies"]
        report["ecosystems"][ecosystem] = {
            "published": bucket["published"], "scanned": bucket["scanned"],
            "coverage": round(bucket["scanned"] / bucket["published"], 4) if bucket["published"] else None,
            "p50_minutes": _percentile(bucket["latencies"], 0.5), "p95_minutes": _percentile(bucket["latencies"], 0.95),
        }
    report["all"] = {"published": total_published, "scanned": total_scanned,
                     "coverage": round(total_scanned / total_published, 4) if total_published else None,
                     "p50_minutes": _percentile(all_latencies, 0.5), "p95_minutes": _percentile(all_latencies, 0.95)}
    return report


def _lookup(data: Dict[str, Any], path: str) -> Any:
    value: Any = data
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def evaluate_targets(targets: Dict[str, Any], measured: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Each pre-registered target with its measured value and pass/fail.

    ``measured`` holds ``benchmark`` (``benchmark_scores`` output) and ``live``
    (``live_coverage`` output). A missing measurement is ``not measured``,
    never a pass.
    """
    results = []
    for phase in targets.get("phases", []):
        for target in phase.get("targets", []):
            value = _lookup(measured, target["metric"])
            if value is None:
                outcome = "not measured"
            elif target["op"] == ">=":
                outcome = "pass" if value >= target["value"] else "fail"
            else:
                outcome = "pass" if value <= target["value"] else "fail"
            results.append({"phase": phase["id"], "name": target["name"], "metric": target["metric"], "op": target["op"],
                            "target": target["value"], "baseline": target.get("baseline"), "measured": value, "outcome": outcome})
    return results
