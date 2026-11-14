"""Forward check of the takeover signals (frontier phase 2).

Offline benchmarks keep almost no registry metadata for compromised releases,
so the takeover score is judged going forward instead: every release the
stream scan flagged is matched against ossf/malicious-packages reports, and
every report for a release published while the stream was running is checked
for whether it had been flagged. A flag is judged only once it is old enough
for a report to have appeared (``settle_days``).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from secopsai import blocklist


def _parse(value: Any) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def reports(directories: Iterable[Path], since: datetime) -> Dict[str, Any]:
    """Blocklist of every report, plus the reports first published on or after ``since``."""
    blocks: Dict[str, Any] = {}
    recent: List[Dict[str, Any]] = []
    for directory in directories:
        for path in Path(directory).rglob("*.json"):
            try:
                record = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            blocklist.add_record(blocks, record)
            published = _parse(record.get("published"))
            if published and published >= since:
                for affected in record.get("affected") or []:
                    package = affected.get("package") or {}
                    ecosystem = blocklist.ECOSYSTEMS.get(str(package.get("ecosystem") or ""))
                    if ecosystem:
                        recent.append({"id": record.get("id"), "ecosystem": ecosystem, "package": str(package.get("name") or ""),
                                       "versions": [str(v) for v in affected.get("versions") or []], "published": record["published"]})
    return {"blocks": blocks, "recent": recent}


def evaluate(flagged: List[Dict[str, Any]], corpus: Dict[str, Any], *, stream_start: datetime, now: datetime,
             settle_days: int = 3) -> Dict[str, Any]:
    settled = [row for row in flagged if (_parse(row.get("published_at")) or now) <= now - timedelta(days=settle_days)]
    confirmed = [row for row in settled if blocklist.blocked(corpus["blocks"], row["ecosystem"], row["package"], row["version"])]
    flagged_keys = {(row["ecosystem"], blocklist.normalize(row["ecosystem"], row["package"]), row["version"]) for row in flagged}
    in_window = [report for report in corpus["recent"] if (_parse(report["published"]) or now) >= stream_start]
    caught = [report for report in in_window
              if any((report["ecosystem"], blocklist.normalize(report["ecosystem"], report["package"]), version) in flagged_keys
                     for version in report["versions"])]
    return {
        "generated_at": now.isoformat(), "stream_start": stream_start.isoformat(), "settle_days": settle_days,
        "flagged": len(flagged), "settled": len(settled), "confirmed": len(confirmed),
        "precision": round(len(confirmed) / len(settled), 4) if settled else None,
        "reports_in_window": len(in_window), "reports_flagged": len(caught),
        "recall": round(len(caught) / len(in_window), 4) if in_window else None,
        "confirmed_examples": confirmed[:20], "caught_examples": caught[:20],
    }
