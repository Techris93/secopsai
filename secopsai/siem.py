"""Privacy-preserving SIEM-style metrics and normalized event exports."""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from typing import Any, Iterable


class MetricsRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, float] = defaultdict(float)
        self._gauges: dict[str, float] = defaultdict(float)
        self._histograms: dict[str, list[float]] = defaultdict(list)

    def increment(self, name: str, value: float = 1.0) -> None:
        with self._lock:
            self._counters[str(name)] += float(value)

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[str(name)] = float(value)

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            values = self._histograms[str(name)]
            values.append(float(value))
            del values[:-1_000]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "counters": dict(self._counters),
                "gauges": dict(self._gauges),
                "histograms": {name: {"count": len(values), "sum": sum(values), "max": max(values) if values else 0.0} for name, values in self._histograms.items()},
                "generated_at": time.time(),
            }

    def prometheus(self) -> str:
        snapshot = self.snapshot()
        lines: list[str] = []
        for name, value in snapshot["counters"].items():
            lines.append(f"secopsai_{_metric_name(name)} {value}")
        for name, value in snapshot["gauges"].items():
            lines.append(f"secopsai_{_metric_name(name)} {value}")
        for name, values in snapshot["histograms"].items():
            metric = _metric_name(name)
            lines.append(f"secopsai_{metric}_count {values['count']}")
            lines.append(f"secopsai_{metric}_sum {values['sum']}")
            lines.append(f"secopsai_{metric}_max {values['max']}")
        return "\n".join(lines) + ("\n" if lines else "")


def _metric_name(value: str) -> str:
    return "".join(char if char.isalnum() else "_" for char in value.lower()).strip("_") or "metric"


def source_health_record(source: str, *, status: str, latency_ms: float = 0.0, cursor: str = "", error: str = "") -> dict[str, Any]:
    return {"source": str(source)[:160], "status": str(status)[:40], "latency_ms": round(max(0.0, float(latency_ms)), 2), "cursor": str(cursor)[:400], "error": str(error)[:1000], "checked_at": time.time()}


def export_normalized_events(events: Iterable[dict[str, Any]]) -> str:
    """Produce newline-delimited JSON safe for SIEM export."""
    lines = []
    for event in events:
        item = dict(event)
        item.pop("payload_json", None)
        item["payload"] = item.get("payload") or {}
        lines.append(json.dumps(item, sort_keys=True, ensure_ascii=True))
    return "\n".join(lines) + ("\n" if lines else "")
