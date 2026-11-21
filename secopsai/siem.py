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


def export_to_http_sink(events: Iterable[dict[str, Any]], *, endpoint: str, requester: Any, approved: bool = False) -> dict[str, Any]:
    """Send minimized events only through an explicitly configured sink."""
    if not endpoint or not endpoint.startswith("https://"):
        raise ValueError("SIEM export endpoints must use HTTPS")
    if not approved:
        return {"status": "proposed", "endpoint": endpoint, "events": len(list(events)), "network_called": False}
    body = export_normalized_events(events)
    response = requester(endpoint, {"Content-Type": "application/x-ndjson"}, body)
    return {"status": "sent", "endpoint": endpoint, "response": response, "network_called": True}


def _age_seconds(value: Any, now: float) -> float | None:
    from datetime import datetime

    text = str(value or "").strip()
    if not text:
        return None
    try:
        return max(0.0, now - datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def enterprise_metrics(store: Any, *, now: float | None = None) -> MetricsRegistry:
    """Metrics computed from the persistent enterprise store.

    A per-process registry is empty in a fresh CLI or API process, so the
    values here come from stored state: record counts, connector cursors, open
    vulnerabilities, recent events and penetration-test items.
    """
    current = time.time() if now is None else now
    registry = MetricsRegistry()
    counts = (store.summary(limit=1).get("counts") or {})
    for name in ("events", "assets", "vulnerabilities", "open_vulnerabilities", "controls", "evidence", "dead_letters", "actions"):
        registry.gauge(f"{name}_total", counts.get(name, 0))

    cursors = store.list_source_cursors(limit=500)
    registry.gauge("sources_total", len(cursors))
    registry.gauge("sources_degraded", sum(1 for cursor in cursors if cursor.get("status") != "healthy"))
    for cursor in cursors:
        source = str(cursor.get("source") or "unknown")
        age = _age_seconds(cursor.get("last_success_at"), current)
        if age is not None:
            registry.gauge(f"source_age_seconds_{source}", round(age, 1))
        metadata = cursor.get("metadata") if isinstance(cursor.get("metadata"), dict) else {}
        if isinstance(metadata.get("latency_ms"), (int, float)):
            registry.gauge(f"source_latency_ms_{source}", metadata["latency_ms"])

    inputs = store.metrics_inputs()
    overdue = 0
    for vulnerability in inputs["open_vulnerabilities"]:
        due_in = _age_seconds(vulnerability.get("sla_due_at"), current)
        # _age_seconds clamps at zero, so a positive value means the due date has passed.
        if due_in:
            overdue += 1
        registry.increment(f"open_vulnerabilities_{str(vulnerability.get('severity') or 'unknown').lower()}")
    registry.gauge("vulnerabilities_overdue", overdue)
    for event in inputs["recent_events"]:
        observed = _age_seconds(event.get("observed_at"), current)
        received = _age_seconds(event.get("received_at"), current)
        if observed is not None and received is not None:
            registry.observe("ingest_delay_seconds", max(0.0, observed - received))
    items = inputs["pentest_items"]
    registry.gauge("pentest_items_open", sum(1 for item in items if item.get("status") in {"open", "retest_failed"}))
    registry.gauge("pentest_items_awaiting_retest", sum(1 for item in items if item.get("status") == "fixed_pending_retest"))
    return registry
