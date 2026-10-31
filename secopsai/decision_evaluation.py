"""Offline evaluation of independently labelled, held-out decision records."""
from __future__ import annotations
import hashlib
import json
import math
from secopsai.decision_policy import POLICY_VERSION
from secopsai.decision_contracts import number


# A popular, aged release with no malicious-package advisory is not a reviewed
# label, so the report counts these and whoever approves the manifest sees them.
BENIGN_ONLY_LABEL_SOURCES = {"registry_vetted", "production_aged"}


def evaluation_passes(report: dict) -> bool:
    return (report.get("policy_version") == POLICY_VERSION and report.get("held_out") is True
            and isinstance(report.get("provider"), str) and bool(report["provider"])
            and isinstance(report.get("model_version"), str) and bool(report["model_version"])
            and len(str(report.get("corpus_sha256", ""))) == 64
            and report.get("malware_count", 0) >= 600 and report.get("benign_count", 0) >= 200
            and report.get("malware_closed") == 0 and 0 <= report.get("malware_closure_upper95", 1) <= .005
            and 0 <= report.get("benign_escalation_rate", 1) <= .15
            and report.get("invalid_closed") == 0 and report.get("incomplete_closed") == 0)


def evaluate_records(records: list[dict], *, held_out: bool = False) -> dict:
    # Records are actual captured outputs with independently reviewed labels.
    # No calls to providers and no mutations of alert state occur here.
    ids = [row["artifact_id"] for row in records]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate evaluation artifacts")
    for row in records:
        if row.get("decision") not in {"close", "review", "escalate"}:
            raise ValueError("unknown captured policy decision")
        allowed_sources = {"independent_review"} | (BENIGN_ONLY_LABEL_SOURCES if row.get("label") == "benign" else set())
        if row.get("label") not in {"malware", "benign", "ambiguous"} or row.get("label_source") not in allowed_sources:
            raise ValueError("evaluation requires independently reviewed labels")
        if row.get("partition") != "held_out" and held_out:
            raise ValueError("all samples must be held out")
        number(row.get("latency_ms", 0), 0, 1e12, "latency_ms")
        for key in ("retries", "input_tokens"):
            number(row.get(key, 0), 0, 1e12, key, integer=True)
    identities = {(row.get("provider"), row.get("model_version")) for row in records}
    if len(identities) != 1 or any(not isinstance(part, str) or not part for identity in identities for part in identity):
        raise ValueError("evaluate each provider/model or combined policy independently with an explicit identity")
    provider, model = next(iter(identities))
    malware = [r for r in records if r["label"] == "malware"]
    benign = [r for r in records if r["label"] == "benign"]
    closed = lambda r: r.get("decision") == "close"
    report = {"policy_version": POLICY_VERSION, "held_out": held_out, "provider": provider, "model_version": model,
              "corpus_sha256": hashlib.sha256(json.dumps(records, sort_keys=True, allow_nan=False).encode()).hexdigest(),
              "sample_count": len(records), "malware_count": len(malware), "benign_count": len(benign),
              "malware_closed": sum(closed(r) for r in malware),
              "invalid_closed": sum(closed(r) and r.get("valid") is not True for r in records),
              "incomplete_closed": sum(closed(r) and r.get("evidence_complete") is not True for r in records),
              "malware_closure_upper95": 1 - math.pow(.05, 1 / len(malware)) if malware and not any(closed(r) for r in malware) else 1,
              "benign_escalation_rate": sum(r.get("decision") == "escalate" for r in benign) / len(benign) if benign else 1,
              "benign_by_label_source": {source: {"escalated": sum(r["label_source"] == source and r.get("decision") == "escalate" for r in benign),
                                                  "closed": sum(r["label_source"] == source and closed(r) for r in benign)}
                                         for source in sorted({r["label_source"] for r in benign})},
              "benign_close_rate": sum(closed(r) for r in benign) / len(benign) if benign else 0,
              "benign_label_sources": {source: sum(r["label_source"] == source for r in benign) for source in sorted({r["label_source"] for r in benign})},
              "abstention_rate": sum(r.get("decision") == "review" for r in records) / len(records) if records else 0,
              "disagreement_rate": sum(r.get("models_disagree") is True for r in records) / len(records) if records else 0,
              "evidence_coverage_rate": sum(r.get("evidence_complete") is True for r in records) / len(records) if records else 0,
              "latency_ms_mean": sum(r.get("latency_ms", 0) for r in records) / len(records) if records else 0,
              "retries": sum(r.get("retries", 0) for r in records), "input_tokens": sum(r.get("input_tokens", 0) for r in records)}
    report["accepted"] = evaluation_passes(report)
    return report
