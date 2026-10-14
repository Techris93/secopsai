"""Evidence-backed research usefulness and effort metrics; absent observations are unknown."""
from __future__ import annotations

import math

from secopsai.research_assurance import person
from secopsai.research_operation_store import append, records, text, timestamp, read_connection

OUTCOMES = {"independent_reproduction", "maintainer_acknowledgement", "citation", "detection_validation", "patch_verified", "correction", "missed_issue", "false_alarm", "effort"}


def record_outcome(case_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    from secopsai.research_cases import get_case
    person(actor, role="researcher", db_path=db_path)
    case = get_case(case_id, db_path=db_path)
    kind = payload.get("outcome")
    if kind not in OUTCOMES:
        raise ValueError("invalid research outcome")
    value = {"outcome": kind, "reference": text(payload.get("reference"), "evidence of outcome"),
             "occurred_at": timestamp(payload.get("occurred_at", "")), "rationale": text(payload.get("rationale"), "outcome rationale")}
    if kind == "independent_reproduction":
        reviewer = payload.get("researcher_id", "")
        person(reviewer, role="researcher", db_path=db_path)
        if reviewer == case.get("owner"):
            raise ValueError("independent reproduction requires a different qualified researcher")
        value["researcher_id"] = reviewer
    if kind in {"detection_validation", "patch_verified"}:
        experiment_id = payload.get("experiment_id")
        experiments = records("experiment", case_id=case_id, db_path=db_path)
        experiment = next((r for r in experiments if r["record_id"] == experiment_id), None)
        if not experiment or experiment["payload"]["mode"] not in {"detection_test", "patch_verification"}:
            raise ValueError("validated defenses require a recorded test experiment")
        value["experiment_id"] = experiment_id
    if kind == "effort":
        for field in ("researcher_hours", "cost"):
            number = payload.get(field)
            if isinstance(number, bool) or not isinstance(number, (int, float)) or not math.isfinite(number) or number < 0:
                raise ValueError("effort and cost must be finite nonnegative measurements")
            value[field] = number
        value["currency"] = text(payload.get("currency"), "currency", limit=3).upper()
    return append("research_outcome", value, actor=actor, case_id=case_id, db_path=db_path)


def metrics_report(*, db_path=None) -> dict:
    with read_connection(db_path) as conn:
        case_ids = [r[0] for r in conn.execute("SELECT DISTINCT case_id FROM research_operation_records WHERE kind IN ('research_outcome','human_review')")]
    counts = dict.fromkeys(OUTCOMES - {"effort"}, 0)
    hours, costs, accepted, baseline = 0.0, {}, set(), None
    for case_id in case_ids:
        for record in records("research_outcome", case_id=case_id, db_path=db_path, limit=10000):
            baseline = min(baseline or record["created_at"], record["created_at"])
            value = record["payload"]
            if value["outcome"] == "effort":
                hours += value["researcher_hours"]
                currency = value["currency"]
                costs[currency] = costs.get(currency, 0) + value["cost"]
            else:
                counts[value["outcome"]] += 1
        reviews = records("human_review", case_id=case_id, db_path=db_path)
        if any(r["payload"]["role"] == "editor" and r["payload"]["decision"] == "approved" for r in reviews):
            accepted.add(case_id)
    return {"baseline_started_at": baseline, "observed_outcomes": counts, "researcher_hours": hours,
            "recorded_cost_by_currency": costs, "historically_accepted_cases": len(accepted),
            "cost_per_historically_accepted_case": {c: v / len(accepted) if accepted else None for c, v in costs.items()},
            "false_alarm_rate": None, "miss_rate": None,
            "rate_limitation": "Outcome counts lack independently labeled universe denominators; counts cannot establish accuracy or reputation."}
