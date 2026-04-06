from __future__ import annotations

from typing import Iterable


VALID_DISPOSITIONS = {
    "true_positive",
    "false_positive",
    "expected_behavior",
    "accepted_risk",
    "exception_granted",
    "needs_review",
    "tune_policy",
    "remediated",
}

VALID_STATUSES = {
    "open",
    "in_review",
    "triaged",
    "closed",
}


def validate_disposition(disposition: str) -> str:
    value = str(disposition or "").strip().lower()
    if value not in VALID_DISPOSITIONS:
        raise ValueError(
            f"Unsupported disposition '{disposition}'. Valid values: {', '.join(sorted(VALID_DISPOSITIONS))}"
        )
    return value


def validate_status(status: str, *, allowed: Iterable[str] | None = None) -> str:
    allowed_values = set(allowed or VALID_STATUSES)
    value = str(status or "").strip().lower()
    if value not in allowed_values:
        raise ValueError(
            f"Unsupported status '{status}'. Valid values: {', '.join(sorted(allowed_values))}"
        )
    return value


def require_closure_note(disposition: str, note: str) -> str:
    disposition = validate_disposition(disposition)
    clean_note = str(note or "").strip()
    if not clean_note:
        raise ValueError("A closure note is required.")
    if disposition in {"false_positive", "accepted_risk", "exception_granted", "tune_policy"} and len(clean_note) < 12:
        raise ValueError("Provide a more specific closure note explaining why this disposition is justified.")
    return clean_note
