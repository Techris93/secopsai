"""Authorized sample intake, disclosure milestones and accountable operational requirements."""
from __future__ import annotations

from secopsai.research_assurance import person
from secopsai.research_operation_store import append, records, text, timestamp

TLP = {"RED", "AMBER", "AMBER+STRICT", "GREEN", "CLEAR"}


def submit_sample(case_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    from secopsai.research_artifacts import attach_to_case, import_artifact
    from secopsai.research_cases import get_case

    person(actor, role="researcher", db_path=db_path)
    get_case(case_id, db_path=db_path)
    sharing = payload.get("tlp")
    if sharing not in TLP:
        raise ValueError("explicit TLP sharing instructions are required")
    consent = payload.get("consent")
    if not isinstance(consent, dict) or consent.get("authorized_to_share") is not True or consent.get("research_use") is not True:
        raise ValueError("submitter must have authority to share the sample for research")
    if type(consent.get("public_release")) is not bool:
        raise ValueError("public-release permission must be explicit; TLP is not a license")
    agreement = text(payload.get("agreement_reference"), "sharing agreement reference", limit=4000)
    submitter = text(payload.get("submitter"), "submitter", limit=240)
    scope = text(payload.get("authorized_scope"), "authorized research scope")
    license_note = text(payload.get("license"), "sample license")
    artifact = import_artifact(text(payload.get("path"), "local sample path", limit=4000), ecosystem=payload.get("ecosystem", ""),
                               package_name=payload.get("package", ""), version=payload.get("version", ""),
                               provenance={"source": "authorized partner submission", "origin": "partner_submission", "submitter": submitter, "agreement_reference": agreement,
                                           "authorized_scope": scope, "tlp": sharing, "consent": consent, "license": license_note}, db_path=db_path)
    attach_to_case(case_id, artifact["artifact_id"], actor=actor, db_path=db_path)
    return append("partner_submission", {"artifact_id": artifact["artifact_id"], "sha256": artifact["sha256"], "submitter": submitter,
                                          "agreement_reference": agreement, "authorized_scope": scope, "tlp": sharing,
                                          "consent": consent, "license": license_note}, actor=actor, case_id=case_id, db_path=db_path)


def disclosure_milestone(case_id: str, payload: dict, *, actor: str, db_path=None) -> dict:
    from secopsai.research_cases import get_case
    person(actor, role="researcher", db_path=db_path)
    get_case(case_id, db_path=db_path)
    kind = payload.get("milestone")
    if kind not in {"contact_prepared", "contact_sent", "acknowledged", "status_update", "extension", "active_exploitation_exception", "multiparty_coordination", "patch_available", "patch_verified", "disclosed", "closed"}:
        raise ValueError("invalid disclosure milestone")
    value = {"milestone": kind, "occurred_at": timestamp(payload.get("occurred_at", "")),
             "recipient": text(payload.get("recipient"), "recipient", limit=500), "reference": text(payload.get("reference"), "evidence/reference"),
             "rationale": text(payload.get("rationale"), "rationale"), "next_action": text(payload.get("next_action"), "next action"),
             "due_at": timestamp(payload["due_at"]) if payload.get("due_at") else None}
    if kind in {"extension", "active_exploitation_exception", "disclosed"}:
        person(payload.get("approved_by", ""), role="editor", db_path=db_path)
        value["approved_by"] = payload["approved_by"]
    # Recording a milestone does not send a message, change an embargo, or
    # publish a technical disclosure. Those remain existing protected actions.
    return append("disclosure_milestone", value, actor=actor, case_id=case_id, db_path=db_path)


def operational_requirement(payload: dict, *, actor: str, db_path=None) -> dict:
    person(actor, role="operator", db_path=db_path)
    kind = payload.get("kind")
    if kind not in {"legal_signoff", "partner_agreement", "research_sensor_authorization", "commercial_conflict", "research_quality_evaluation", "solo_operation"}:
        raise ValueError("unsupported operational requirement")
    status = payload.get("status")
    if status not in {"accepted", "pending", "revoked"}:
        raise ValueError("invalid requirement status")
    value = {"status": status, "responsible_person": text(payload.get("responsible_person"), "real responsible person", limit=240),
             "scope": text(payload.get("scope"), "scope"), "reference": text(payload.get("reference"), "supporting agreement or report reference"),
             "recorded_at": timestamp(payload.get("recorded_at", "")), "expires_at": timestamp(payload["expires_at"]) if payload.get("expires_at") else None,
             "limitations": text(payload.get("limitations"), "limitations")}
    if kind == "solo_operation":
        # One accountable human runs the desk: they hold the author, editor
        # and backup duties.  Drafts come from the automated desk, so the
        # editor is still distinct from the author of what they release.
        solo = text(payload.get("operator_id"), "solo operator", limit=160)
        for role in ("author", "editor", "technical_reviewer"):
            person(solo, role=role, db_path=db_path)
        value["operator_id"] = solo
    if kind == "research_quality_evaluation":
        metrics = payload.get("metrics")
        if not isinstance(metrics, dict) or not all(k in metrics for k in ("corpus_sha256", "independent_labels", "held_out", "malicious_false_closures", "false_escalations", "abstention_rate", "disagreement_rate", "evidence_coverage", "latency", "cost", "acceptance_criteria", "uncertainty")):
            raise ValueError("quality evaluation requires a fixed, independently labeled held-out corpus and all policy metrics")
        if metrics["independent_labels"] is not True or metrics["held_out"] is not True:
            raise ValueError("evaluation labels and test split must be independent")
        value["metrics"] = metrics
    return append(kind, value, actor=actor, db_path=db_path)


def solo_operator(*, db_path=None) -> str:
    """The accepted solo operator's identity, or "" when the desk is staffed."""
    if not accepted_requirement("solo_operation", db_path=db_path):
        return ""
    return str(records("solo_operation", db_path=db_path)[0]["payload"].get("operator_id") or "")


def accepted_requirement(kind: str, *, db_path=None) -> bool:
    import soc_store
    latest = records(kind, db_path=db_path)
    if not latest:
        return False
    value = latest[0]["payload"]
    return value["status"] == "accepted" and (not value.get("expires_at") or value["expires_at"] > soc_store.utc_now())
