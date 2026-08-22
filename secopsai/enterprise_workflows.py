"""Small, auditable workflow primitives for enterprise security operations."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Iterable


FRAMEWORKS = {"soc2", "iso27001", "iso42001", "hipaa", "nist-csf", "cis", "nis2"}
ROLES = {"operator", "analyst", "security_engineer", "auditor", "reviewer", "administrator"}


def _text(value: Any, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]


def control_record(*, control_id: str, framework: str, title: str, owner: str, status: str = "not_started", review_due_at: str = "", metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    framework = framework.strip().lower()
    if framework not in FRAMEWORKS:
        raise ValueError(f"unsupported framework: {framework}")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,119}", control_id):
        raise ValueError("control_id is invalid")
    return {"control_id": control_id, "framework": framework, "title": _text(title, 300), "owner": _text(owner, 200), "status": _text(status, 40), "review_due_at": _text(review_due_at, 40), "metadata": metadata or {}}


def evidence_record(*, control_id: str, source: str, evidence_type: str = "automated", content: Any = None, expires_at: str = "", reviewer: str = "") -> dict[str, Any]:
    rendered = str(content or "")[:100_000]
    digest = hashlib.sha256(rendered.encode("utf-8")).hexdigest()
    return {"control_id": _text(control_id, 120), "source": _text(source, 500), "evidence_type": _text(evidence_type, 80), "sha256": digest, "expires_at": _text(expires_at, 40), "reviewer": _text(reviewer, 200), "status": "pending_review", "metadata": {"content_length": len(rendered)}}


def questionnaire_answer(*, question_id: str, answer: str, question: str = "", evidence_refs: Iterable[str] = (), status: str = "draft") -> dict[str, Any]:
    refs = [_text(item, 160) for item in evidence_refs if _text(item, 160)][:20]
    if not _text(question_id, 160):
        raise ValueError("question_id is required")
    return {
        "question_id": _text(question_id, 160),
        "question": _text(question, 2_000),
        "answer": _text(answer, 10_000),
        "evidence_refs": refs,
        "status": _text(status, 40),
    }


def questionnaire_record(*, questionnaire_id: str, title: str, owner: str, questions: Iterable[dict[str, Any]], customer: str = "") -> dict[str, Any]:
    normalized = []
    for item in list(questions)[:2_000]:
        if not isinstance(item, dict):
            continue
        normalized.append(questionnaire_answer(
            question_id=str(item.get("question_id") or item.get("id") or ""),
            question=str(item.get("question") or ""),
            answer=str(item.get("answer") or ""),
            evidence_refs=item.get("evidence_refs") or [],
            status=str(item.get("status") or "draft"),
        ))
    return {"questionnaire_id": _text(questionnaire_id, 120), "title": _text(title, 300), "owner": _text(owner, 200), "customer": _text(customer, 300), "status": "draft", "questions": normalized}


def threat_model_record(*, threat_model_id: str, title: str, owner: str, assets: Iterable[dict[str, Any]] = (), threats: Iterable[dict[str, Any]] = (), mitigations: Iterable[dict[str, Any]] = ()) -> dict[str, Any]:
    return {"threat_model_id": _text(threat_model_id, 120), "title": _text(title, 300), "owner": _text(owner, 200), "status": "draft", "method": "stride", "assets": list(assets)[:500], "threats": list(threats)[:500], "mitigations": list(mitigations)[:500]}


def pentest_engagement(*, engagement_id: str, title: str, owner: str, scope: Iterable[str], authorized_by: str, start_at: str = "", end_at: str = "") -> dict[str, Any]:
    scope_values = [_text(item, 500) for item in scope if _text(item, 500)][:200]
    if not scope_values:
        raise ValueError("penetration-test scope is required")
    if not _text(authorized_by, 300):
        raise ValueError("penetration-test authorization evidence is required")
    return {"engagement_id": _text(engagement_id, 120), "title": _text(title, 300), "owner": _text(owner, 200), "status": "planned", "scope": scope_values, "authorized_by": _text(authorized_by, 300), "start_at": _text(start_at, 40), "end_at": _text(end_at, 40)}


@dataclass(frozen=True)
class TicketProposal:
    provider: str
    title: str
    body: str
    finding_id: str
    approval_required: bool = True

    def as_record(self) -> dict[str, Any]:
        return {"action_type": "create_ticket", "target_id": self.finding_id, "status": "proposed", "approval_required": self.approval_required, "payload": {"provider": self.provider, "title": self.title[:300], "body": self.body[:10_000]}}
