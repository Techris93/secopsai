"""Finding-linked developer security awareness content and metrics."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


MODULES = {
    "dependency-safety": "Verify AI-suggested and newly registered packages before installation.",
    "credential-hygiene": "Recognize credential-file access and rotate affected secrets safely.",
    "cloud-identity": "Review least-privilege cloud identities and suspicious token use.",
    "kubernetes-posture": "Avoid privileged workloads, broad RBAC, and unpinned images.",
    "secure-ci": "Use SAST, SCA, secrets scanning, SBOM, and protected release gates.",
}


@dataclass(frozen=True)
class AwarenessRecommendation:
    module_id: str
    reason: str
    finding_ids: tuple[str, ...] = ()

    def as_record(self) -> dict[str, Any]:
        return {"module_id": self.module_id, "title": MODULES[self.module_id], "reason": self.reason, "finding_ids": list(self.finding_ids), "status": "recommended"}


def recommend_from_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rules: list[tuple[str, tuple[str, ...]]] = [
        ("dependency-safety", ("package", "supply", "dependency", "slopsquat")),
        ("credential-hygiene", ("credential", "token", "secret", "harvest")),
        ("cloud-identity", ("cloud", "iam", "aws", "gcp", "service account")),
        ("kubernetes-posture", ("kubernetes", "k8s", "container", "rbac", "privileged")),
        ("secure-ci", ("ci", "pipeline", "sast", "supply-chain")),
    ]
    recommendations = []
    for module_id, terms in rules:
        matched = [str(item.get("finding_id")) for item in findings if any(term in str(item.get("title") or item.get("summary") or "").lower() for term in terms)]
        if matched:
            recommendations.append(AwarenessRecommendation(module_id, "Linked to reviewed SecOpsAI findings.", tuple(matched[:50])).as_record())
    return recommendations
