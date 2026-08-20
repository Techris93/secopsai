"""Deterministic Kubernetes manifest and audit posture checks."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable

from secopsai.cloud_connectors import normalize_kubernetes_audit_event


def _finding(rule_id: str, severity: str, message: str, *, path: str = "", evidence: Any = None) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "confidence": "high",
        "message": message,
        "path": path,
        "evidence": evidence or {},
        "recommended_mitigation": "Review the manifest and apply the least-privilege Kubernetes control before deployment.",
    }


def scan_manifest(text: str, *, source_name: str = "manifest.yaml") -> dict[str, Any]:
    if len(text.encode("utf-8")) > 2 * 1024 * 1024:
        raise ValueError("Kubernetes manifest exceeds the safety limit")
    findings: list[dict[str, Any]] = []
    try:
        import yaml
    except ImportError:
        import json

        try:
            documents = [json.loads(text)]
        except json.JSONDecodeError as exc:
            raise RuntimeError("Kubernetes YAML scanning requires PyYAML; JSON manifests work without the optional dependency") from exc
    else:
        documents = list(yaml.safe_load_all(text))
    for index, document in enumerate(documents):
        if not isinstance(document, dict):
            continue
        kind = str(document.get("kind") or "").lower()
        metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
        name = str(metadata.get("name") or f"document-{index}")
        path = f"{source_name}#{index}:{kind}/{name}"
        spec = document.get("spec") if isinstance(document.get("spec"), dict) else {}
        template = spec.get("template") if isinstance(spec.get("template"), dict) else document
        pod_spec = template.get("spec") if isinstance(template.get("spec"), dict) else {}
        if pod_spec.get("hostNetwork") is True:
            findings.append(_finding("K8S-HOST-NETWORK", "high", "Workload shares the node network namespace.", path=path))
        if pod_spec.get("hostPID") is True or pod_spec.get("hostIPC") is True:
            findings.append(_finding("K8S-HOST-NAMESPACE", "high", "Workload shares a privileged host namespace.", path=path))
        for container_type in ("containers", "initContainers", "ephemeralContainers"):
            for container in pod_spec.get(container_type) or []:
                if not isinstance(container, dict):
                    continue
                cname = str(container.get("name") or container_type)
                security = container.get("securityContext") if isinstance(container.get("securityContext"), dict) else {}
                if security.get("privileged") is True:
                    findings.append(_finding("K8S-PRIVILEGED-CONTAINER", "critical", f"Container {cname} runs privileged.", path=path, evidence={"container": cname}))
                if security.get("allowPrivilegeEscalation") is True:
                    findings.append(_finding("K8S-PRIVILEGE-ESCALATION", "high", f"Container {cname} allows privilege escalation.", path=path, evidence={"container": cname}))
                image = str(container.get("image") or "")
                if image and (":" not in image.rsplit("/", 1)[-1] or image.endswith(":latest")):
                    findings.append(_finding("K8S-UNPINNED-IMAGE", "medium", f"Container {cname} is not pinned to an immutable image digest.", path=path, evidence={"container": cname, "image": image}))
        for volume in pod_spec.get("volumes") or []:
            if isinstance(volume, dict) and isinstance(volume.get("hostPath"), dict):
                findings.append(_finding("K8S-HOSTPATH", "high", "Workload mounts a hostPath volume.", path=path, evidence={"volume": volume.get("name"), "path": volume["hostPath"].get("path")}))
        if kind in {"clusterrolebinding", "rolebinding"}:
            role_ref = document.get("roleRef") if isinstance(document.get("roleRef"), dict) else {}
            if str(role_ref.get("name") or "").lower() == "cluster-admin":
                findings.append(_finding("K8S-CLUSTER-ADMIN", "critical", "Binding grants cluster-admin privileges.", path=path))
        if kind == "networkpolicy" and not spec.get("egress"):
            findings.append(_finding("K8S-EGRESS-UNDEFINED", "medium", "NetworkPolicy does not define egress restrictions.", path=path))
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return {"source": source_name, "sha256": digest, "findings": findings, "finding_count": len(findings)}


def normalize_audit_records(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [normalize_kubernetes_audit_event(item) for item in records if isinstance(item, dict)]


def dry_run_admission(manifest: str, *, source_name: str = "manifest.yaml") -> dict[str, Any]:
    result = scan_manifest(manifest, source_name=source_name)
    blocking = [item for item in result["findings"] if item["severity"] in {"critical", "high"}]
    return {**result, "admission": "deny" if blocking else "allow", "mode": "dry_run", "mutation_performed": False}
