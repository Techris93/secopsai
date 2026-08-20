"""Read-only AWS, GCP, Kubernetes, and generic webhook event adapters.

Connectors accept an injected fetcher so production credentials and network
clients stay outside the parser. Tests can therefore use deterministic fixture
payloads without calling a cloud API. Every normalized record is bounded and
safe to persist through :mod:`secopsai.enterprise_store`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable

from secopsai.enterprise_store import EnterpriseContext, EnterpriseRepository, redact, utc_now


Fetcher = Callable[[str, str], Any]


@dataclass(frozen=True)
class ConnectorConfig:
    source: str
    enabled: bool = False
    credentials_ref: str = ""
    region: str = ""
    project_id: str = ""
    cluster: str = ""
    read_only: bool = True
    max_events: int = 100

    def validate(self) -> None:
        if self.source not in NORMALIZERS:
            raise ValueError(f"unsupported connector source: {self.source}")
        if not self.read_only:
            raise PermissionError("enterprise connectors are read-only by default")
        if not 1 <= int(self.max_events) <= 500:
            raise ValueError("max_events must be between 1 and 500")


class AwsReadOnlyConnector:
    """Thin boto3-compatible read-only adapter with injected session support."""

    def __init__(self, *, region: str, session: Any = None) -> None:
        self.region = region
        if session is None:
            try:
                import boto3
                session = boto3.Session(region_name=region)
            except ImportError as exc:
                raise RuntimeError("install the enterprise AWS extra or inject a boto3-compatible session") from exc
        self.session = session

    def cloudtrail_events(self, *, lookup_attributes: list[dict[str, str]] | None = None, max_events: int = 50) -> list[dict[str, Any]]:
        client = self.session.client("cloudtrail", region_name=self.region)
        response = client.lookup_events(LookupAttributes=lookup_attributes or [], MaxResults=max(1, min(int(max_events), 50)))
        return list(response.get("Events") or [])

    def guardduty_findings(self, detector_id: str, *, max_findings: int = 50) -> list[dict[str, Any]]:
        client = self.session.client("guardduty", region_name=self.region)
        ids = client.list_findings(DetectorId=detector_id, MaxResults=max(1, min(int(max_findings), 50))).get("FindingIds") or []
        if not ids:
            return []
        return list(client.get_findings(DetectorId=detector_id, FindingIds=ids[:50]).get("Findings") or [])

    def securityhub_findings(self, *, max_findings: int = 50) -> list[dict[str, Any]]:
        client = self.session.client("securityhub", region_name=self.region)
        return list(client.get_findings(MaxResults=max(1, min(int(max_findings), 100))).get("Findings") or [])

    def iam_metadata(self, *, max_items: int = 100) -> dict[str, list[dict[str, Any]]]:
        client = self.session.client("iam", region_name=self.region)
        bounded = max(1, min(int(max_items), 100))
        users = list(client.list_users(MaxItems=bounded).get("Users") or [])
        roles = list(client.list_roles(MaxItems=bounded).get("Roles") or [])
        access_keys: list[dict[str, Any]] = []
        for user in users[:bounded]:
            name = _text(user.get("UserName"), 128)
            if name:
                access_keys.extend(client.list_access_keys(UserName=name, MaxItems=bounded).get("AccessKeyMetadata") or [])
        return {"users": users, "roles": roles, "access_keys": access_keys[:bounded]}

    def vpc_flow_metadata(self, *, max_items: int = 100) -> list[dict[str, Any]]:
        client = self.session.client("ec2", region_name=self.region)
        return list(client.describe_flow_logs(MaxResults=max(1, min(int(max_items), 100))).get("FlowLogs") or [])

    def secret_metadata(self, *, max_items: int = 100) -> list[dict[str, Any]]:
        client = self.session.client("secretsmanager", region_name=self.region)
        return list(client.list_secrets(MaxResults=max(1, min(int(max_items), 100))).get("SecretList") or [])


class GcpReadOnlyConnector:
    """Google client adapter using an injected read-only client object."""

    def __init__(self, client: Any) -> None:
        self.client = client

    def audit_logs(self, *, filter_text: str = "", page_size: int = 100) -> list[dict[str, Any]]:
        if not hasattr(self.client, "list_entries"):
            raise RuntimeError("GCP client does not expose list_entries")
        entries = self.client.list_entries(filter_=filter_text, page_size=max(1, min(int(page_size), 100)))
        return [dict(item) if isinstance(item, dict) else {"entry": str(item)} for item in entries]

    def security_findings(self, *, source_name: str = "") -> list[dict[str, Any]]:
        if not hasattr(self.client, "list_findings"):
            raise RuntimeError("GCP client does not expose list_findings")
        findings = self.client.list_findings(source_name=source_name)
        return [dict(item) if isinstance(item, dict) else {"finding": str(item)} for item in findings]

    def iam_metadata(self, *, project_id: str) -> list[dict[str, Any]]:
        if not hasattr(self.client, "list_service_accounts"):
            raise RuntimeError("GCP client does not expose list_service_accounts")
        return [dict(item) if isinstance(item, dict) else {"service_account": str(item)} for item in self.client.list_service_accounts(project_id=project_id)]

    def vpc_metadata(self, *, project_id: str) -> list[dict[str, Any]]:
        if not hasattr(self.client, "list_firewall_rules"):
            raise RuntimeError("GCP client does not expose list_firewall_rules")
        return [dict(item) if isinstance(item, dict) else {"firewall_rule": str(item)} for item in self.client.list_firewall_rules(project_id=project_id)]

    def gke_metadata(self, *, project_id: str, cluster: str) -> list[dict[str, Any]]:
        if not hasattr(self.client, "list_gke_workloads"):
            raise RuntimeError("GCP client does not expose list_gke_workloads")
        return [dict(item) if isinstance(item, dict) else {"workload": str(item)} for item in self.client.list_gke_workloads(project_id=project_id, cluster=cluster)]

    def secret_metadata(self, *, project_id: str) -> list[dict[str, Any]]:
        if not hasattr(self.client, "list_secret_metadata"):
            raise RuntimeError("GCP client does not expose list_secret_metadata")
        return [dict(item) if isinstance(item, dict) else {"secret": str(item)} for item in self.client.list_secret_metadata(project_id=project_id)]


class KubernetesReadOnlyConnector:
    """Kubernetes client adapter limited to GET/list-style methods."""

    def __init__(self, client: Any) -> None:
        self.client = client

    def audit_events(self, *, limit: int = 100) -> list[dict[str, Any]]:
        if not hasattr(self.client, "list_audit_events"):
            raise RuntimeError("Kubernetes client does not expose list_audit_events")
        return [dict(item) for item in list(self.client.list_audit_events(limit=max(1, min(int(limit), 500))) or []) if isinstance(item, dict)]

    def posture_objects(self) -> dict[str, list[dict[str, Any]]]:
        required = ("list_namespaces", "list_workloads", "list_rbac", "list_network_policies")
        missing = [name for name in required if not hasattr(self.client, name)]
        if missing:
            raise RuntimeError(f"Kubernetes client is missing read-only methods: {', '.join(missing)}")
        return {name[5:]: [dict(item) for item in list(getattr(self.client, name)() or []) if isinstance(item, dict)] for name in required}


@dataclass(frozen=True)
class ConnectorResult:
    source: str
    events: list[dict[str, Any]]
    cursor: str
    status: str
    error: str = ""


def _text(value: Any, limit: int = 400) -> str:
    return str(value or "").strip()[:limit]


def _severity(value: Any, default: str = "info") -> str:
    normalized = _text(value, 20).lower()
    return normalized if normalized in {"info", "low", "medium", "high", "critical"} else default


def _event(source: str, event_type: str, payload: dict[str, Any], *, observed_at: str = "", severity: str = "info", correlation_id: str = "") -> dict[str, Any]:
    return {
        "event_id": _text(payload.get("id") or payload.get("event_id") or payload.get("finding_id"), 100),
        "source": source,
        "event_type": event_type,
        "observed_at": _text(observed_at or payload.get("eventTime") or payload.get("timestamp") or utc_now(), 40),
        "severity": _severity(severity),
        "correlation_id": _text(correlation_id or payload.get("correlation_id"), 160),
        "payload": redact(payload),
    }


def normalize_aws_cloudtrail_event(payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize a CloudTrail record without retaining raw request bodies."""
    detail = payload.get("detail") if isinstance(payload.get("detail"), dict) else payload
    event_name = _text(detail.get("eventName") or detail.get("event_type") or "unknown", 160)
    source = _text(detail.get("eventSource") or "aws.cloudtrail", 160)
    actor = detail.get("userIdentity") if isinstance(detail.get("userIdentity"), dict) else {}
    normalized = dict(detail)
    normalized["actor"] = {
        "type": _text(actor.get("type"), 60),
        "arn": _text(actor.get("arn"), 300),
        "account_id": _text(actor.get("accountId"), 80),
    }
    severity = "high" if event_name.lower() in {"delete trail", "stoplogging", "puteventselectors", "createaccesskey"} else "info"
    return _event("aws.cloudtrail", f"aws.{event_name.lower().replace(' ', '_')}", normalized, observed_at=_text(detail.get("eventTime"), 40), severity=severity, correlation_id=_text(detail.get("eventID"), 100))


def normalize_aws_guardduty_finding(payload: dict[str, Any]) -> dict[str, Any]:
    finding = payload.get("Finding") if isinstance(payload.get("Finding"), dict) else payload
    severity_value = finding.get("severity")
    severity = "critical" if float(severity_value or 0) >= 8 else "high" if float(severity_value or 0) >= 5 else "medium" if float(severity_value or 0) >= 2 else "low"
    return _event("aws.guardduty", "aws.guardduty.finding", dict(finding), observed_at=_text(finding.get("updatedAt") or finding.get("createdAt"), 40), severity=severity, correlation_id=_text(finding.get("id"), 100))


def normalize_aws_security_hub_finding(payload: dict[str, Any]) -> dict[str, Any]:
    finding = payload.get("Finding") if isinstance(payload.get("Finding"), dict) else payload
    severity = finding.get("Severity") if isinstance(finding.get("Severity"), dict) else {}
    return _event("aws.securityhub", "aws.securityhub.finding", dict(finding), observed_at=_text(finding.get("UpdatedAt"), 40), severity=_text(severity.get("Label"), 20).lower(), correlation_id=_text(finding.get("Id"), 100))


def normalize_gcp_audit_log(payload: dict[str, Any]) -> dict[str, Any]:
    proto = payload.get("protoPayload") if isinstance(payload.get("protoPayload"), dict) else payload
    method = _text(proto.get("methodName") or "unknown", 200)
    principal = _text((proto.get("authenticationInfo") or {}).get("principalEmail") if isinstance(proto.get("authenticationInfo"), dict) else "", 240)
    normalized = dict(payload)
    normalized["principal"] = principal
    normalized.pop("protoPayload", None)
    normalized["method_name"] = method
    severity = "high" if any(token in method.lower() for token in ("setiam", "createkey", "delete", "disable")) else "info"
    return _event("gcp.audit", f"gcp.{method.lower().replace('/', '_').replace('.', '_')}", normalized, observed_at=_text(payload.get("timestamp"), 40), severity=severity, correlation_id=_text(payload.get("insertId"), 100))


def normalize_gcp_scc_finding(payload: dict[str, Any]) -> dict[str, Any]:
    finding = payload.get("finding") if isinstance(payload.get("finding"), dict) else payload
    severity = _text(finding.get("severity"), 20).lower()
    return _event("gcp.scc", "gcp.scc.finding", dict(finding), observed_at=_text(finding.get("eventTime") or finding.get("createTime"), 40), severity=severity, correlation_id=_text(finding.get("name") or finding.get("findingId"), 240))


def normalize_kubernetes_audit_event(payload: dict[str, Any]) -> dict[str, Any]:
    user = payload.get("user") if isinstance(payload.get("user"), dict) else {}
    object_ref = payload.get("objectRef") if isinstance(payload.get("objectRef"), dict) else {}
    verb = _text(payload.get("verb") or "unknown", 40).lower()
    resource = _text(object_ref.get("resource") or "unknown", 80).lower()
    suspicious = (verb in {"create", "delete", "patch", "update"} and resource in {"clusterroles", "clusterrolebindings", "rolebindings", "secrets", "pods", "deployments"})
    normalized = dict(payload)
    normalized["actor"] = {"username": _text(user.get("username"), 240), "groups": list(user.get("groups") or [])[:20]}
    normalized["object"] = {key: _text(object_ref.get(key), 200) for key in ("resource", "namespace", "name", "apiGroup")}
    return _event("kubernetes.audit", f"kubernetes.{verb}.{resource}", normalized, observed_at=_text(payload.get("requestReceivedTimestamp") or payload.get("stageTimestamp"), 40), severity="high" if suspicious else "info", correlation_id=_text(payload.get("auditID"), 100))


NORMALIZERS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "aws.cloudtrail": normalize_aws_cloudtrail_event,
    "aws.guardduty": normalize_aws_guardduty_finding,
    "aws.securityhub": normalize_aws_security_hub_finding,
    "gcp.audit": normalize_gcp_audit_log,
    "gcp.scc": normalize_gcp_scc_finding,
    "kubernetes.audit": normalize_kubernetes_audit_event,
}


def collect_connector(
    source: str,
    *,
    fetcher: Fetcher,
    store: EnterpriseRepository,
    context: EnterpriseContext,
    cursor: str = "",
    limit: int = 100,
) -> ConnectorResult:
    """Fetch one bounded page, normalize it, and persist safe events."""
    if source not in NORMALIZERS:
        raise ValueError(f"unsupported read-only connector source: {source}")
    bounded = max(1, min(int(limit), 500))
    try:
        response = fetcher(source, cursor)
        if isinstance(response, dict):
            records = response.get("events") or response.get("findings") or response.get("items") or []
            if not records and (response.get("eventName") or response.get("eventID") or response.get("protoPayload") or response.get("objectRef")):
                records = [response]
            next_cursor = _text(response.get("next_cursor") or response.get("nextToken") or response.get("nextPageToken"), 400)
        else:
            records = response or []
            next_cursor = ""
        if not isinstance(records, list):
            raise ValueError("connector response must contain a list")
        normalizer = NORMALIZERS[source]
        events: list[dict[str, Any]] = []
        for raw in records[:bounded]:
            if not isinstance(raw, dict):
                continue
            normalized = normalizer(raw)
            normalized["organization_id"] = context.organization_id
            persisted = store.append_event(normalized, idempotency_key=f"{source}:{normalized.get('correlation_id') or normalized.get('event_id')}")
            events.append(persisted)
        store.upsert_source_cursor({"source": source, "cursor_value": next_cursor, "status": "healthy", "last_success_at": utc_now(), "metadata": {"events": len(events)}})
        return ConnectorResult(source, events, next_cursor, "healthy")
    except Exception as exc:
        reason = str(exc)[:1000]
        store.record_dead_letter({"source": source, "reason": reason, "payload": {"cursor": cursor}, "retryable": True})
        store.upsert_source_cursor({"source": source, "cursor_value": cursor, "status": "degraded", "last_error_at": utc_now(), "metadata": {"error": reason}})
        return ConnectorResult(source, [], cursor, "degraded", reason)
