CREATE TABLE IF NOT EXISTS enterprise_events (
    event_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    source TEXT NOT NULL,
    event_type TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    severity TEXT NOT NULL,
    correlation_id TEXT NOT NULL DEFAULT '',
    idempotency_key TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_enterprise_events_idempotency
    ON enterprise_events (organization_id, idempotency_key)
    WHERE idempotency_key <> '';
CREATE INDEX IF NOT EXISTS idx_enterprise_events_org_received
    ON enterprise_events (organization_id, received_at DESC, event_id DESC);
CREATE INDEX IF NOT EXISTS idx_enterprise_events_source_type
    ON enterprise_events (organization_id, source, event_type, observed_at DESC);

CREATE TABLE IF NOT EXISTS enterprise_assets (
    asset_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    name TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    criticality TEXT NOT NULL DEFAULT 'normal',
    metadata_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enterprise_assets_org_owner
    ON enterprise_assets (organization_id, owner, criticality);

CREATE TABLE IF NOT EXISTS enterprise_vulnerabilities (
    vulnerability_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    asset_id TEXT NOT NULL DEFAULT '',
    advisory_id TEXT NOT NULL DEFAULT '',
    package_name TEXT NOT NULL DEFAULT '',
    package_version TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL,
    cvss_score REAL,
    exploitability_score REAL,
    status TEXT NOT NULL,
    sla_due_at TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enterprise_vulns_org_status
    ON enterprise_vulnerabilities (organization_id, status, severity, sla_due_at);
CREATE INDEX IF NOT EXISTS idx_enterprise_vulns_org_asset
    ON enterprise_vulnerabilities (organization_id, asset_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS enterprise_findings (
    finding_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enterprise_findings_org_status
    ON enterprise_findings (organization_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS enterprise_alerts (
    alert_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enterprise_alerts_org_status
    ON enterprise_alerts (organization_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS enterprise_cases (
    case_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enterprise_cases_org_status
    ON enterprise_cases (organization_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS enterprise_actions (
    action_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    approval_required INTEGER NOT NULL DEFAULT 1,
    idempotency_key TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_enterprise_actions_idempotency
    ON enterprise_actions (organization_id, idempotency_key)
    WHERE idempotency_key <> '';

CREATE TABLE IF NOT EXISTS enterprise_source_cursors (
    organization_id TEXT NOT NULL,
    source TEXT NOT NULL,
    cursor_value TEXT NOT NULL DEFAULT '',
    last_success_at TEXT NOT NULL DEFAULT '',
    last_error_at TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (organization_id, source)
);

CREATE TABLE IF NOT EXISTS enterprise_dead_letters (
    dead_letter_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    retryable INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enterprise_dlq_org_created
    ON enterprise_dead_letters (organization_id, created_at DESC);

CREATE TABLE IF NOT EXISTS enterprise_audit_logs (
    audit_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    result TEXT NOT NULL,
    request_id TEXT NOT NULL,
    details_json TEXT NOT NULL,
    occurred_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enterprise_audit_org_time
    ON enterprise_audit_logs (organization_id, occurred_at DESC);

CREATE TABLE IF NOT EXISTS enterprise_controls (
    control_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    framework TEXT NOT NULL,
    title TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    review_due_at TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enterprise_controls_org_framework
    ON enterprise_controls (organization_id, framework, status, review_due_at);

CREATE TABLE IF NOT EXISTS enterprise_evidence (
    evidence_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    control_id TEXT NOT NULL DEFAULT '',
    evidence_type TEXT NOT NULL,
    source TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    collected_at TEXT NOT NULL,
    expires_at TEXT NOT NULL DEFAULT '',
    reviewer TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enterprise_evidence_org_control
    ON enterprise_evidence (organization_id, control_id, status, expires_at);

CREATE TABLE IF NOT EXISTS enterprise_questionnaires (
    questionnaire_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enterprise_questionnaires_org_status
    ON enterprise_questionnaires (organization_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS enterprise_threat_models (
    threat_model_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enterprise_threat_models_org_status
    ON enterprise_threat_models (organization_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS enterprise_pentest_engagements (
    engagement_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    status TEXT NOT NULL,
    owner TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_enterprise_pentest_org_status
    ON enterprise_pentest_engagements (organization_id, status, updated_at DESC);

CREATE TABLE IF NOT EXISTS enterprise_tickets (
    ticket_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    external_id TEXT NOT NULL,
    finding_id TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (organization_id, provider, external_id)
);
