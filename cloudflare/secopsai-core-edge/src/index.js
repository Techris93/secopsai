const MAX_ALERT_BYTES = 64 * 1024;
const SIGNATURE_MAX_AGE_SECONDS = 300;
const ACCEPTED_ALERT_TYPES = new Set([
  "collector_degraded",
  "collector_retention_risk",
  "storage_capacity_warning",
  "external_advisory_match",
  "external_advisory_feed_degraded",
  "npm_proactive_anomaly",
  "npm_enrichment_degraded",
]);
const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);
const WORKSPACE_TYPES = ["assets", "findings", "sites", "sensors", "services", "wifi_networks", "sync_state"];
const INTELLIGENCE_SCHEMA_VERSION = "secopsai.intelligence.v1";
const AGENT_TRIAGE_SCHEMA_VERSION = "secopsai.agent-triage.v1";
const DAILY_AUTOMATION_SCHEMA_VERSION = "secopsai.daily-automation.v1";
const MCP_GATEWAY_SCHEMA_VERSION = "secopsai.mcp.gateway.status.v1";
const INTELLIGENCE_JOB_SCHEMA_VERSION = "secopsai.intelligence.job.v1";
const MAX_INTELLIGENCE_BYTES = 64 * 1024;
const MAX_INTELLIGENCE_RESULT_BYTES = 512 * 1024;
const MAX_SUMMARY_BYTES = 32 * 1024;
const ONTOLOGY_SCHEMA_VERSION = "secopsai.ontology.v1";
// Keep one request below the lowest D1 plan limits.  The paid plan permits
// more reads/batch statements, but accepting a larger request here would make
// the same authenticated bridge payload fail when the database is on Free.
const MAX_ONTOLOGY_D1_READ_QUERIES = 50;
const MAX_ONTOLOGY_D1_BATCH_STATEMENTS = 1000;
const MAX_ONTOLOGY_ENTITIES = 500;
const MAX_ONTOLOGY_RELATIONSHIPS = 500;
const MAX_ONTOLOGY_EVENTS = 500;
const MAX_ONTOLOGY_EVIDENCE_REFS = 500;
const MAX_ONTOLOGY_DEPTH = 4;
const ONTOLOGY_ENTITY_TYPES = new Set([
  "package", "package_version", "artifact", "registry", "release_event", "advisory", "vulnerability",
  "repository", "manifest", "dependency", "build", "ci_run", "deployment", "asset", "service", "sensor",
  "network", "workspace", "owner", "team", "finding", "alert", "candidate", "research_case", "investigation",
  "evidence", "ioc", "hypothesis", "collector", "source", "automation_run", "intelligence_job", "task", "command",
  "model", "triage_decision", "remediation_action", "approval", "publication",
]);
const ONTOLOGY_RELATION_TYPES = new Set([
  "VERSION_AFFECTED_BY_ADVISORY", "VERSION_HAS_ARTIFACT", "PACKAGE_HAS_VERSION", "VERSION_RELEASED_IN", "REPOSITORY_DEPENDS_ON_VERSION",
  "MANIFEST_DECLARES_DEPENDENCY", "BUILD_PRODUCES_ARTIFACT", "ARTIFACT_DEPLOYED_TO_ASSET", "ASSET_PROVIDES_SERVICE",
  "ASSET_OWNED_BY_TEAM", "FINDING_ON_VERSION", "FINDING_ON_ASSET", "ALERT_DERIVED_FROM_FINDING",
  "CANDIDATE_PROMOTED_TO_CASE", "CASE_GROUPS_FINDING", "CASE_GROUPS_ALERT", "CASE_SUPPORTED_BY_EVIDENCE", "EVIDENCE_FROM_SOURCE",
  "EVIDENCE_SUPPORTS_HYPOTHESIS", "ACTION_REMEDIATES_FINDING", "RUN_PRODUCED_RESULT", "COMMAND_REQUESTS_RUN",
  "ACTOR_APPROVED_ACTION", "COLLECTOR_OBSERVED_RELEASE", "SOURCE_PROVIDES_ADVISORY", "ASSET_DEPENDS_ON_SERVICE",
  "INVESTIGATION_PRODUCES_EVIDENCE", "JOB_TARGETS_ENTITY", "TASK_ASSIGNED_TO_OWNER",
  "CASE_HAS_SUBJECT", "CASE_HAS_ARTIFACT", "CASE_HAS_IOC", "RELEASE_EVENT_FROM_SOURCE",
  "TRIAGE_DECISION_FOR_ENTITY",
]);
const JOB_ACTIVE_STATUSES = new Set(["queued", "running", "awaiting_provider"]);
const JOB_FINAL_STATUSES = new Set(["succeeded", "failed", "canceled"]);
const COMMAND_ACTIVE_STATUSES = new Set(["queued", "running"]);
const COMMAND_FINAL_STATUSES = new Set(["succeeded", "degraded", "failed", "canceled", "recovered"]);
const INTELLIGENCE_ACTIONS = new Set([
  "explain_finding", "triage_finding", "prioritize_findings", "analyze_asset_change",
  "analyze_research_case", "generate_analyst_brief", "review_publication_safety",
  "recommend_remediation", "triage_artifact", "execute_specialist_work", "review_specialist_work",
]);
const COORDINATOR_COMMANDS = new Set(["daily-run", "autopilot-run-now", "autopilot-rollback", "autopilot-rollback-tuning"]);

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
};

export async function handleRequest(request, env) {
  const requestId = boundedHeader(request.headers.get("x-request-id")) || crypto.randomUUID();
  const url = new URL(request.url);
  // The hosted Pages proxy normalizes ontology paths, but direct API clients
  // and older dashboard builds may retain a trailing slash.  Keep the
  // ontology contract tolerant of that harmless URL variant without changing
  // the matching semantics of unrelated routes.
  const ontologyPathname = url.pathname.replace(/\/+$/, "") || "/";
  try {
    if (request.method === "GET" && url.pathname === "/healthz") {
      return response(200, { status: "ok", service: "secopsai-core-edge" }, requestId);
    }
    if (request.method === "GET" && url.pathname === "/readyz") {
      await env.DB.prepare("SELECT 1 AS ready").first();
      return response(200, { status: "ready", data_store: "d1" }, requestId);
    }
    if (request.method === "POST" && url.pathname === "/api/v1/research/alerts/webhook") {
      return await ingestResearchAlert(request, env, requestId);
    }
    if (request.method === "GET" && url.pathname === "/api/v1/workspace") {
      requireBearer(request, env.CORE_READ_TOKEN);
      return response(200, await workspacePayload(env.DB, boundedLimit(url.searchParams.get("limit"), 100, 500)), requestId);
    }
    if (request.method === "GET" && url.pathname === "/api/v1/audit-logs") {
      requireBearer(request, env.CORE_READ_TOKEN);
      const limit = boundedLimit(url.searchParams.get("limit"), 100, 500);
      const rows = await env.DB.prepare(
        "SELECT request_id, action, actor_role, result, source_instance, details_json, created_at FROM audit_logs ORDER BY created_at DESC, audit_id DESC LIMIT ?",
      ).bind(limit).all();
      return response(200, { audit_logs: rows.results.map(decodeAudit) }, requestId);
    }
    if (request.method === "GET" && (ontologyPathname === "/api/v1/ontology" || ontologyPathname === "/api/v1/ontology/search")) {
      requireBearer(request, env.CORE_READ_TOKEN);
      const result = await ontologySearch(env.DB, url.searchParams, clean(env.CORE_WORKSPACE_ID, 160));
      await writeAudit(env.DB, { requestId, action: "ontology.search", actorRole: "operator_read", result: "success", sourceInstance: "secopsai-core-edge", details: { query: clean(url.searchParams.get("q"), 120), entity_type: clean(url.searchParams.get("entity_type"), 80), count: result.entities?.length || 0 }, createdAt: nowIso() });
      return response(200, result, requestId);
    }
    const ontologyEntityMatch = ontologyPathname.match(/^\/api\/v1\/ontology\/entities\/([^/]+)(?:\/(neighbors|timeline|lineage|risk))?$/);
    if (ontologyEntityMatch && request.method === "GET") {
      const entityId = decodeURIComponent(ontologyEntityMatch[1]);
      const operation = ontologyEntityMatch[2] || "detail";
      if (operation === "risk") {
        requireBearer(request, env.CORE_INTELLIGENCE_TOKEN);
        const result = await ontologyRisk(env.DB, entityId, url.searchParams, clean(env.CORE_WORKSPACE_ID, 160));
        await writeAudit(env.DB, { requestId, action: "ontology.risk.read", actorRole: "intelligence_read", result: "success", sourceInstance: "secopsai-core-edge", details: { entity_id: clean(entityId, 512), risk_score: result.risk_score }, createdAt: nowIso() });
        return response(200, result, requestId);
      }
      requireBearer(request, env.CORE_READ_TOKEN);
      const workspace = clean(env.CORE_WORKSPACE_ID, 160);
      if (operation === "neighbors") {
        const result = await ontologyNeighbors(env.DB, entityId, url.searchParams, workspace);
        await writeAudit(env.DB, { requestId, action: "ontology.neighbors.read", actorRole: "operator_read", result: "success", sourceInstance: "secopsai-core-edge", details: { entity_id: clean(entityId, 512), depth: result.depth, nodes: result.nodes?.length || 0 }, createdAt: nowIso() });
        return response(200, result, requestId);
      }
      if (operation === "timeline") {
        const result = await ontologyTimeline(env.DB, entityId, url.searchParams, workspace);
        await writeAudit(env.DB, { requestId, action: "ontology.timeline.read", actorRole: "operator_read", result: "success", sourceInstance: "secopsai-core-edge", details: { entity_id: clean(entityId, 512), events: result.events?.length || 0 }, createdAt: nowIso() });
        return response(200, result, requestId);
      }
      if (operation === "lineage") {
        const result = await ontologyLineage(env.DB, entityId, url.searchParams, workspace);
        await writeAudit(env.DB, { requestId, action: "ontology.lineage.read", actorRole: "operator_read", result: "success", sourceInstance: "secopsai-core-edge", details: { entity_id: clean(entityId, 512), paths: result.paths?.length || 0 }, createdAt: nowIso() });
        return response(200, result, requestId);
      }
      const result = await ontologyEntity(env.DB, entityId, workspace);
      await writeAudit(env.DB, { requestId, action: "ontology.entity.read", actorRole: "operator_read", result: "success", sourceInstance: "secopsai-core-edge", details: { entity_id: clean(entityId, 512) }, createdAt: nowIso() });
      return response(200, result, requestId);
    }
    if (request.method === "GET" && ontologyPathname === "/api/v1/ontology/quality") {
      requireBearer(request, env.CORE_READ_TOKEN);
      const result = await ontologyQuality(env.DB, url.searchParams, clean(env.CORE_WORKSPACE_ID, 160));
      await writeAudit(env.DB, { requestId, action: "ontology.quality.read", actorRole: "operator_read", result: "success", sourceInstance: "secopsai-core-edge", details: { entities: result.entities, relationships: result.relationships }, createdAt: nowIso() });
      return response(200, result, requestId);
    }
    if (request.method === "POST" && url.pathname === "/api/v1/ontology/sync") {
      requireBearer(request, env.CORE_BRIDGE_TOKEN);
      return response(200, await syncOntology(request, env, requestId), requestId);
    }
    if (request.method === "GET" && url.pathname === "/api/v1/research/alerts") {
      requireBearer(request, env.CORE_READ_TOKEN);
      const limit = boundedLimit(url.searchParams.get("limit"), 100, 500);
      return response(200, { research_alerts: await listResearchAlerts(env.DB, limit) }, requestId);
    }
    if (request.method === "GET" && url.pathname === "/api/v1/intelligence/actions") {
      requireBearer(request, env.CORE_READ_TOKEN);
      return response(200, intelligenceActions(), requestId);
    }
    if (request.method === "GET" && url.pathname === "/api/v1/mcp/sessions") {
      requireBearer(request, env.CORE_READ_TOKEN);
      return response(200, await mcpGatewayStatus(env.DB, boundedLimit(url.searchParams.get("limit"), 100, 500)), requestId);
    }
    if (url.pathname === "/api/v1/intelligence/jobs" && request.method === "GET") {
      requireBearer(request, env.CORE_INTELLIGENCE_TOKEN);
      return response(200, await listIntelligenceJobs(env.DB, url.searchParams), requestId);
    }
    if (url.pathname === "/api/v1/intelligence/jobs" && request.method === "POST") {
      requireBearer(request, env.CORE_INTELLIGENCE_TOKEN);
      return response(200, await createIntelligenceJob(request, env, requestId), requestId);
    }
    const jobMatch = url.pathname.match(/^\/api\/v1\/intelligence\/jobs\/([^/]+)(?:\/(cancel|heartbeat))?$/);
    if (jobMatch && request.method === "GET" && !jobMatch[2]) {
      requireBearer(request, env.CORE_INTELLIGENCE_TOKEN);
      return response(200, { job: await getIntelligenceJob(env.DB, decodeURIComponent(jobMatch[1]), true) }, requestId);
    }
    if (jobMatch && request.method === "POST" && jobMatch[2] === "cancel") {
      requireBearer(request, env.CORE_INTELLIGENCE_TOKEN);
      return response(200, { job: await cancelIntelligenceJob(env.DB, decodeURIComponent(jobMatch[1]), requestId) }, requestId);
    }
    if (jobMatch && request.method === "POST" && jobMatch[2] === "heartbeat") {
      requireBearer(request, env.CORE_BRIDGE_TOKEN);
      const heartbeatPayload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Bridge heartbeat");
      return response(200, { job: await heartbeatIntelligenceJob(env.DB, decodeURIComponent(jobMatch[1]), requestId, heartbeatPayload) }, requestId);
    }
    if (request.method === "GET" && url.pathname === "/api/v1/intelligence/autopilot") {
      requireBearer(request, env.CORE_INTELLIGENCE_TOKEN);
      return response(200, await agentTriageStatus(env.DB, boundedLimit(url.searchParams.get("limit"), 50, 100)), requestId);
    }
    if (request.method === "POST" && url.pathname === "/api/v1/intelligence/autopilot/configure") {
      requireBearer(request, env.CORE_INTELLIGENCE_TOKEN);
      return response(200, { settings: await configureAgentTriage(request, env.DB, requestId) }, requestId);
    }
    if (request.method === "POST" && url.pathname === "/api/v1/intelligence/autopilot/run-now") {
      requireBearer(request, env.CORE_INTELLIGENCE_TOKEN);
      return response(200, { result: await queueCoordinatorCommand(request, env.DB, requestId, "autopilot-run-now", {}) }, requestId);
    }
    if (request.method === "GET" && url.pathname === "/api/v1/intelligence/daily") {
      requireBearer(request, env.CORE_INTELLIGENCE_TOKEN);
      return response(200, await dailyAutomationStatus(env.DB, boundedLimit(url.searchParams.get("limit"), 20, 100)), requestId);
    }
    if (request.method === "POST" && url.pathname === "/api/v1/intelligence/daily/configure") {
      requireBearer(request, env.CORE_INTELLIGENCE_TOKEN);
      return response(200, { settings: await configureDailyAutomation(request, env.DB, requestId) }, requestId);
    }
    if (request.method === "POST" && url.pathname === "/api/v1/intelligence/daily/run") {
      requireBearer(request, env.CORE_INTELLIGENCE_TOKEN);
      return response(200, { result: await queueCoordinatorCommand(request, env.DB, requestId, "daily-run", {}) }, requestId);
    }
    const rollbackMatch = url.pathname.match(/^\/api\/v1\/intelligence\/autopilot\/(runs|tuning)\/([^/]+)\/rollback$/);
    if (request.method === "POST" && rollbackMatch) {
      requireBearer(request, env.CORE_INTELLIGENCE_TOKEN);
      const type = rollbackMatch[1] === "runs" ? "autopilot-rollback" : "autopilot-rollback-tuning";
      const key = rollbackMatch[1] === "runs" ? "run_id" : "proposal_id";
      return response(200, { result: await queueCoordinatorCommand(request, env.DB, requestId, type, { [key]: decodeURIComponent(rollbackMatch[2]) }) }, requestId);
    }
    if (request.method === "POST" && url.pathname === "/api/v1/intelligence/bridge/claim") {
      requireBearer(request, env.CORE_BRIDGE_TOKEN);
      return response(200, await claimIntelligenceJob(request, env.DB, requestId), requestId);
    }
    if (request.method === "POST" && url.pathname === "/api/v1/intelligence/bridge/state") {
      requireBearer(request, env.CORE_BRIDGE_TOKEN);
      return response(200, await syncRunnerState(request, env.DB, requestId), requestId);
    }
    if (request.method === "GET" && url.pathname === "/api/v1/intelligence/bridge/state") {
      requireBearer(request, env.CORE_BRIDGE_TOKEN);
      return response(200, await hostedCoordinatorState(env.DB, boundedLimit(url.searchParams.get("limit"), 20, 100)), requestId);
    }
    if (request.method === "POST" && url.pathname === "/api/v1/intelligence/bridge/commands/claim") {
      requireBearer(request, env.CORE_BRIDGE_TOKEN);
      return response(200, await claimCoordinatorCommand(request, env.DB, requestId), requestId);
    }
    const bridgeJobMatch = url.pathname.match(/^\/api\/v1\/intelligence\/bridge\/jobs\/([^/]+)\/(complete|fail|heartbeat)$/);
    if (request.method === "POST" && bridgeJobMatch) {
      requireBearer(request, env.CORE_BRIDGE_TOKEN);
      const jobId = decodeURIComponent(bridgeJobMatch[1]);
      if (bridgeJobMatch[2] === "complete") return response(200, await completeIntelligenceJob(request, env.DB, jobId, requestId), requestId);
      if (bridgeJobMatch[2] === "heartbeat") {
        const heartbeatPayload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Bridge heartbeat");
        return response(200, { job: await heartbeatIntelligenceJob(env.DB, jobId, requestId, heartbeatPayload) }, requestId);
      }
      return response(200, await failIntelligenceJob(request, env.DB, jobId, requestId), requestId);
    }
    const bridgeCommandMatch = url.pathname.match(/^\/api\/v1\/intelligence\/bridge\/commands\/([^/]+)\/(complete|fail|heartbeat)$/);
    if (request.method === "POST" && bridgeCommandMatch) {
      requireBearer(request, env.CORE_BRIDGE_TOKEN);
      const commandId = decodeURIComponent(bridgeCommandMatch[1]);
      if (bridgeCommandMatch[2] === "heartbeat") {
        const heartbeatPayload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Coordinator heartbeat");
        return response(200, await heartbeatCoordinatorCommand(heartbeatPayload, env.DB, commandId, requestId), requestId);
      }
      return response(200, await finishCoordinatorCommand(request, env.DB, commandId, bridgeCommandMatch[2], requestId), requestId);
    }
    return response(404, { error: "not_found" }, requestId);
  } catch (error) {
    if (error instanceof HttpError) return response(error.status, { error: error.code, detail: error.message }, requestId);
    console.error(JSON.stringify({ level: "error", event: "core_edge.request_failed", request_id: requestId, error: safeMessage(error) }));
    return response(500, { error: "internal_error" }, requestId);
  }
}

async function ingestResearchAlert(request, env, requestId) {
  if (!env.RESEARCH_WEBHOOK_SECRET) throw new HttpError(503, "not_configured", "Research alert webhook is not configured");
  const declaredLength = Number(request.headers.get("content-length") || 0);
  if (declaredLength > MAX_ALERT_BYTES) throw new HttpError(413, "request_too_large", "Research alert exceeds the request size limit");
  const body = new Uint8Array(await request.arrayBuffer());
  if (body.byteLength > MAX_ALERT_BYTES) throw new HttpError(413, "request_too_large", "Research alert exceeds the request size limit");
  await verifySignature(request.headers, body, env.RESEARCH_WEBHOOK_SECRET);
  let payload;
  try {
    payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    throw new HttpError(400, "invalid_json", "Request body must be valid UTF-8 JSON");
  }
  const alert = validateAlert(payload);
  const now = new Date().toISOString();
  const alertId = `RAL-WEB-${(await sha256Hex(alert.alert_id)).slice(0, 24).toUpperCase()}`;
  const existing = await env.DB.prepare("SELECT alert_id FROM research_alerts WHERE source_alert_id = ?").bind(alert.alert_id).first();
  await env.DB.prepare(`
    INSERT INTO research_alerts (
      alert_id, source_alert_id, alert_type, severity, candidate_id, campaign_id,
      reason, evidence_json, status, owner, occurred_at, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', '', ?, ?, ?)
    ON CONFLICT(source_alert_id) DO UPDATE SET
      alert_type=excluded.alert_type,
      severity=excluded.severity,
      candidate_id=excluded.candidate_id,
      campaign_id=excluded.campaign_id,
      reason=excluded.reason,
      evidence_json=excluded.evidence_json,
      occurred_at=excluded.occurred_at,
      updated_at=excluded.updated_at
  `).bind(
    alertId,
    alert.alert_id,
    alert.alert_type,
    alert.severity,
    alert.candidate_id,
    alert.campaign_id,
    alert.reason,
    JSON.stringify(sanitize(alert.evidence)),
    alert.occurred_at,
    now,
    now,
  ).run();
  await writeAudit(env.DB, {
    requestId,
    action: "research.alert.ingested",
    actorRole: "research_worker",
    result: existing ? "updated" : "created",
    sourceInstance: "secopsai-research-worker",
    details: { alert_id: alertId, source_alert_id: alert.alert_id, alert_type: alert.alert_type, severity: alert.severity },
    createdAt: now,
  });
  return response(200, { status: "accepted", alert_id: alertId, created: !existing }, requestId);
}

function ontologyEntityType(value) {
  const type = clean(value, 80).toLowerCase();
  if (!ONTOLOGY_ENTITY_TYPES.has(type)) throw new HttpError(422, "invalid_entity_type", `Unsupported ontology entity type: ${type}`);
  return type;
}

function ontologyRelationType(value) {
  const type = clean(value, 120).toUpperCase();
  if (!ONTOLOGY_RELATION_TYPES.has(type)) throw new HttpError(422, "invalid_relationship_type", `Unsupported ontology relationship type: ${type}`);
  return type;
}

function ontologyNormalize(value, maximum = 1024) {
  return clean(value, maximum).normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();
}

function ontologySafeLocatorSync(value) {
  // Keep the full bounded request value for opaque hashing. Truncating before
  // hashing makes distinct secrets that share a prefix correlate to the same
  // locator and can leak meaningful path/token prefixes.
  const raw = String(value || "").trim();
  if (!raw) return "";
  const lowered = raw.toLowerCase();
  if (["file:", "data:", "javascript:", "\\\\", "/"].some((prefix) => lowered.startsWith(prefix))) return "redacted://local";
  try {
    const parsed = new URL(raw);
    if (["http:", "https:"].includes(parsed.protocol) && parsed.hostname) {
      const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
      const privateHost = host === "localhost" || host.endsWith(".local") || host.endsWith(".internal") || host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:") || /^(?:0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(host);
      if (parsed.username || parsed.password || privateHost) return "redacted://url";
      const safeHost = host.includes(":") ? `[${host}]` : host;
      return `${parsed.protocol}//${safeHost}${parsed.port ? `:${parsed.port}` : ""}${parsed.pathname}`.slice(0, 1024);
    }
  } catch {
    // Opaque locators may contain bearer tokens, local paths, or credentials.
    // Keep only a deterministic digest so operators can correlate a reference
    // without exposing the original value to D1 or the browser.
  }
  return `redacted://opaque/${shortDigest(raw)}`;
}

// Stored evidence references use SHA-256 so Python, Edge, and D1 derive the
// same redacted locator.  Synchronous response sanitization uses the bounded
// FNV fallback above because it cannot await Web Crypto; it never participates
// in an identity or evidence-reference key.
async function ontologySafeLocator(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  const lowered = raw.toLowerCase();
  const digest = async (kind) => `redacted://${kind}/${(await sha256Hex(raw)).slice(0, 32)}`;
  if (["file:", "data:", "javascript:", "\\\\", "/"].some((prefix) => lowered.startsWith(prefix))) return digest("local");
  try {
    const parsed = new URL(raw);
    if (["http:", "https:"].includes(parsed.protocol) && parsed.hostname) {
      const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
      const privateHost = host === "localhost" || host.endsWith(".local") || host.endsWith(".internal") || host === "::1" || host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80:") || /^(?:0\.|10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.)/.test(host);
      if (parsed.username || parsed.password || privateHost) return digest("url");
      const safeHost = host.includes(":") ? `[${host}]` : host;
      return `${parsed.protocol}//${safeHost}${parsed.port ? `:${parsed.port}` : ""}${parsed.pathname}`.slice(0, 1024);
    }
  } catch {
    // Opaque locators are represented by a deterministic digest only.
  }
  return digest("opaque");
}

async function ontologyCanonicalKey(type, namespace, value) {
  // Canonical identity is normalized from the complete request value. The
  // request itself is bounded by MAX_INTELLIGENCE_BYTES, while the stored key
  // is reduced to a cryptographic digest below when it exceeds the shared
  // Python/SQLite identity bounds.
  let key = String(value || "").normalize("NFKC").toLowerCase().replace(/\s+/g, " ").trim();
  if (["pypi", "python"].includes(namespace) && ["package", "package_version"].includes(type)) key = key.replace(/_/g, "-");
  if (["vulnerability", "advisory"].includes(type)) key = key.toUpperCase();
  if (["artifact", "evidence"].includes(type)) key = key.replace(/^(?:sha(?:256)?|hash):/i, "");
  if (["repository", "registry", "source"].includes(type)) key = key.replace(/\/+$/, "");
  // Keep the identity contract byte-for-byte compatible with Python. Python
  // hashes the complete normalized key whenever the stored key or the full
  // prefixed identifier would exceed its bounded SQLite field. Returning a
  // prefix plus digest here produced different IDs for long values and could
  // merge two records after a cross-plane replay.
  const prefixes = ontologyPrefixes();
  const prefixedBytes = new TextEncoder().encode(`${prefixes[type] || type}:${namespace}:${key}`).byteLength;
  if (new TextEncoder().encode(key).byteLength <= 1024 && prefixedBytes <= 512) return key;
  return `sha256-${(await sha256Hex(key)).slice(0, 40)}`;
}

function ontologyConfidence(value, fallback = 100) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.max(0, Math.min(Math.round(parsed), 100)) : fallback;
}

function ontologySourcePriority(value) {
  const priorities = { "secopsai-research": 90, core: 85, registry: 80, edge: 75, github: 70, scanner: 65, legacy: 40, unknown: 0 };
  const normalized = ontologySource(value);
  return priorities[normalized] ?? (normalized ? 50 : 0);
}

function ontologySource(value) {
  const normalized = ontologyNormalize(value, 160).replace(/_/g, "-");
  return {
    "secopsai research": "secopsai-research",
    research: "secopsai-research",
    "secopsai-core": "core",
  }[normalized] || normalized;
}

async function ontologyEntityId(type, namespace, canonicalKey) {
  const prefixes = ontologyPrefixes();
  const candidate = `${prefixes[type] || type}:${namespace}:${canonicalKey}`;
  if (new TextEncoder().encode(candidate).byteLength <= 512) return candidate;
  return `${prefixes[type] || type}:${namespace}:sha256-${(await sha256Hex(canonicalKey)).slice(0, 40)}`;
}

function ontologyPrefixes() {
  return {
    package: "pkg", package_version: "pkgver", artifact: "artifact", release_event: "release", advisory: "adv",
    vulnerability: "vuln", repository: "repo", manifest: "manifest", dependency: "dep", build: "build", ci_run: "ci",
    deployment: "deploy", asset: "asset", service: "service", sensor: "sensor", network: "network", workspace: "workspace",
    owner: "owner", team: "team", finding: "finding", alert: "alert", candidate: "candidate", research_case: "case",
    investigation: "investigation", evidence: "evidence", ioc: "ioc", hypothesis: "hypothesis", collector: "collector",
    source: "source", automation_run: "automation", intelligence_job: "job", task: "task", command: "command", model: "model",
    triage_decision: "triage", remediation_action: "action", approval: "approval", publication: "publication",
  };
}

function publicOntologyEntity(row, includeProperties = true) {
  if (!row) return null;
  const output = {
    entity_id: row.entity_id,
    entity_type: row.entity_type,
    namespace: row.namespace,
    canonical_key: row.canonical_key,
    display_name: row.display_name,
    source: row.source,
    source_id: row.source_id || "",
    workspace_id: row.workspace_id || "hosted",
    owner_id: row.owner_id || "",
    status: row.status || "active",
    confidence: Number(row.confidence ?? 0),
    first_seen_at: row.first_seen_at,
    last_seen_at: row.last_seen_at,
    observed_at: row.observed_at,
    freshness_at: row.freshness_at,
    valid_from: row.valid_from || null,
    valid_to: row.valid_to || null,
    schema_version: row.schema_version || ONTOLOGY_SCHEMA_VERSION,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
  if (includeProperties) output.properties = parseJson(row.properties_json, {});
  return output;
}

function publicOntologyRelationship(row) {
  return {
    relationship_id: row.relationship_id,
    relationship_type: row.relationship_type,
    from_entity_id: row.from_entity_id,
    to_entity_id: row.to_entity_id,
    source: row.source,
    source_record_id: row.source_record_id || "",
    workspace_id: row.workspace_id || "hosted",
    evidence_ref_id: row.evidence_ref_id || null,
    properties: parseJson(row.properties_json, {}),
    confidence: Number(row.confidence ?? 0),
    observed_at: row.observed_at,
    valid_from: row.valid_from || null,
    valid_to: row.valid_to || null,
    freshness_at: row.freshness_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

function ontologyWorkspaceAllowed(row, expectedWorkspace) {
  if (!expectedWorkspace) return true;
  return String(row?.workspace_id || "") === expectedWorkspace;
}

function ontologyWorkspace(value, expectedWorkspace, fallback = "hosted") {
  const supplied = clean(value, 160);
  // The Python runner labels its source records ``local`` because the full
  // ledger lives on the execution host.  Once a record crosses the bridge,
  // bind that projection to the Core instance's hosted workspace so scoped
  // reads cannot miss it (or expose it to another tenant).
  if (expectedWorkspace && (!supplied || supplied === "local")) return expectedWorkspace;
  return supplied || expectedWorkspace || fallback;
}

async function ontologySearch(db, searchParams, expectedWorkspace = "") {
  const limit = boundedLimit(searchParams.get("limit"), 100, 500);
  const type = clean(searchParams.get("entity_type"), 80).toLowerCase();
  if (type) ontologyEntityType(type);
  const requestedWorkspace = clean(searchParams.get("workspace_id"), 160);
  if (expectedWorkspace && requestedWorkspace && requestedWorkspace !== expectedWorkspace) throw new HttpError(403, "scope_mismatch", "Ontology workspace is not available to this Core instance");
  const workspace = requestedWorkspace || expectedWorkspace;
  const query = ontologyNormalize(searchParams.get("q"), 256);
  const clauses = [];
  const values = [];
  if (type) { clauses.push("e.entity_type = ?"); values.push(type); }
  if (workspace) { clauses.push("e.workspace_id = ?"); values.push(workspace); }
  if (query) {
    const like = `%${query}%`;
    clauses.push("(lower(e.entity_id) LIKE ? OR lower(e.canonical_key) LIKE ? OR lower(e.display_name) LIKE ? OR lower(e.source_id) LIKE ? OR EXISTS (SELECT 1 FROM ontology_aliases a WHERE a.entity_id=e.entity_id AND a.normalized_value LIKE ?))");
    values.push(like, like, like, like, like);
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  const rows = await db.prepare(`SELECT * FROM ontology_entities e ${where} ORDER BY e.updated_at DESC, e.entity_id LIMIT ?`).bind(...values, limit).all();
  return { schema_version: ONTOLOGY_SCHEMA_VERSION, entities: (rows.results || []).map((row) => publicOntologyEntity(row, false)), query, limit };
}

async function ontologyEntity(db, entityId, expectedWorkspace = "") {
  const normalized = clean(entityId, 512);
  let row = await db.prepare("SELECT * FROM ontology_entities WHERE entity_id = ?").bind(normalized).first();
  if (!row) {
    const alias = await db.prepare("SELECT entity_id FROM ontology_aliases WHERE normalized_value = ? LIMIT 1").bind(ontologyNormalize(normalized, 512)).first();
    if (alias) row = await db.prepare("SELECT * FROM ontology_entities WHERE entity_id = ?").bind(alias.entity_id).first();
  }
  if (!row || !ontologyWorkspaceAllowed(row, expectedWorkspace)) throw new HttpError(404, "not_found", `Ontology entity not found: ${normalized}`);
  const aliases = await db.prepare("SELECT alias_type, alias_value, source, confidence FROM ontology_aliases WHERE entity_id = ? ORDER BY alias_type, alias_value").bind(row.entity_id).all();
  const relationScope = expectedWorkspace ? " AND r.workspace_id = ?" : "";
  const counts = expectedWorkspace
    ? await db.prepare(`SELECT (SELECT COUNT(*) FROM ontology_relationships r JOIN ontology_entities t ON t.entity_id = r.to_entity_id WHERE r.from_entity_id = ?${relationScope} AND t.workspace_id = ?) AS outgoing, (SELECT COUNT(*) FROM ontology_relationships r JOIN ontology_entities f ON f.entity_id = r.from_entity_id WHERE r.to_entity_id = ?${relationScope} AND f.workspace_id = ?) AS incoming`).bind(row.entity_id, expectedWorkspace, expectedWorkspace, row.entity_id, expectedWorkspace, expectedWorkspace).first()
    : await db.prepare("SELECT (SELECT COUNT(*) FROM ontology_relationships WHERE from_entity_id = ?) AS outgoing, (SELECT COUNT(*) FROM ontology_relationships WHERE to_entity_id = ?) AS incoming").bind(row.entity_id, row.entity_id).first();
  return { schema_version: ONTOLOGY_SCHEMA_VERSION, entity: { ...publicOntologyEntity(row), aliases: aliases.results || [], relationship_counts: { outgoing: Number(counts?.outgoing || 0), incoming: Number(counts?.incoming || 0) } } };
}

async function ontologyNeighbors(db, entityId, searchParams, expectedWorkspace = "") {
  const root = clean(entityId, 512);
  const depth = boundedInteger(searchParams.get("depth"), 1, 1, MAX_ONTOLOGY_DEPTH, "depth");
  const limit = boundedLimit(searchParams.get("limit"), 100, 500);
  const relationType = clean(searchParams.get("relationship_type"), 120);
  if (relationType) ontologyRelationType(relationType);
  const rootRow = await db.prepare("SELECT entity_id, workspace_id FROM ontology_entities WHERE entity_id = ?").bind(root).first();
  if (!rootRow || !ontologyWorkspaceAllowed(rootRow, expectedWorkspace)) throw new HttpError(404, "not_found", `Ontology entity not found: ${root}`);
  const nodes = new Map();
  const relations = new Map();
  const frontier = [[root, 0]];
  const visited = new Set([root]);
  while (frontier.length && nodes.size < limit) {
    const [current, distance] = frontier.shift();
    if (distance >= depth) continue;
    const clauses = ["(r.from_entity_id = ? OR r.to_entity_id = ?)"];
    const values = [current, current];
    if (expectedWorkspace) {
      clauses.push("r.workspace_id = ?", "f.workspace_id = ?", "t.workspace_id = ?");
      values.push(expectedWorkspace, expectedWorkspace, expectedWorkspace);
    }
    if (relationType) { clauses.push("r.relationship_type = ?"); values.push(relationType.toUpperCase()); }
    const joins = expectedWorkspace ? " JOIN ontology_entities f ON f.entity_id = r.from_entity_id JOIN ontology_entities t ON t.entity_id = r.to_entity_id" : "";
    const rows = await db.prepare(`SELECT r.* FROM ontology_relationships r${joins} WHERE ${clauses.join(" AND ")} ORDER BY r.updated_at DESC LIMIT ?`).bind(...values, limit).all();
    for (const row of rows.results || []) {
      const relation = publicOntologyRelationship(row);
      relations.set(relation.relationship_id, relation);
      const other = relation.from_entity_id === current ? relation.to_entity_id : relation.from_entity_id;
      if (other !== root && !nodes.has(other)) {
        const node = await db.prepare("SELECT * FROM ontology_entities WHERE entity_id = ?").bind(other).first();
        if (node && ontologyWorkspaceAllowed(node, expectedWorkspace)) nodes.set(other, publicOntologyEntity(node, false));
      }
      if (!visited.has(other) && visited.size < limit) { visited.add(other); frontier.push([other, distance + 1]); }
    }
  }
  return { schema_version: ONTOLOGY_SCHEMA_VERSION, entity_id: root, depth, nodes: [...nodes.values()], relationships: [...relations.values()] };
}

async function ontologyTimeline(db, entityId, searchParams, expectedWorkspace = "") {
  const normalized = clean(entityId, 512);
  const limit = boundedLimit(searchParams.get("limit"), 100, 500);
  const root = await db.prepare("SELECT workspace_id FROM ontology_entities WHERE entity_id = ?").bind(normalized).first();
  if (!root || !ontologyWorkspaceAllowed(root, expectedWorkspace)) throw new HttpError(404, "not_found", `Ontology entity not found: ${normalized}`);
  const events = await db.prepare("SELECT event_id, event_type, source, source_record_id, summary_json, occurred_at FROM ontology_events WHERE entity_id = ? ORDER BY occurred_at DESC, event_id DESC LIMIT ?").bind(normalized, limit).all();
  const relationSql = expectedWorkspace ? "SELECT r.relationship_id, r.relationship_type, r.from_entity_id, r.to_entity_id, r.source, r.source_record_id, r.properties_json, r.confidence, r.observed_at FROM ontology_relationships r JOIN ontology_entities f ON f.entity_id = r.from_entity_id JOIN ontology_entities t ON t.entity_id = r.to_entity_id WHERE (r.from_entity_id = ? OR r.to_entity_id = ?) AND r.workspace_id = ? AND f.workspace_id = ? AND t.workspace_id = ? ORDER BY r.observed_at DESC, r.relationship_id DESC LIMIT ?" : "SELECT relationship_id, relationship_type, from_entity_id, to_entity_id, source, source_record_id, properties_json, confidence, observed_at FROM ontology_relationships WHERE from_entity_id = ? OR to_entity_id = ? ORDER BY observed_at DESC, relationship_id DESC LIMIT ?";
  const relationships = expectedWorkspace ? await db.prepare(relationSql).bind(normalized, normalized, expectedWorkspace, expectedWorkspace, expectedWorkspace, limit).all() : await db.prepare(relationSql).bind(normalized, normalized, limit).all();
  const output = (events.results || []).map((row) => ({ event_id: row.event_id, event_type: row.event_type, source: row.source, source_record_id: row.source_record_id || "", summary: parseJson(row.summary_json, {}), occurred_at: row.occurred_at, kind: "event" }));
  output.push(...(relationships.results || []).map((row) => ({ event_id: row.relationship_id, event_type: row.relationship_type, source: row.source, source_record_id: row.source_record_id || "", summary: { from_entity_id: row.from_entity_id, to_entity_id: row.to_entity_id, confidence: Number(row.confidence || 0), ...parseJson(row.properties_json, {}) }, occurred_at: row.observed_at, kind: "relationship" })));
  output.sort((left, right) => String(right.occurred_at).localeCompare(String(left.occurred_at)));
  return { schema_version: ONTOLOGY_SCHEMA_VERSION, entity_id: normalized, events: output.slice(0, limit) };
}

async function ontologyLineage(db, entityId, searchParams, expectedWorkspace = "") {
  const depth = boundedInteger(searchParams.get("depth"), 2, 1, MAX_ONTOLOGY_DEPTH, "depth");
  const limit = boundedLimit(searchParams.get("limit"), 100, 500);
  const graph = await ontologyNeighbors(db, entityId, new URLSearchParams({ depth: String(depth), limit: String(limit) }), expectedWorkspace);
  const adjacency = new Map();
  for (const relation of graph.relationships) {
    if (!adjacency.has(relation.from_entity_id)) adjacency.set(relation.from_entity_id, []);
    if (!adjacency.has(relation.to_entity_id)) adjacency.set(relation.to_entity_id, []);
    adjacency.get(relation.from_entity_id).push(relation.to_entity_id);
    adjacency.get(relation.to_entity_id).push(relation.from_entity_id);
  }
  const paths = [];
  const queue = [[clean(entityId, 512), [clean(entityId, 512)]]];
  while (queue.length && paths.length < limit) {
    const [current, path] = queue.shift();
    if (path.length > 1) paths.push(path);
    if (path.length - 1 >= depth) continue;
    for (const next of adjacency.get(current) || []) if (!path.includes(next)) queue.push([next, [...path, next]]);
  }
  return { schema_version: ONTOLOGY_SCHEMA_VERSION, entity_id: clean(entityId, 512), depth, paths, nodes: graph.nodes, relationships: graph.relationships };
}

async function ontologyRisk(db, entityId, searchParams, expectedWorkspace = "") {
  const detail = await ontologyEntity(db, entityId, expectedWorkspace);
  const graph = await ontologyNeighbors(db, entityId, new URLSearchParams({ depth: "2", limit: "250" }), expectedWorkspace);
  const findingIds = new Set();
  if (detail.entity.entity_type === "finding") findingIds.add(detail.entity.entity_id);
  for (const node of graph.nodes) if (node.entity_type === "finding") findingIds.add(node.entity_id);
  const findings = [];
  const properties = detail.entity.properties && typeof detail.entity.properties === "object" ? detail.entity.properties : {};
  let severityScore = Number(properties.severity_score || 0);
  const severityValues = { critical: 95, high: 80, medium: 55, low: 25, info: 10 };
  for (const findingId of [...findingIds].slice(0, 100)) {
    const graphFinding = graph.nodes.find((node) => node.entity_id === findingId);
    const sourceFindingId = clean(graphFinding?.source_id || (findingId === detail.entity.entity_id ? detail.entity.source_id : ""), 512);
    let row = await db.prepare("SELECT payload_json FROM workspace_records WHERE record_type = 'findings' AND record_id = ? LIMIT 1").bind(findingId).first();
    if (!row && sourceFindingId && sourceFindingId !== findingId) {
      row = await db.prepare("SELECT payload_json FROM workspace_records WHERE record_type = 'findings' AND record_id = ? LIMIT 1").bind(sourceFindingId).first();
    }
    if (row) {
      const finding = parseJson(row.payload_json, {});
      findings.push({ finding_id: sourceFindingId || findingId, ontology_entity_id: findingId, ...finding });
      severityScore = Math.max(severityScore, Number(finding.severity_score || severityValues[String(finding.severity || "").toLowerCase()] || 0));
    }
  }
  const criticalityValues = { critical: 20, high: 12, medium: 6, low: 0, normal: 0 };
  const exploitabilityValues = { critical: 15, high: 12, medium: 7, low: 2 };
  const reachability = properties.internet_exposed ?? properties.internet_reachable;
  const reachabilityBonus = [true, "true", "yes", "public", "internet"].includes(typeof reachability === "string" ? reachability.toLowerCase() : reachability) ? 12 : 0;
  const criticalityBonus = criticalityValues[String(properties.asset_criticality || properties.criticality || "").toLowerCase()] || 0;
  const rawExploitability = properties.exploitability_score;
  const exploitabilityBonus = rawExploitability !== undefined && Number.isFinite(Number(rawExploitability))
    ? Math.max(0, Math.min(15, Math.round(Number(rawExploitability) * 1.5)))
    : (exploitabilityValues[String(properties.exploitability || "").toLowerCase()] || 0);
  const evidenceReferences = graph.relationships.filter((item) => item.evidence_ref_id).length;
  const evidenceQualityBonus = Math.min(10, evidenceReferences * 2);
  const riskScore = Math.max(0, Math.min(100, severityScore + criticalityBonus + exploitabilityBonus + reachabilityBonus + evidenceQualityBonus));
  const freshnessAt = detail.entity.freshness_at || detail.entity.last_seen_at;
  const freshnessStale = freshnessAt ? (Date.now() - Date.parse(freshnessAt)) > 7 * 24 * 60 * 60 * 1000 : true;
  return { schema_version: ONTOLOGY_SCHEMA_VERSION, entity_id: detail.entity.entity_id, entity: detail.entity, risk_score: riskScore, severity_score: severityScore, findings, related_entities: graph.nodes, relationships: graph.relationships, evidence_references: evidenceReferences, freshness_at: freshnessAt, freshness_stale: freshnessStale, risk_factors: { severity_score: severityScore, asset_criticality_bonus: criticalityBonus, exploitability_bonus: exploitabilityBonus, reachability_bonus: reachabilityBonus, evidence_quality_bonus: evidenceQualityBonus }, confidence: Math.min(detail.entity.confidence, ...graph.relationships.map((item) => item.confidence)), explanation: "Deterministic context from linked findings, relationships, evidence references, and freshness metadata.", recommended_next_step: riskScore >= 55 ? "Review the evidence and confirm ownership before proposing a reversible remediation." : "Continue collecting provenance and monitor the linked context before taking action.", action_contract: { mode: "proposal", reversible: true, approval_required: true, preconditions: ["evidence references are reviewed", "owner and workspace are confirmed"], rollback: "No change is applied until an operator approves a bounded remediation proposal." } };
}

async function ontologyQuality(db, searchParams, expectedWorkspace = "") {
  const requestedWorkspace = clean(searchParams.get("workspace_id"), 160);
  if (expectedWorkspace && requestedWorkspace && requestedWorkspace !== expectedWorkspace) throw new HttpError(403, "scope_mismatch", "Ontology workspace is not available to this Core instance");
  const workspace = requestedWorkspace || expectedWorkspace;
  const clause = workspace ? " WHERE workspace_id = ?" : "";
  const params = workspace ? [workspace] : [];
  const entities = await db.prepare(`SELECT COUNT(*) AS count FROM ontology_entities${clause}`).bind(...params).first();
  const relationships = await db.prepare(`SELECT COUNT(*) AS count FROM ontology_relationships${clause}`).bind(...params).first();
  const provenance = await db.prepare(`SELECT COUNT(*) AS count FROM ontology_relationships${clause}${workspace ? " AND" : " WHERE"} source <> 'unknown' AND source_record_id <> ''`).bind(...params).first();
  const evidence = await db.prepare(`SELECT COUNT(*) AS count FROM ontology_evidence_refs${workspace ? " WHERE workspace_id = ?" : ""}`).bind(...(workspace ? params : [])).first();
  const orphan = workspace
    ? await db.prepare("SELECT COUNT(*) AS count FROM ontology_relationships r WHERE r.workspace_id = ? AND (NOT EXISTS (SELECT 1 FROM ontology_entities e WHERE e.entity_id=r.from_entity_id AND e.workspace_id = ?) OR NOT EXISTS (SELECT 1 FROM ontology_entities e WHERE e.entity_id=r.to_entity_id AND e.workspace_id = ?))").bind(workspace, workspace, workspace).first()
    : await db.prepare("SELECT COUNT(*) AS count FROM ontology_relationships r WHERE NOT EXISTS (SELECT 1 FROM ontology_entities e WHERE e.entity_id=r.from_entity_id) OR NOT EXISTS (SELECT 1 FROM ontology_entities e WHERE e.entity_id=r.to_entity_id)").first();
  const orphanEntities = workspace
    ? await db.prepare("SELECT COUNT(*) AS count FROM ontology_entities e WHERE e.workspace_id = ? AND NOT EXISTS (SELECT 1 FROM ontology_relationships r JOIN ontology_entities other ON other.entity_id = CASE WHEN r.from_entity_id = e.entity_id THEN r.to_entity_id ELSE r.from_entity_id END WHERE (r.from_entity_id=e.entity_id OR r.to_entity_id=e.entity_id) AND r.workspace_id = ? AND other.workspace_id = ?)").bind(workspace, workspace, workspace).first()
    : await db.prepare("SELECT COUNT(*) AS count FROM ontology_entities e WHERE NOT EXISTS (SELECT 1 FROM ontology_relationships r WHERE r.from_entity_id=e.entity_id OR r.to_entity_id=e.entity_id)").first();
  const findings = await db.prepare(`SELECT COUNT(*) AS count FROM ontology_entities${clause}${workspace ? " AND" : " WHERE"} entity_type = 'finding'`).bind(...params).first();
  const linkedFindings = workspace
    ? await db.prepare("SELECT COUNT(*) AS count FROM ontology_entities e WHERE e.workspace_id = ? AND e.entity_type = 'finding' AND EXISTS (SELECT 1 FROM ontology_relationships r JOIN ontology_entities other ON other.entity_id = CASE WHEN r.from_entity_id=e.entity_id THEN r.to_entity_id ELSE r.from_entity_id END WHERE (r.from_entity_id=e.entity_id OR r.to_entity_id=e.entity_id) AND r.workspace_id = ? AND other.workspace_id = ? AND r.relationship_type IN ('FINDING_ON_VERSION','FINDING_ON_ASSET','CASE_GROUPS_FINDING','ALERT_DERIVED_FROM_FINDING'))").bind(workspace, workspace, workspace).first()
    : await db.prepare("SELECT COUNT(*) AS count FROM ontology_entities e WHERE e.entity_type = 'finding' AND EXISTS (SELECT 1 FROM ontology_relationships r WHERE (r.from_entity_id=e.entity_id OR r.to_entity_id=e.entity_id) AND r.relationship_type IN ('FINDING_ON_VERSION','FINDING_ON_ASSET','CASE_GROUPS_FINDING','ALERT_DERIVED_FROM_FINDING'))").first();
  const conflicts = await db.prepare("SELECT COUNT(*) AS count FROM ontology_conflicts WHERE status = 'open'").first();
  const changes = await db.prepare("SELECT COUNT(*) AS count FROM ontology_change_log").first();
  const relationshipsWithEvidence = await db.prepare(`SELECT COUNT(*) AS count FROM ontology_relationships${clause}${workspace ? " AND" : " WHERE"} evidence_ref_id IS NOT NULL AND evidence_ref_id <> ''`).bind(...params).first();
  // ``ontologySafeLocator`` uses both a bare redaction marker (for local
  // paths) and a marker with a digest (for URL credentials/private hosts).
  // Treat either form as redacted when reporting citation quality.
  const evidenceWithLocator = await db.prepare(`SELECT COUNT(*) AS count FROM ontology_evidence_refs WHERE locator <> '' AND locator NOT LIKE 'redacted://local%' AND locator NOT LIKE 'redacted://url%' AND locator NOT LIKE 'redacted://opaque%'${workspace ? " AND workspace_id = ?" : ""}`).bind(...(workspace ? params : [])).first();
  const staleRunnerHeartbeats = await db.prepare("SELECT COUNT(*) AS count FROM runner_heartbeats WHERE last_seen_at < ?").bind(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()).first();
  const heartbeatLatest = await db.prepare("SELECT MAX(last_seen_at) AS last_seen_at FROM runner_heartbeats").first();
  const canonicalEntities = await db.prepare(`SELECT COUNT(*) AS count FROM ontology_entities${clause}${workspace ? " AND" : " WHERE"} instr(entity_id, ':') > 0`).bind(...params).first();
  const connectedEntities = workspace
    ? await db.prepare("SELECT COUNT(*) AS count FROM ontology_entities e WHERE e.workspace_id = ? AND EXISTS (SELECT 1 FROM ontology_relationships r JOIN ontology_entities other ON other.entity_id = CASE WHEN r.from_entity_id=e.entity_id THEN r.to_entity_id ELSE r.from_entity_id END WHERE (r.from_entity_id=e.entity_id OR r.to_entity_id=e.entity_id) AND r.workspace_id = ? AND other.workspace_id = ?)").bind(workspace, workspace, workspace).first()
    : await db.prepare("SELECT COUNT(*) AS count FROM ontology_entities e WHERE EXISTS (SELECT 1 FROM ontology_relationships r WHERE r.from_entity_id=e.entity_id OR r.to_entity_id=e.entity_id)").first();
  const staleSources = await db.prepare(`SELECT COUNT(DISTINCT source) AS count FROM ontology_entities${clause}${workspace ? " AND" : " WHERE"} source <> '' AND freshness_at < ?`).bind(...params, new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString()).first();
  const queueRow = await db.prepare("SELECT MIN(queued_at) AS queued_at FROM (SELECT queued_at FROM intelligence_jobs WHERE status IN ('queued','running') UNION ALL SELECT queued_at FROM coordinator_commands WHERE status IN ('queued','running'))").first();
  const byType = await db.prepare(`SELECT entity_type, COUNT(*) AS count FROM ontology_entities${clause} GROUP BY entity_type`).bind(...params).all();
  const totalRelationships = Number(relationships?.count || 0);
  const withProvenance = Number(provenance?.count || 0);
  const findingTotal = Number(findings?.count || 0);
  const linkedFindingCount = Number(linkedFindings?.count || 0);
  const staleCutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  const stale = await db.prepare(`SELECT COUNT(*) AS count FROM ontology_entities${clause}${workspace ? " AND" : " WHERE"} freshness_at < ?`).bind(...params, staleCutoff).first();
  const queueAgeSeconds = queueRow?.queued_at ? Math.max(0, Math.floor((Date.now() - Date.parse(queueRow.queued_at)) / 1000)) : 0;
  const staleRunnerCount = Number(staleRunnerHeartbeats?.count || 0);
  const orphanEntityCount = Number(orphanEntities?.count || 0);
  const orphanRelationshipCount = Number(orphan?.count || 0);
  const qualityAlerts = [];
  if (staleRunnerCount) qualityAlerts.push({ code: "stale_runner_heartbeat", count: staleRunnerCount, threshold: 0 });
  if (queueAgeSeconds > 3600) qualityAlerts.push({ code: "queue_age_high", seconds: queueAgeSeconds, threshold: 3600 });
  if (orphanEntityCount || orphanRelationshipCount) qualityAlerts.push({ code: "orphaned_graph_records", entities: orphanEntityCount, relationships: orphanRelationshipCount, threshold: 0 });
  if (totalRelationships && (withProvenance / totalRelationships) < 0.9) qualityAlerts.push({ code: "provenance_coverage_low", percent: Math.round((withProvenance / totalRelationships) * 100) / 100, threshold: 90 });
  const entityTotal = Number(entities?.count || 0);
  const canonicalEntityCount = Number(canonicalEntities?.count || 0);
  const connectedEntityCount = Number(connectedEntities?.count || 0);
  const graphCoverage = entityTotal ? Math.round(((entityTotal - orphanEntityCount) / entityTotal) * 10000) / 100 : 100;
  const duplicateConflicts = Number((await db.prepare("SELECT COUNT(*) AS count FROM ontology_conflicts WHERE status = 'open' AND conflict_type IN ('duplicate_alias','duplicate_identity')").first())?.count || 0);
  const contradictoryRelationships = Number((await db.prepare("SELECT COUNT(*) AS count FROM ontology_conflicts WHERE status = 'open' AND conflict_type IN ('source_contradiction','contradictory_relationship')").first())?.count || 0);
  const heartbeatFreshnessSeconds = heartbeatLatest?.last_seen_at ? Math.max(0, Math.floor((Date.now() - Date.parse(heartbeatLatest.last_seen_at)) / 1000)) : null;
  const heartbeatMeasurementStatus = heartbeatFreshnessSeconds === null ? "unknown" : (staleRunnerCount ? "stale" : "fresh");
  return { schema_version: ONTOLOGY_SCHEMA_VERSION, workspace_id: workspace || "all", entities: entityTotal, relationships: totalRelationships, evidence_references: Number(evidence?.count || 0), relationships_with_provenance: withProvenance, relationships_with_evidence: Number(relationshipsWithEvidence?.count || 0), provenance_coverage_percent: totalRelationships ? Math.round((withProvenance / totalRelationships) * 10000) / 100 : null, evidence_with_valid_locator: Number(evidenceWithLocator?.count || 0), orphan_relationships: orphanRelationshipCount, orphan_entities: orphanEntityCount, stale_entities: Number(stale?.count || 0), stale_runner_heartbeats: staleRunnerCount, heartbeat_freshness_seconds: heartbeatFreshnessSeconds, heartbeat_measurement_status: heartbeatMeasurementStatus, queue_age_seconds: queueAgeSeconds, quality_alerts: qualityAlerts, stale_after_seconds: 7 * 24 * 60 * 60, canonical_id_coverage_percent: entityTotal ? Math.round((canonicalEntityCount / entityTotal) * 10000) / 100 : null, graph_coverage_percent: entityTotal ? Math.round((connectedEntityCount / entityTotal) * 10000) / 100 : null, findings_total: findingTotal, findings_linked_percent: findingTotal ? Math.round((linkedFindingCount / findingTotal) * 10000) / 100 : null, open_conflicts: Number(conflicts?.count || 0), duplicate_candidates: duplicateConflicts, contradictory_relationships: contradictoryRelationships, stale_sources: Number(staleSources?.count || 0), ai_evidence_completeness_percent: null, false_positive_rate: null, recommendation_acceptance_rate: null, action_completion_rate: null, action_rollback_rate: null, change_history_records: Number(changes?.count || 0), entities_by_type: Object.fromEntries((byType.results || []).map((row) => [row.entity_type, Number(row.count || 0)])) };
}

function ontologyWriteStatementEstimate(entities, evidenceRefs, relationships, events) {
  // Each entity always emits its row and one change-log row.  Aliases emit one
  // alias or conflict row each.  Relationships emit their row and change-log
  // row; evidence and events emit one row each.  The receipt is part of the
  // same atomic batch. Keep this estimate in lockstep with queueWrite below so
  // an oversized batch is rejected before any D1 read or write.
  let statements = 1;
  for (const item of entities) {
    statements += 2;
    for (const alias of (Array.isArray(item?.aliases) ? item.aliases : []).slice(0, 20)) {
      const aliasValue = clean(typeof alias === "object" && alias ? alias.value : alias, 512);
      if (aliasValue) statements += 1;
    }
  }
  statements += evidenceRefs.length;
  statements += relationships.length * 2;
  statements += events.length;
  return statements;
}

function ontologyReadBudget(maximum) {
  let used = 0;
  return {
    get used() { return used; },
    async first(statement) {
      if (used >= maximum) {
        throw new HttpError(413, "d1_query_budget_exceeded", "Ontology synchronization exceeds the D1 read-query budget; retry with a smaller chunk");
      }
      used += 1;
      return statement.first();
    },
  };
}

async function syncOntology(request, env, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Ontology synchronization");
  const entities = payload.entities || [];
  const relationships = payload.relationships || [];
  const events = payload.events || [];
  const evidenceRefs = payload.evidence_refs || [];
  if (!Array.isArray(entities) || !Array.isArray(relationships) || !Array.isArray(events) || !Array.isArray(evidenceRefs)) throw new HttpError(422, "invalid_payload", "entities, relationships, events, and evidence_refs must be arrays");
  if (entities.length > MAX_ONTOLOGY_ENTITIES || relationships.length > MAX_ONTOLOGY_RELATIONSHIPS || events.length > MAX_ONTOLOGY_EVENTS || evidenceRefs.length > MAX_ONTOLOGY_EVIDENCE_REFS) throw new HttpError(413, "payload_too_large", "Ontology synchronization batch exceeds its bounded limit");
  if (ontologyWriteStatementEstimate(entities, evidenceRefs, relationships, events) > MAX_ONTOLOGY_D1_BATCH_STATEMENTS) {
    throw new HttpError(413, "payload_too_large", "Ontology synchronization batch exceeds the D1 statement limit; retry with a smaller chunk");
  }
  const schemaVersion = clean(payload.schema_version || ONTOLOGY_SCHEMA_VERSION, 80) || ONTOLOGY_SCHEMA_VERSION;
  if (schemaVersion !== ONTOLOGY_SCHEMA_VERSION) throw new HttpError(422, "invalid_schema", `Unsupported ontology schema version: ${schemaVersion}`);
  const headerIdempotency = clean(request.headers.get("Idempotency-Key"), 200);
  const bodyIdempotency = clean(payload.idempotency_key, 200);
  if (headerIdempotency && bodyIdempotency && headerIdempotency !== bodyIdempotency) {
    throw new HttpError(422, "invalid_idempotency_key", "Idempotency-Key header and body value must match");
  }
  const suppliedIdempotency = headerIdempotency || bodyIdempotency;
  if (suppliedIdempotency && !/^[A-Za-z0-9._:-]{8,200}$/.test(suppliedIdempotency)) {
    throw new HttpError(422, "invalid_idempotency_key", "Idempotency-Key must be 8-200 ASCII letters, digits, '.', '_', ':' or '-'");
  }
  const requestHash = await sha256Hex(JSON.stringify({
    schema_version: schemaVersion,
    source_instance: payload.source_instance || "ontology-bridge",
    organization_id: payload.organization_id || "",
    workspace_id: payload.workspace_id || "",
    entities, relationships, events, evidence_refs: evidenceRefs,
  }));
  const idempotencyKey = suppliedIdempotency || requestHash;
  const expectedOrganization = clean(env.CORE_ORGANIZATION_ID, 160);
  const expectedWorkspace = clean(env.CORE_WORKSPACE_ID, 160);
  // D1 Free permits at most 50 read queries per Worker invocation. Count all
  // ontology preflight/construction reads, including the receipt lookup, so a
  // paid-plan request cannot accidentally exceed the portable Free budget.
  const readBudget = ontologyReadBudget(MAX_ONTOLOGY_D1_READ_QUERIES);
  // A retry after a network timeout must return the original bounded receipt
  // without replaying change-log writes.  The table is created by migration
  // 0005; a missing table is surfaced as a normal D1 failure for rollout
  // visibility rather than silently weakening idempotency.
  const previousReceipt = await readBudget.first(env.DB.prepare("SELECT response_json, request_hash FROM ontology_ingest_receipts WHERE idempotency_key = ?").bind(idempotencyKey));
  if (previousReceipt) {
    if (previousReceipt.request_hash && previousReceipt.request_hash !== requestHash) throw new HttpError(409, "idempotency_conflict", "Idempotency-Key was already used for a different ontology payload");
    const previous = parseJson(previousReceipt.response_json, {});
    await writeAudit(env.DB, { requestId, action: "ontology.sync", actorRole: "intelligence_bridge", result: "idempotent", sourceInstance: clean(payload.source_instance, 160) || "ontology-bridge", details: { idempotency_key: idempotencyKey, counts: previous.counts || {} }, createdAt: nowIso() });
    return { ...previous, idempotent: true, idempotency_key: idempotencyKey };
  }
  for (const key of ["organization_id", "workspace_id"]) {
    const expected = key === "organization_id" ? expectedOrganization : expectedWorkspace;
    const supplied = clean(payload[key], 160);
    if (expected && supplied && supplied !== expected) throw new HttpError(403, "scope_mismatch", `Ontology ${key} does not match this Core workspace`);
  }
  // Validate the complete batch before the first write.  D1 statements are
  // asynchronous and a malformed item late in a batch would otherwise leave
  // a partially applied snapshot.  This preflight also detects duplicate
  // canonical identities and unknown relationship/event endpoints up front.
  const preflightEntityIds = new Set();
  const preflightEntityWorkspaces = new Map();
  const preflightCanonical = new Map();
  const preflightCanonicalRows = new Map();
  const preflightAliasRows = new Map();
  const preflightEntityRows = new Map();
  const preflightEntityChanges = new Map();
  for (const item of entities) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new HttpError(422, "invalid_entity", "Ontology entity must be an object");
    preflightBoundedJson(item.properties || {}, 64 * 1024, "Ontology properties");
    const type = ontologyEntityType(item.entity_type || item.type);
    const namespace = ontologyNormalize(item.namespace || item.ecosystem || "global", 120) || "global";
    let entityWorkspace = ontologyWorkspace(item.workspace_id, expectedWorkspace);
    if (expectedOrganization && clean(item.organization_id, 160) && clean(item.organization_id, 160) !== expectedOrganization) throw new HttpError(403, "scope_mismatch", "Ontology record organization does not match this Core instance");
    if (expectedWorkspace && entityWorkspace !== expectedWorkspace && entityWorkspace !== "local") throw new HttpError(403, "scope_mismatch", "Ontology record workspace does not match this Core workspace");
    const rawCanonicalValue = item.canonical_key || item.key || item.source_id || item.entity_id;
    if (type === "package_version" && !ontologyNormalize(rawCanonicalValue, 4096).includes("@")) throw new HttpError(422, "invalid_entity", "package_version canonical_key must include package@version");
    const canonicalKey = await ontologyCanonicalKey(type, namespace, rawCanonicalValue);
    if (!canonicalKey) throw new HttpError(422, "invalid_entity", "Ontology canonical_key is required");
    const rawExplicitEntityId = String(item.entity_id || "").trim();
    if (rawExplicitEntityId && new TextEncoder().encode(rawExplicitEntityId).byteLength > 512) throw new HttpError(422, "invalid_entity", "Ontology entity_id must be a namespaced stable identifier no longer than 512 bytes");
    const explicitEntityId = clean(rawExplicitEntityId, 512);
    if (explicitEntityId && (!explicitEntityId.includes(":") || explicitEntityId.length > 512)) throw new HttpError(422, "invalid_entity", "Ontology entity_id must be a namespaced stable identifier");
    const entityId = explicitEntityId || await ontologyEntityId(type, namespace, canonicalKey);
    if (preflightEntityIds.has(entityId)) throw new HttpError(409, "identity_conflict", `Ontology batch contains duplicate entity: ${entityId}`);
    const canonicalIdentity = `${type}:${namespace}:${canonicalKey}`;
    const priorBatchEntity = preflightCanonical.get(canonicalIdentity);
    if (priorBatchEntity && priorBatchEntity !== entityId) throw new HttpError(409, "identity_conflict", `Ontology batch contains duplicate canonical identity: ${canonicalKey}`);
    preflightEntityIds.add(entityId);
    preflightCanonical.set(canonicalIdentity, entityId);
    const existing = await readBudget.first(env.DB.prepare("SELECT * FROM ontology_entities WHERE entity_id = ?").bind(entityId));
    if (existing?.workspace_id && existing.workspace_id !== "local" && entityWorkspace !== "local" && existing.workspace_id !== entityWorkspace) throw new HttpError(403, "scope_mismatch", "Ontology entity belongs to a different workspace");
    if (existing?.workspace_id && existing.workspace_id !== "local" && entityWorkspace === "local") entityWorkspace = clean(existing.workspace_id, 160) || entityWorkspace;
    if (explicitEntityId && existing && (
      String(existing.entity_type || "") !== type
      || String(existing.namespace || "") !== namespace
      || String(existing.canonical_key || "") !== canonicalKey
    )) {
      throw new HttpError(409, "entity_identity_conflict", "An explicit entity_id cannot be rewired to a different type, namespace, or canonical key");
    }
    // Both the incoming and retained entity properties are bounded before any
    // entity write.  A higher-priority existing source may cause the stored
    // properties to come from D1 rather than this request.
    preflightBoundedJson(existing ? parseJson(existing.properties_json, {}) : {}, 64 * 1024, "Ontology properties");
    const entitySource = ontologySource(item.source || "unknown") || "unknown";
    const preserve = existing && ontologySourcePriority(existing.source) > ontologySourcePriority(entitySource);
    const entityProperties = preserve ? parseJson(existing.properties_json, {}) : (item.properties || {});
    const entityPropertiesJson = preflightBoundedJson(entityProperties, 64 * 1024, "Ontology properties");
    const entityChangeBeforeJson = preflightBoundedJson(ontologyEntityChangeProjection(existing), MAX_SUMMARY_BYTES, "Ontology change");
    const entityChangeAfterJson = preflightBoundedJson({ entity_id: entityId, entity_type: type, namespace, canonical_key: canonicalKey, source: preserve ? existing.source : entitySource, workspace_id: entityWorkspace }, MAX_SUMMARY_BYTES, "Ontology change");
    preflightEntityChanges.set(entityId, { beforeJson: entityChangeBeforeJson, afterJson: entityChangeAfterJson, propertiesJson: entityPropertiesJson, changeId: `chg:${(await sha256Hex(`entity|${entityId}|upsert|${entityChangeAfterJson}`)).slice(0, 40)}` });
    preflightEntityRows.set(entityId, existing || null);
    preflightEntityWorkspaces.set(entityId, entityWorkspace);
    const canonicalExisting = await readBudget.first(env.DB.prepare("SELECT entity_id FROM ontology_entities WHERE entity_type = ? AND namespace = ? AND canonical_key = ? LIMIT 1").bind(type, namespace, canonicalKey));
    if (canonicalExisting && canonicalExisting.entity_id !== entityId) throw new HttpError(409, "identity_conflict", `Canonical identity already belongs to ${canonicalExisting.entity_id}`);
    preflightCanonicalRows.set(canonicalIdentity, canonicalExisting || null);
    for (const alias of (Array.isArray(item.aliases) ? item.aliases : []).slice(0, 20)) {
      const aliasValue = clean(typeof alias === "object" && alias ? alias.value : alias, 512);
      if (!aliasValue) continue;
      const aliasType = clean(typeof alias === "object" && alias ? alias.type : "source", 80) || "source";
      const normalized = ontologyNormalize(aliasValue, 512);
      const aliasSource = ontologySource(typeof alias === "object" && alias ? (alias.source || entitySource) : entitySource) || "unknown";
      const aliasKey = `${aliasType}|${normalized}|${aliasSource}`;
      if (!preflightAliasRows.has(aliasKey)) {
        const incumbent = await readBudget.first(env.DB.prepare("SELECT alias_id, entity_id FROM ontology_aliases WHERE alias_type = ? AND normalized_value = ? AND source = ? LIMIT 1").bind(aliasType, normalized, aliasSource));
        preflightAliasRows.set(aliasKey, incumbent || null);
      }
    }
  }
  const preflightEvidenceIds = new Set();
  const preflightEvidenceWorkspaces = new Map();
  const preflightEvidenceRows = new Map();
  const preflightExternalEntityRows = new Map();
  const preflightExternalEvidenceRows = new Map();
  const preflightEvidenceRecords = [];
  for (const item of evidenceRefs) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new HttpError(422, "invalid_evidence_ref", "Ontology evidence_ref must be an object");
    const summaryJson = preflightBoundedJson(item.summary || {}, MAX_SUMMARY_BYTES, "Ontology evidence summary");
    const source = ontologySource(item.source || "unknown") || "unknown";
    if (expectedOrganization && clean(item.organization_id, 160) && clean(item.organization_id, 160) !== expectedOrganization) throw new HttpError(403, "scope_mismatch", "Ontology evidence organization does not match this Core instance");
    const locator = await ontologySafeLocator(item.locator || item.uri || item.source_id);
    if (!locator) throw new HttpError(422, "invalid_evidence_ref", "Ontology evidence locator is required");
    const contentHash = clean(item.content_hash || item.sha256, 128);
    let evidenceWorkspace = ontologyWorkspace(item.workspace_id, expectedWorkspace);
    if (expectedWorkspace && evidenceWorkspace !== expectedWorkspace && evidenceWorkspace !== "local") throw new HttpError(403, "scope_mismatch", "Ontology evidence workspace does not match this Core workspace");
    const evidenceId = clean(item.evidence_ref_id, 512) || `eref:${(await sha256Hex(`${source}|${locator}|${contentHash}`)).slice(0, 40)}`;
    const existingEvidence = await readBudget.first(env.DB.prepare("SELECT workspace_id FROM ontology_evidence_refs WHERE evidence_ref_id = ?").bind(evidenceId));
    if (existingEvidence?.workspace_id && existingEvidence.workspace_id !== "local" && evidenceWorkspace !== "local" && existingEvidence.workspace_id !== evidenceWorkspace) throw new HttpError(403, "scope_mismatch", "Ontology evidence reference belongs to a different workspace");
    if (existingEvidence?.workspace_id && existingEvidence.workspace_id !== "local" && evidenceWorkspace === "local") evidenceWorkspace = clean(existingEvidence.workspace_id, 160) || evidenceWorkspace;
    preflightEvidenceIds.add(evidenceId);
    preflightEvidenceWorkspaces.set(evidenceId, evidenceWorkspace);
    preflightEvidenceRows.set(evidenceId, existingEvidence || null);
    preflightEvidenceRecords.push({
      source,
      locator,
      contentHash,
      evidenceId,
      evidenceWorkspace,
      summaryJson,
      contentType: clean(item.content_type, 120),
      observedAt: clean(item.observed_at || "", 64),
    });
  }
  const lookupExternalEntity = async (entityId) => {
    if (preflightExternalEntityRows.has(entityId)) return preflightExternalEntityRows.get(entityId);
    const row = await readBudget.first(env.DB.prepare("SELECT workspace_id FROM ontology_entities WHERE entity_id=?").bind(entityId));
    preflightExternalEntityRows.set(entityId, row || null);
    return row || null;
  };
  const lookupExternalEvidence = async (evidenceId) => {
    if (preflightExternalEvidenceRows.has(evidenceId)) return preflightExternalEvidenceRows.get(evidenceId);
    const row = await readBudget.first(env.DB.prepare("SELECT workspace_id FROM ontology_evidence_refs WHERE evidence_ref_id=?").bind(evidenceId));
    preflightExternalEvidenceRows.set(evidenceId, row || null);
    return row || null;
  };
  const preflightRelationshipRecords = [];
  for (let index = 0; index < relationships.length; index += 1) {
    const item = relationships[index];
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new HttpError(422, "invalid_relationship", "Ontology relationship must be an object");
    const relation = ontologyRelationType(item.relationship_type || item.type);
    const propertiesJson = preflightBoundedJson(item.properties || {}, MAX_SUMMARY_BYTES, "Ontology relationship properties");
    const from = clean(item.from_entity_id || item.from, 512);
    const to = clean(item.to_entity_id || item.to, 512);
    if (!from || !to || from === to) throw new HttpError(422, "invalid_relationship", "Ontology relationships require distinct endpoints");
    const fromRow = preflightEntityWorkspaces.has(from)
      ? { workspace_id: preflightEntityWorkspaces.get(from) }
      : await lookupExternalEntity(from);
    const toRow = preflightEntityWorkspaces.has(to)
      ? { workspace_id: preflightEntityWorkspaces.get(to) }
      : await lookupExternalEntity(to);
    if (!fromRow) throw new HttpError(422, "invalid_relationship", `Unknown relationship source entity: ${from}`);
    if (!toRow) throw new HttpError(422, "invalid_relationship", `Unknown relationship target entity: ${to}`);
    const relationshipWorkspace = ontologyWorkspace(item.workspace_id, expectedWorkspace || fromRow?.workspace_id || "hosted");
    const source = ontologySource(item.source || "unknown") || "unknown";
    const sourceRecord = clean(item.source_record_id || item.source_id, 512);
    if (expectedOrganization && clean(item.organization_id, 160) && clean(item.organization_id, 160) !== expectedOrganization) throw new HttpError(403, "scope_mismatch", "Ontology relationship organization does not match this Core instance");
    if (expectedWorkspace && relationshipWorkspace !== expectedWorkspace && relationshipWorkspace !== "local") throw new HttpError(403, "scope_mismatch", "Ontology relationship workspace does not match this Core workspace");
    if (relationshipWorkspace !== "local" && [fromRow?.workspace_id, toRow?.workspace_id].some((scope) => scope && scope !== relationshipWorkspace && scope !== "local")) throw new HttpError(403, "scope_mismatch", "Ontology relationship endpoints belong to a different workspace");
    const evidenceRefId = clean(item.evidence_ref_id, 512);
    const externalEvidence = evidenceRefId && !preflightEvidenceIds.has(evidenceRefId) ? await lookupExternalEvidence(evidenceRefId) : null;
    if (evidenceRefId && !preflightEvidenceIds.has(evidenceRefId) && !externalEvidence) throw new HttpError(422, "invalid_relationship", `Unknown relationship evidence reference: ${evidenceRefId}`);
    if (evidenceRefId) {
      const evidenceRow = preflightEvidenceWorkspaces.has(evidenceRefId)
        ? { workspace_id: preflightEvidenceWorkspaces.get(evidenceRefId) }
        : externalEvidence;
      const evidenceWorkspace = clean(evidenceRow?.workspace_id, 160) || "local";
      if (evidenceWorkspace !== "local" && relationshipWorkspace !== "local" && evidenceWorkspace !== relationshipWorkspace) throw new HttpError(403, "scope_mismatch", "Ontology relationship evidence belongs to a different workspace");
      if (evidenceWorkspace !== "local" && relationshipWorkspace === "local" && [fromRow?.workspace_id, toRow?.workspace_id].some((scope) => scope && scope !== evidenceWorkspace && scope !== "local")) throw new HttpError(403, "scope_mismatch", "Ontology relationship evidence endpoints belong to a different workspace");
    }
    const relationId = `rel:${(await sha256Hex(`${relation}|${from}|${to}|${source}|${sourceRecord}`)).slice(0, 40)}`;
    const confidence = ontologyConfidence(item.confidence);
    const observedAt = clean(item.observed_at, 64);
    const validFrom = clean(item.valid_from, 64) || null;
    const validTo = clean(item.valid_to, 64) || null;
    const freshnessAt = clean(item.freshness_at || item.observed_at, 64);
    const existingRelationship = await readBudget.first(env.DB.prepare("SELECT relationship_type, from_entity_id, to_entity_id, source, source_record_id, workspace_id FROM ontology_relationships WHERE relationship_id = ?").bind(relationId));
    if (existingRelationship?.workspace_id && existingRelationship.workspace_id !== "local" && relationshipWorkspace !== "local" && existingRelationship.workspace_id !== relationshipWorkspace) throw new HttpError(403, "scope_mismatch", "Ontology relationship belongs to a different workspace");
    if (existingRelationship && (existingRelationship.relationship_type !== relation || existingRelationship.from_entity_id !== from || existingRelationship.to_entity_id !== to || existingRelationship.source !== source || String(existingRelationship.source_record_id || "") !== sourceRecord)) {
      throw new HttpError(409, "relationship_identity_conflict", "A relationship_id cannot be rewired or change type/source identity");
    }
    const relationshipChangeAfterJson = preflightBoundedJson({ relationship_id: relationId, relationship_type: relation, from_entity_id: from, to_entity_id: to, source, source_record_id: sourceRecord, workspace_id: relationshipWorkspace }, MAX_SUMMARY_BYTES, "Ontology change");
    preflightRelationshipRecords.push({ relation, from, to, source, sourceRecord, relationshipWorkspace, evidenceRefId, relationId, propertiesJson, confidence, observedAt, validFrom, validTo, freshnessAt, relationshipChangeAfterJson, changeId: `chg:${(await sha256Hex(`relationship|${relationId}|upsert|${relationshipChangeAfterJson}`)).slice(0, 40)}` });
  }
  const preflightEventRecords = [];
  for (const item of events) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new HttpError(422, "invalid_event", "Ontology event must be an object");
    const summaryJson = preflightBoundedJson(item.summary || {}, MAX_SUMMARY_BYTES, "Ontology event summary");
    const entityId = clean(item.entity_id, 512);
    const externalEventEntity = entityId && !preflightEntityIds.has(entityId) ? await lookupExternalEntity(entityId) : null;
    if (!entityId || (!preflightEntityIds.has(entityId) && !externalEventEntity)) throw new HttpError(422, "invalid_event", `Unknown event entity: ${entityId}`);
    const eventType = clean(item.event_type || "observed", 120) || "observed";
    const source = ontologySource(item.source || "unknown") || "unknown";
    const sourceRecord = clean(item.source_record_id || item.source_id, 512);
    const eventWorkspace = ontologyWorkspace(item.workspace_id, expectedWorkspace || preflightEntityWorkspaces.get(entityId) || "hosted");
    if (expectedOrganization && clean(item.organization_id, 160) && clean(item.organization_id, 160) !== expectedOrganization) throw new HttpError(403, "scope_mismatch", "Ontology event organization does not match this Core instance");
    if (expectedWorkspace && eventWorkspace !== expectedWorkspace && eventWorkspace !== "local") throw new HttpError(403, "scope_mismatch", "Ontology event workspace does not match this Core workspace");
    if (eventWorkspace !== "local") {
      const eventEntity = preflightEntityWorkspaces.has(entityId)
        ? { workspace_id: preflightEntityWorkspaces.get(entityId) }
        : externalEventEntity;
      if (eventEntity?.workspace_id && eventEntity.workspace_id !== eventWorkspace && eventEntity.workspace_id !== "local") throw new HttpError(403, "scope_mismatch", "Ontology event entity belongs to a different workspace");
    }
    // ``now`` is a transport timestamp and would give the same replay a new
    // event identity. Use producer observation/creation time when present,
    // then a fixed epoch so omission remains deterministic.
    const occurredAt = clean(item.occurred_at || item.observed_at || item.created_at || "1970-01-01T00:00:00Z", 64) || "1970-01-01T00:00:00Z";
    // Event identity likewise ignores transport/request identifiers so a
    // replay with a different event_id remains a semantic upsert.
    const eventId = `event:${(await sha256Hex(`${entityId}|${eventType}|${source}|${sourceRecord}|${occurredAt}`)).slice(0, 40)}`;
    preflightEventRecords.push({ entityId, eventType, source, sourceRecord, eventWorkspace, occurredAt, eventId, summaryJson });
  }
  const result = { status: "accepted", schema_version: ONTOLOGY_SCHEMA_VERSION, counts: { entities: entities.length, relationships: relationships.length, events: events.length, evidence_refs: evidenceRefs.length }, idempotency_key: idempotencyKey };
  const resultJson = preflightBoundedJson(result, 32768, "Ontology ingest receipt");
  const now = nowIso();
  // D1 batches are transactional: if any prepared write fails, Cloudflare
  // rolls back the complete batch.  Build every mutation only after the
  // preflight above has succeeded so a malformed late record cannot leave a
  // partially materialized ontology snapshot.
  const writeStatements = [];
  const queueWrite = (sql, ...values) => {
    writeStatements.push(env.DB.prepare(sql).bind(...values));
  };
  const entityIds = new Set();
  for (const item of entities) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new HttpError(422, "invalid_entity", "Ontology entity must be an object");
    const type = ontologyEntityType(item.entity_type || item.type);
    const namespace = ontologyNormalize(item.namespace || item.ecosystem || "global", 120) || "global";
    let entityWorkspace = ontologyWorkspace(item.workspace_id, expectedWorkspace);
    if (expectedOrganization && clean(item.organization_id, 160) && clean(item.organization_id, 160) !== expectedOrganization) throw new HttpError(403, "scope_mismatch", "Ontology record organization does not match this Core instance");
    if (expectedWorkspace && entityWorkspace !== expectedWorkspace && entityWorkspace !== "local") throw new HttpError(403, "scope_mismatch", "Ontology record workspace does not match this Core workspace");
    const rawCanonicalValue = item.canonical_key || item.key || item.source_id || item.entity_id;
    if (type === "package_version" && !ontologyNormalize(rawCanonicalValue, 4096).includes("@")) throw new HttpError(422, "invalid_entity", "package_version canonical_key must include package@version");
    const canonicalKey = await ontologyCanonicalKey(type, namespace, rawCanonicalValue);
    if (!canonicalKey) throw new HttpError(422, "invalid_entity", "Ontology canonical_key is required");
    const rawExplicitEntityId = String(item.entity_id || "").trim();
    if (rawExplicitEntityId && new TextEncoder().encode(rawExplicitEntityId).byteLength > 512) throw new HttpError(422, "invalid_entity", "Ontology entity_id must be a namespaced stable identifier no longer than 512 bytes");
    const explicitEntityId = clean(rawExplicitEntityId, 512);
    if (explicitEntityId && (!explicitEntityId.includes(":") || explicitEntityId.length > 512)) throw new HttpError(422, "invalid_entity", "Ontology entity_id must be a namespaced stable identifier");
    const entityId = explicitEntityId || await ontologyEntityId(type, namespace, canonicalKey);
    if (!item.workspace_id && !expectedWorkspace && preflightEntityWorkspaces.has(entityId)) entityWorkspace = preflightEntityWorkspaces.get(entityId) || entityWorkspace;
    entityIds.add(entityId);
    const firstSeen = clean(item.first_seen_at || item.first_seen || item.observed_at || now, 64);
    const lastSeen = clean(item.last_seen_at || item.last_seen || item.observed_at || now, 64);
    const source = ontologySource(item.source || "unknown") || "unknown";
    const existing = preflightEntityRows.has(entityId)
      ? preflightEntityRows.get(entityId)
      : await readBudget.first(env.DB.prepare("SELECT * FROM ontology_entities WHERE entity_id = ?").bind(entityId));
    if (existing?.workspace_id && existing.workspace_id !== "local" && entityWorkspace !== "local" && existing.workspace_id !== entityWorkspace) throw new HttpError(403, "scope_mismatch", "Ontology entity belongs to a different workspace");
    if (existing?.workspace_id && existing.workspace_id !== "local" && entityWorkspace === "local") entityWorkspace = clean(existing.workspace_id, 160) || entityWorkspace;
    const canonicalExisting = preflightCanonicalRows.get(`${type}:${namespace}:${canonicalKey}`) || null;
    if (canonicalExisting && canonicalExisting.entity_id !== entityId) throw new HttpError(409, "identity_conflict", `Canonical identity already belongs to ${canonicalExisting.entity_id}`);
    const preserve = existing && ontologySourcePriority(existing.source) > ontologySourcePriority(source);
    const entityDisplayName = clean(preserve ? existing.display_name : (item.display_name || item.label || canonicalKey), 512);
    const entitySourceId = clean(item.source_id, 512) || (preserve ? clean(existing.source_id, 512) : "");
    const entityOwnerId = clean(item.owner_id || item.owner, 256) || (preserve ? clean(existing.owner_id, 256) : "");
    const entityStatus = preserve ? (clean(existing.status, 80) || "active") : (clean(item.status || "active", 80) || "active");
    const entityChange = preflightEntityChanges.get(entityId);
    if (!entityChange) throw new HttpError(422, "invalid_entity", "Ontology entity preflight did not produce a change envelope");
    queueWrite(`INSERT INTO ontology_entities
      (entity_id, entity_type, namespace, canonical_key, display_name, source, source_id, workspace_id, owner_id, status, properties_json, confidence, first_seen_at, last_seen_at, observed_at, freshness_at, valid_from, valid_to, schema_version, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(entity_id) DO UPDATE SET entity_type=excluded.entity_type, namespace=excluded.namespace, canonical_key=excluded.canonical_key, display_name=excluded.display_name, source=excluded.source, source_id=CASE WHEN excluded.source_id <> '' THEN excluded.source_id ELSE ontology_entities.source_id END, workspace_id=excluded.workspace_id, owner_id=CASE WHEN excluded.owner_id <> '' THEN excluded.owner_id ELSE ontology_entities.owner_id END, status=excluded.status, properties_json=excluded.properties_json, confidence=excluded.confidence, first_seen_at=CASE WHEN excluded.first_seen_at < ontology_entities.first_seen_at THEN excluded.first_seen_at ELSE ontology_entities.first_seen_at END, last_seen_at=CASE WHEN excluded.last_seen_at > ontology_entities.last_seen_at THEN excluded.last_seen_at ELSE ontology_entities.last_seen_at END, observed_at=excluded.observed_at, freshness_at=excluded.freshness_at, valid_from=COALESCE(excluded.valid_from, ontology_entities.valid_from), valid_to=COALESCE(excluded.valid_to, ontology_entities.valid_to), schema_version=excluded.schema_version, updated_at=excluded.updated_at`, entityId, type, namespace, canonicalKey, entityDisplayName, preserve ? existing.source : source, entitySourceId, entityWorkspace, entityOwnerId, entityStatus, entityChange.propertiesJson, ontologyConfidence(item.confidence), firstSeen, lastSeen, clean(item.observed_at || lastSeen, 64), clean(item.freshness_at || lastSeen, 64), clean(item.valid_from, 64) || null, clean(item.valid_to, 64) || null, ONTOLOGY_SCHEMA_VERSION, now, now);
    queueWrite(`INSERT OR IGNORE INTO ontology_change_log (change_id, object_type, object_id, action, before_json, after_json, source, actor, occurred_at)
      VALUES (?, 'entity', ?, 'upsert', ?, ?, ?, ?, ?)`,
      entityChange.changeId,
      entityId,
      entityChange.beforeJson,
      entityChange.afterJson,
      source,
      clean(payload.source_instance || "ontology-bridge", 160) || "ontology-bridge",
      now);
    for (const alias of (Array.isArray(item.aliases) ? item.aliases : []).slice(0, 20)) {
      const aliasValue = clean(typeof alias === "object" && alias ? alias.value : alias, 512);
      if (!aliasValue) continue;
      const aliasType = clean(typeof alias === "object" && alias ? alias.type : "source", 80) || "source";
      const normalized = ontologyNormalize(aliasValue, 512);
      const aliasSource = ontologySource(typeof alias === "object" && alias ? (alias.source || source) : source) || "unknown";
      const aliasId = `alias:${await sha256Hex(`${aliasType}|${normalized}|${aliasSource}`)}`.slice(0, 52);
      const incumbent = preflightAliasRows.get(`${aliasType}|${normalized}|${aliasSource}`) || null;
      if (incumbent && incumbent.entity_id !== entityId) {
        const conflictId = `conflict:${(await sha256Hex(`alias|${aliasType}|${normalized}|${aliasSource}|${incumbent.entity_id}|${entityId}`)).slice(0, 40)}`;
        queueWrite("INSERT OR IGNORE INTO ontology_conflicts (conflict_id, object_type, object_id, conflict_type, details_json, status, source, created_at) VALUES (?, 'alias', ?, 'duplicate_alias', ?, 'open', ?, ?)",
          conflictId,
          aliasId,
          boundedJson({ alias_type: aliasType, normalized_value: normalized, source: aliasSource, incumbent_entity_id: incumbent.entity_id, candidate_entity_id: entityId }, MAX_SUMMARY_BYTES, "Ontology conflict"),
          clean(payload.source_instance || "ontology-bridge", 160) || "ontology-bridge",
          now);
        continue;
      }
      queueWrite(`INSERT INTO ontology_aliases (alias_id, entity_id, alias_type, alias_value, normalized_value, source, confidence, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(alias_id) DO UPDATE SET entity_id=excluded.entity_id, alias_value=excluded.alias_value, confidence=excluded.confidence, updated_at=excluded.updated_at`,
        aliasId,
        entityId,
        aliasType,
        aliasValue,
        normalized,
        aliasSource,
        ontologyConfidence(typeof alias === "object" && alias ? alias.confidence : 100),
        now,
        now);
    }
  }
  for (let index = 0; index < evidenceRefs.length; index += 1) {
    const item = evidenceRefs[index];
    const evidence = preflightEvidenceRecords[index];
    if (!evidence) throw new HttpError(422, "invalid_evidence_ref", "Ontology evidence preflight did not produce a record");
    const { source, locator, contentHash, evidenceId, summaryJson } = evidence;
    let evidenceWorkspace = evidence.evidenceWorkspace;
    if (expectedWorkspace && evidenceWorkspace !== expectedWorkspace && evidenceWorkspace !== "local") throw new HttpError(403, "scope_mismatch", "Ontology evidence workspace does not match this Core workspace");
    const existingEvidence = preflightEvidenceRows.get(evidenceId) || null;
    if (existingEvidence?.workspace_id && existingEvidence.workspace_id !== "local" && evidenceWorkspace !== "local" && existingEvidence.workspace_id !== evidenceWorkspace) throw new HttpError(403, "scope_mismatch", "Ontology evidence reference belongs to a different workspace");
    if (existingEvidence?.workspace_id && existingEvidence.workspace_id !== "local" && evidenceWorkspace === "local") evidenceWorkspace = clean(existingEvidence.workspace_id, 160) || evidenceWorkspace;
    queueWrite(`INSERT INTO ontology_evidence_refs (evidence_ref_id, source, locator, content_hash, content_type, workspace_id, summary_json, observed_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(evidence_ref_id) DO UPDATE SET source=excluded.source, locator=excluded.locator, content_hash=excluded.content_hash, content_type=excluded.content_type, workspace_id=excluded.workspace_id, summary_json=excluded.summary_json, observed_at=excluded.observed_at, updated_at=excluded.updated_at`,
      evidenceId,
      source,
      locator,
      contentHash,
      evidence.contentType,
      evidenceWorkspace,
      summaryJson,
      evidence.observedAt || now,
      now,
      now);
  }
  for (let index = 0; index < relationships.length; index += 1) {
    const relationship = preflightRelationshipRecords[index];
    if (!relationship) throw new HttpError(422, "invalid_relationship", "Ontology relationship preflight did not produce a record");
    const { relation, from, to, source, sourceRecord, relationshipWorkspace, evidenceRefId, relationId, propertiesJson, relationshipChangeAfterJson, changeId: relationshipChangeId } = relationship;
    queueWrite(`INSERT INTO ontology_relationships
      (relationship_id, relationship_type, from_entity_id, to_entity_id, source, source_record_id, workspace_id, evidence_ref_id, properties_json, confidence, observed_at, valid_from, valid_to, freshness_at, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(relationship_id) DO UPDATE SET relationship_type=excluded.relationship_type, from_entity_id=excluded.from_entity_id, to_entity_id=excluded.to_entity_id, source=excluded.source, source_record_id=excluded.source_record_id, workspace_id=excluded.workspace_id, evidence_ref_id=excluded.evidence_ref_id, properties_json=excluded.properties_json, confidence=excluded.confidence, observed_at=excluded.observed_at, valid_from=excluded.valid_from, valid_to=excluded.valid_to, freshness_at=excluded.freshness_at, updated_at=excluded.updated_at`,
      relationId,
      relation,
      from,
      to,
      source,
      sourceRecord,
      relationshipWorkspace,
      evidenceRefId || null,
      propertiesJson,
      relationship.confidence,
      relationship.observedAt || now,
      relationship.validFrom,
      relationship.validTo,
      relationship.freshnessAt || relationship.observedAt || now,
      now,
      now);
    queueWrite(`INSERT OR IGNORE INTO ontology_change_log (change_id, object_type, object_id, action, before_json, after_json, source, actor, occurred_at) VALUES (?, 'relationship', ?, 'upsert', '{}', ?, ?, ?, ?)`,
      relationshipChangeId,
      relationId,
      relationshipChangeAfterJson,
      source,
      clean(payload.source_instance || "ontology-bridge", 160) || "ontology-bridge",
      now);
  }
  for (let index = 0; index < events.length; index += 1) {
    const event = preflightEventRecords[index];
    if (!event) throw new HttpError(422, "invalid_event", "Ontology event preflight did not produce a record");
    const { entityId, eventType, source, sourceRecord, occurredAt, eventId, summaryJson } = event;
    queueWrite(`INSERT INTO ontology_events (event_id, entity_id, event_type, source, source_record_id, summary_json, occurred_at, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(event_id) DO UPDATE SET event_type=excluded.event_type, source=excluded.source, source_record_id=excluded.source_record_id, summary_json=excluded.summary_json, occurred_at=excluded.occurred_at`,
      eventId,
      entityId,
      eventType,
      source,
      sourceRecord,
      summaryJson,
      occurredAt,
      now);
  }
  queueWrite("INSERT INTO ontology_ingest_receipts (idempotency_key, request_hash, source_instance, response_json, created_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(idempotency_key) DO NOTHING",
    idempotencyKey,
    requestHash,
    clean(payload.source_instance, 160) || "ontology-bridge",
    resultJson,
    now);
  if (typeof env.DB.batch !== "function") throw new HttpError(503, "d1_batch_unavailable", "Ontology synchronization requires transactional D1 batch support");
  await env.DB.batch(writeStatements);
  await writeAudit(env.DB, { requestId, action: "ontology.sync", actorRole: "intelligence_bridge", result: "success", sourceInstance: clean(payload.source_instance, 160) || "ontology-bridge", details: { idempotency_key: idempotencyKey, entities: entities.length, relationships: relationships.length, events: events.length }, createdAt: now });
  return result;
}

function intelligenceActions() {
  const descriptions = {
    explain_finding: "Explain one finding and identify evidence-backed next steps.",
    triage_finding: "Classify one finding and propose evidence-bounded reversible handling.",
    prioritize_findings: "Prioritize open findings using normalized severity and context.",
    analyze_asset_change: "Explain a recent asset change and its security significance.",
    analyze_research_case: "Analyze claims, contradictions, limitations, and unanswered questions.",
    generate_analyst_brief: "Draft an evidence-grounded analyst brief.",
    review_publication_safety: "Review disclosure, attribution, privacy, and evidentiary risks.",
    recommend_remediation: "Propose prioritized remediation with verification steps.",
    triage_artifact: "Assess deterministic OSS artifact findings.",
    execute_specialist_work: "Run a reviewed specialist profile against a bounded work contract.",
    review_specialist_work: "Independently review one specialist result.",
  };
  return {
    schema_version: INTELLIGENCE_SCHEMA_VERSION,
    actions: [...INTELLIGENCE_ACTIONS].sort().map((name) => ({
      name,
      title: name.replace(/(^|_)([a-z])/g, (_, prefix, letter) => `${prefix ? " " : ""}${letter.toUpperCase()}`),
      description: descriptions[name] || "Bridge-backed intelligence action.",
      scope: name.includes("finding") || name === "recommend_remediation" ? "secopsai.findings.read" : "secopsai.research.read",
      target: name.includes("finding") || name === "recommend_remediation" ? "finding" : "research_case",
      read_only: true,
      requires_bridge: true,
    })),
  };
}

async function readJsonObject(request, maximum = MAX_INTELLIGENCE_BYTES, label = "Request") {
  const declaredLength = Number(request.headers.get("content-length") || 0);
  if (declaredLength > maximum) throw new HttpError(413, "request_too_large", `${label} exceeds the request size limit`);
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > maximum) throw new HttpError(413, "request_too_large", `${label} exceeds the request size limit`);
  if (!bytes.byteLength) return {};
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new HttpError(400, "invalid_json", `${label} must be valid UTF-8 JSON`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new HttpError(422, "invalid_payload", `${label} must be a JSON object`);
  return parsed;
}

function boundedJson(value, maximum, label) {
  const encoded = JSON.stringify(sanitize(value));
  if (new TextEncoder().encode(encoded).byteLength > maximum) throw new HttpError(413, "payload_too_large", `${label} exceeds the size limit`);
  return encoded;
}

// ``sanitize`` intentionally truncates individual strings and arrays for
// stored telemetry.  Ontology ingestion must still reject an oversized input
// before any row is written; otherwise a late record can be silently reduced
// and/or leave an earlier part of the snapshot durable.  Keep this check
// separate from ``boundedJson`` so existing response sanitization retains its
// established behavior.
function preflightBoundedJson(value, maximum, label) {
  let encoded;
  try {
    encoded = JSON.stringify(value);
  } catch {
    throw new HttpError(422, "invalid_payload", `${label} must be JSON serializable`);
  }
  if (encoded === undefined) {
    throw new HttpError(422, "invalid_payload", `${label} must be JSON serializable`);
  }
  if (new TextEncoder().encode(encoded).byteLength > maximum) {
    throw new HttpError(413, "payload_too_large", `${label} exceeds the size limit`);
  }
  return boundedJson(value, maximum, label);
}

// Change-log rows are bounded control-plane records.  Keep the durable
// before-image to the entity's scalar identity/state envelope rather than
// copying the full D1 row (which may contain a 64 KiB properties JSON field)
// into the 32 KiB change-log column.
function ontologyEntityChangeProjection(row) {
  if (!row) return {};
  return {
    entity_id: clean(row.entity_id, 512),
    entity_type: clean(row.entity_type, 80),
    namespace: clean(row.namespace, 120),
    canonical_key: clean(row.canonical_key, 1024),
    display_name: clean(row.display_name, 512),
    source: clean(row.source, 160),
    source_id: clean(row.source_id, 512),
    workspace_id: clean(row.workspace_id, 160),
    owner_id: clean(row.owner_id, 256),
    status: clean(row.status, 80),
    confidence: Number(row.confidence ?? 0),
    first_seen_at: clean(row.first_seen_at, 64),
    last_seen_at: clean(row.last_seen_at, 64),
    observed_at: clean(row.observed_at, 64),
    freshness_at: clean(row.freshness_at, 64),
    valid_from: clean(row.valid_from, 64) || null,
    valid_to: clean(row.valid_to, 64) || null,
  };
}

function nowIso() {
  return new Date().toISOString();
}

function futureIso(seconds) {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

function decodeRowJson(row, column, fallback = {}) {
  return parseJson(row?.[column], fallback);
}

function publicJob(row, { includeInput = true, includeResult = true, includeLease = false } = {}) {
  if (!row) return null;
  const output = { ...row, schema_version: INTELLIGENCE_JOB_SCHEMA_VERSION };
  delete output.idempotency_key;
  const rawInput = String(row.input_json || "{}");
  const rawResult = String(row.result_json || "{}");
  output.input = includeInput ? parseJson(rawInput, {}) : {};
  output.result = includeResult ? parseJson(rawResult, {}) : {};
  if (!includeInput) {
    const input = parseJson(rawInput, {});
    output.input = Object.fromEntries(["target_id", "selected_model", "pipeline_id", "agent_triage_run_id"].filter((key) => input?.[key] !== undefined).map((key) => [key, input[key]]));
    output.input_available = rawInput !== "{}";
    output.input_bytes = new TextEncoder().encode(rawInput).byteLength;
  }
  if (!includeResult) {
    output.result_available = rawResult !== "{}";
    output.result_bytes = new TextEncoder().encode(rawResult).byteLength;
  }
  delete output.input_json;
  delete output.result_json;
  if (!includeLease) {
    delete output.lease_token;
    delete output.lease_generation;
  }
  return output;
}

async function listIntelligenceJobs(db, searchParams) {
  const limit = boundedLimit(searchParams.get("limit"), 50, 100);
  const status = clean(searchParams.get("status"), 40);
  const query = status ?
    "SELECT * FROM intelligence_jobs WHERE status = ? ORDER BY updated_at DESC, job_id DESC LIMIT ?" :
    "SELECT * FROM intelligence_jobs ORDER BY updated_at DESC, job_id DESC LIMIT ?";
  const statement = status ? db.prepare(query).bind(status, limit) : db.prepare(query).bind(limit);
  const rows = await statement.all();
  const counts = await db.prepare("SELECT status, COUNT(*) AS count FROM intelligence_jobs GROUP BY status").all();
  return { jobs: (rows.results || []).map((row) => publicJob(row, { includeInput: false, includeResult: false })), counts: Object.fromEntries((counts.results || []).map((row) => [row.status, Number(row.count || 0)])) };
}

async function getIntelligenceJob(db, jobId, includeResult = false) {
  const normalized = clean(jobId, 100);
  const row = await db.prepare("SELECT * FROM intelligence_jobs WHERE job_id = ?").bind(normalized).first();
  if (!row) throw new HttpError(404, "not_found", `Intelligence job not found: ${normalized}`);
  const events = await db.prepare("SELECT event_id, event_type, actor, message, data_json, created_at FROM intelligence_job_events WHERE job_id = ? ORDER BY event_id").bind(normalized).all();
  const job = publicJob(row, { includeInput: includeResult, includeResult });
  job.events = (events.results || []).map((event) => ({ ...event, data: parseJson(event.data_json, {}) }));
  for (const event of job.events) delete event.data_json;
  return job;
}

async function createIntelligenceJob(request, env, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Intelligence job");
  const action = clean(payload.action, 100);
  if (!INTELLIGENCE_ACTIONS.has(action)) throw new HttpError(422, "invalid_action", "Only approved bridge-backed intelligence actions may be queued");
  const targetId = clean(payload.target_id, 240);
  const inputs = payload.inputs === undefined ? {} : payload.inputs;
  if (!inputs || typeof inputs !== "object" || Array.isArray(inputs)) throw new HttpError(422, "invalid_inputs", "Intelligence inputs must be an object");
  const inputJson = boundedJson(inputs, MAX_INTELLIGENCE_BYTES, "Intelligence job input");
  const requestedBy = clean(payload.requested_by, 160) || "mission-control";
  const idempotencyKey = clean(payload.idempotency_key, 256) || await sha256Hex(`${action}|${targetId}|${inputJson}|${requestedBy}`);
  const existing = await env.DB.prepare("SELECT * FROM intelligence_jobs WHERE idempotency_key = ?").bind(idempotencyKey).first();
  if (existing) return { job: publicJob(existing, { includeInput: false, includeResult: false }), created: false };
  const now = nowIso();
  const jobId = `AIJ-${crypto.randomUUID().replace(/-/g, "").slice(0, 16).toUpperCase()}`;
  try {
    await env.DB.prepare(`INSERT INTO intelligence_jobs
      (job_id, action, target_id, status, requested_by, idempotency_key, attempt, provider, worker_id,
       queued_at, started_at, completed_at, updated_at, lease_until, error_code, error_message, input_json, result_json)
      VALUES (?, ?, ?, 'queued', ?, ?, 0, '', '', ?, NULL, NULL, ?, NULL, NULL, NULL, ?, '{}')`)
      .bind(jobId, action, targetId, requestedBy, idempotencyKey, now, now, inputJson).run();
  } catch (error) {
    const raced = await env.DB.prepare("SELECT * FROM intelligence_jobs WHERE idempotency_key = ?").bind(idempotencyKey).first();
    if (raced) return { job: publicJob(raced, { includeInput: false, includeResult: false }), created: false };
    throw error;
  }
  await writeJobEvent(env.DB, jobId, "queued", requestedBy, "Intelligence job queued.", { action, target_id: targetId });
  await writeAudit(env.DB, { requestId, action: "intelligence.job.queued", actorRole: "intelligence_operator", result: "created", sourceInstance: "secopsai-core-edge", details: { job_id: jobId, intelligence_action: action }, createdAt: now });
  return { job: await getIntelligenceJob(env.DB, jobId, false), created: true };
}

async function cancelIntelligenceJob(db, jobId, requestId) {
  const normalized = clean(jobId, 100);
  const row = await db.prepare("SELECT * FROM intelligence_jobs WHERE job_id = ?").bind(normalized).first();
  if (!row) throw new HttpError(404, "not_found", `Intelligence job not found: ${normalized}`);
  if (row.status === "running") throw new HttpError(409, "job_running", "A running intelligence job must be allowed to expire or complete safely");
  if (!JOB_FINAL_STATUSES.has(row.status)) {
    const now = nowIso();
    await db.prepare("UPDATE intelligence_jobs SET status='canceled', completed_at=?, updated_at=?, lease_until=NULL, lease_token='' WHERE job_id=? AND status IN ('queued','awaiting_provider')").bind(now, now, normalized).run();
    await writeJobEvent(db, normalized, "canceled", "mission-control", "Intelligence job canceled.", {});
    await writeAudit(db, { requestId, action: "intelligence.job.canceled", actorRole: "intelligence_operator", result: "success", sourceInstance: "secopsai-core-edge", details: { job_id: normalized }, createdAt: now });
  }
  return getIntelligenceJob(db, normalized, false);
}

async function heartbeatIntelligenceJob(db, jobId, requestId, payload = {}) {
  const normalized = clean(jobId, 100);
  const row = await db.prepare("SELECT * FROM intelligence_jobs WHERE job_id=?").bind(normalized).first();
  if (!row) throw new HttpError(404, "not_found", `Intelligence job not found: ${normalized}`);
  if (row.status !== "running") {
    if (JOB_FINAL_STATUSES.has(row.status)) return getIntelligenceJob(db, normalized, false);
    throw new HttpError(409, "job_not_running", "Only a running intelligence job can receive a heartbeat");
  }
  const now = nowIso();
  assertLease(row, payload, "job");
  const updated = await db.prepare("UPDATE intelligence_jobs SET updated_at=?, lease_until=? WHERE job_id=? AND status='running' AND worker_id=? AND lease_generation=? AND lease_token=? AND lease_until > ?").bind(now, futureIso(1800), normalized, clean(payload.worker_id, 160), Number(payload.lease_generation), clean(payload.lease_token, 160), now).run();
  if (!changed(updated)) throw new HttpError(409, "lease_lost", "The intelligence job lease is no longer owned by this worker");
  await writeJobEvent(db, normalized, "heartbeat", "bridge", "Bridge renewed the running job lease.", {});
  return getIntelligenceJob(db, normalized, false);
}

async function claimIntelligenceJob(request, db, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Bridge claim");
  const workerId = clean(payload.worker_id, 160);
  if (!workerId) throw new HttpError(422, "invalid_worker", "worker_id is required");
  const now = nowIso();
  const stale = new Date(Date.now() - 900 * 1000).toISOString();
  await db.prepare("UPDATE intelligence_jobs SET status='queued', provider='', worker_id='', started_at=NULL, lease_until=NULL, lease_token='', updated_at=?, error_code='worker_recovered', error_message='Recovered after the bridge stopped reporting.' WHERE status='running' AND (lease_until < ? OR (lease_until IS NULL AND updated_at < ?))").bind(now, now, stale).run();
  const leaseToken = crypto.randomUUID().replace(/-/g, "");
  const updated = await db.prepare(`UPDATE intelligence_jobs SET status='running', provider='hosted_core_bridge', worker_id=?, attempt=attempt+1,
    started_at=?, updated_at=?, lease_until=?, lease_generation=lease_generation+1, lease_token=?, error_code=NULL, error_message=NULL
    WHERE job_id = (SELECT job_id FROM intelligence_jobs WHERE status='queued' ORDER BY queued_at, job_id LIMIT 1)
      AND status='queued'`).bind(workerId, now, now, futureIso(1800), leaseToken).run();
  if (!Number(updated?.meta?.changes || updated?.changes || 0)) {
    await writeAudit(db, { requestId, action: "intelligence.bridge.idle", actorRole: "intelligence_bridge", result: "success", sourceInstance: workerId, details: {}, createdAt: now });
    return { status: "idle", job: null, bridge_request: null };
  }
  const row = await db.prepare("SELECT * FROM intelligence_jobs WHERE status='running' AND worker_id=? ORDER BY started_at DESC, job_id DESC LIMIT 1").bind(workerId).first();
  if (!row) return { status: "idle", job: null, bridge_request: null };
  await writeJobEvent(db, row.job_id, "claimed", workerId, "Intelligence job claimed by bridge.", { provider: "hosted_core_bridge" });
  await writeAudit(db, { requestId, action: "intelligence.bridge.claimed", actorRole: "intelligence_bridge", result: "success", sourceInstance: workerId, details: { job_id: row.job_id, intelligence_action: row.action }, createdAt: now });
  const input = parseJson(row.input_json, {});
  if (row.target_id && input.target_id === undefined) input.target_id = row.target_id;
  return {
    status: "claimed",
    job: { job_id: row.job_id, action: row.action, target_id: row.target_id, status: row.status, attempt: row.attempt, selected_model: clean(input.selected_model, 200), input: sanitize(input), worker_id: row.worker_id, lease_generation: Number(row.lease_generation || 0), lease_token: clean(row.lease_token, 160) },
    bridge_request: {
      schema_version: INTELLIGENCE_SCHEMA_VERSION,
      action: { name: row.action, read_only: true, requires_bridge: true },
      requested_at: now,
      context: sanitize({ target_id: row.target_id, inputs: input }),
      instructions: "Use the local SecOpsAI ledger when available. Return summary, risk_assessment, evidence, recommended_actions, and limitations.",
      safety: { read_only: true, raw_telemetry_included: false, artifact_content_included: false, human_review_required: true },
    },
  };
}

async function completeIntelligenceJob(request, db, jobId, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_RESULT_BYTES, "Bridge result");
  const normalized = clean(jobId, 100);
  const row = await db.prepare("SELECT * FROM intelligence_jobs WHERE job_id=?").bind(normalized).first();
  if (!row) throw new HttpError(404, "not_found", `Intelligence job not found: ${normalized}`);
  if (row.status === "succeeded") return { status: "succeeded", job: await getIntelligenceJob(db, normalized, false) };
  if (row.status !== "running") throw new HttpError(409, "job_not_running", `Job is ${row.status} and cannot be completed`);
  assertLease(row, payload, "job");
  const result = payload.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) throw new HttpError(422, "invalid_result", "Bridge result must be an object");
  const required = ["summary", "risk_assessment", "evidence", "recommended_actions", "limitations"];
  const missing = required.filter((key) => result[key] === undefined);
  if (missing.length) throw new HttpError(422, "invalid_result", `Bridge result is missing: ${missing.join(", ")}`);
  const resultJson = boundedJson(result, MAX_INTELLIGENCE_RESULT_BYTES, "Bridge result");
  const now = nowIso();
  const provider = clean(payload.provider, 120) || "hosted_core_bridge";
  const updated = await db.prepare("UPDATE intelligence_jobs SET status='succeeded', provider=?, result_json=?, completed_at=?, updated_at=?, lease_until=NULL, lease_token='', error_code=NULL, error_message=NULL WHERE job_id=? AND status='running' AND worker_id=? AND lease_generation=? AND lease_token=? AND lease_until > ?").bind(provider, resultJson, now, now, normalized, clean(payload.worker_id, 160), Number(payload.lease_generation), clean(payload.lease_token, 160), now).run();
  if (!changed(updated)) throw new HttpError(409, "lease_lost", "The intelligence job lease is no longer owned by this worker");
  await writeJobEvent(db, normalized, "completed", clean(payload.worker_id, 160) || "bridge", "Bridge completed the intelligence job.", { provider, model: clean(payload.model, 200) });
  await writeAudit(db, { requestId, action: "intelligence.bridge.completed", actorRole: "intelligence_bridge", result: "success", sourceInstance: clean(payload.worker_id, 160) || "bridge", details: { job_id: normalized }, createdAt: now });
  return { status: "succeeded", job: await getIntelligenceJob(db, normalized, false) };
}

async function failIntelligenceJob(request, db, jobId, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Bridge failure");
  const normalized = clean(jobId, 100);
  const row = await db.prepare("SELECT * FROM intelligence_jobs WHERE job_id=?").bind(normalized).first();
  if (!row) throw new HttpError(404, "not_found", `Intelligence job not found: ${normalized}`);
  if (row.status === "failed") return { status: "failed", job: await getIntelligenceJob(db, normalized, false) };
  if (!JOB_ACTIVE_STATUSES.has(row.status)) throw new HttpError(409, "job_not_active", `Job is ${row.status} and cannot be failed`);
  assertLease(row, payload, "job");
  const now = nowIso();
  const errorCode = clean(payload.error_code, 80) || "bridge_failed";
  const errorMessage = clean(payload.error_message, 2000) || "Remote bridge failed";
  const updated = await db.prepare("UPDATE intelligence_jobs SET status='failed', error_code=?, error_message=?, completed_at=?, updated_at=?, lease_until=NULL, lease_token='' WHERE job_id=? AND status='running' AND worker_id=? AND lease_generation=? AND lease_token=? AND lease_until > ?").bind(errorCode, errorMessage, now, now, normalized, clean(payload.worker_id, 160), Number(payload.lease_generation), clean(payload.lease_token, 160), now).run();
  if (!changed(updated)) throw new HttpError(409, "lease_lost", "The intelligence job lease is no longer owned by this worker");
  await writeJobEvent(db, normalized, "failed", clean(payload.worker_id, 160) || "bridge", errorMessage, { error_code: errorCode });
  await writeAudit(db, { requestId, action: "intelligence.bridge.failed", actorRole: "intelligence_bridge", result: "failed", sourceInstance: clean(payload.worker_id, 160) || "bridge", details: { job_id: normalized, error_code: errorCode }, createdAt: now });
  return { status: "failed", job: await getIntelligenceJob(db, normalized, false) };
}

async function writeJobEvent(db, jobId, eventType, actor, message, data) {
  await db.prepare("INSERT INTO intelligence_job_events (job_id, event_type, actor, message, data_json, created_at) VALUES (?, ?, ?, ?, ?, ?)").bind(jobId, clean(eventType, 60), clean(actor, 160), clean(message, 2000), boundedJson(data || {}, MAX_SUMMARY_BYTES, "Job event data"), nowIso()).run();
}

async function readSetting(db, table, columns) {
  const row = await db.prepare(`SELECT ${columns} FROM ${table} WHERE settings_id=1`).first();
  return row || null;
}

function publicTriageSettings(row) {
  if (!row) return { mode: "not_configured" };
  return { ...row, schema_version: AGENT_TRIAGE_SCHEMA_VERSION, auto_create_tuning_proposals: Boolean(row.auto_create_tuning_proposals), auto_activate_tuning: Boolean(row.auto_activate_tuning) };
}

async function agentTriageStatus(db, limit) {
  const settings = publicTriageSettings(await readSetting(db, "agent_triage_settings", "*"));
  const runs = await db.prepare("SELECT * FROM agent_triage_runs ORDER BY updated_at DESC LIMIT ?").bind(limit).all();
  const proposals = await db.prepare("SELECT * FROM agent_triage_tuning_proposals ORDER BY updated_at DESC LIMIT ?").bind(limit).all();
  const summaryRows = await db.prepare("SELECT status, COUNT(*) AS count FROM agent_triage_runs GROUP BY status").all();
  const commands = await db.prepare("SELECT * FROM coordinator_commands WHERE command_type IN ('autopilot-run-now','autopilot-rollback','autopilot-rollback-tuning') ORDER BY updated_at DESC LIMIT ?").bind(limit).all();
  return { schema_version: AGENT_TRIAGE_SCHEMA_VERSION, settings, summary: Object.fromEntries((summaryRows.results || []).map((row) => [row.status, Number(row.count || 0)])), runs: (runs.results || []).map((row) => ({ ...row, summary: parseJson(row.summary_json, {}), recommendation: parseJson(row.recommendation_json, {}), decision: parseJson(row.decision_json, {}) })), tuning_proposals: (proposals.results || []).map((row) => ({ ...row, summary: parseJson(row.summary_json, {}) })), commands: (commands.results || []).map((row) => publicCommand(row, { includeResult: false })) };
}

async function configureAgentTriage(request, db, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Autopilot configuration");
  const current = await readSetting(db, "agent_triage_settings", "*");
  const mode = clean(payload.mode === undefined ? current?.mode : payload.mode, 20).toLowerCase();
  if (!["off", "advisory", "guarded"].includes(mode)) throw new HttpError(422, "invalid_mode", "Agent triage mode must be off, advisory, or guarded");
  const selectedModel = clean(payload.selected_model === undefined ? current?.selected_model : payload.selected_model, 200);
  const interval = boundedInteger(payload.poll_interval_seconds === undefined ? current?.poll_interval_seconds : payload.poll_interval_seconds, 30, 10, 3600, "poll_interval_seconds");
  const confidence = boundedInteger(payload.min_auto_close_confidence === undefined ? current?.min_auto_close_confidence : payload.min_auto_close_confidence, 97, 90, 100, "min_auto_close_confidence");
  const refs = boundedInteger(payload.min_evidence_refs === undefined ? current?.min_evidence_refs : payload.min_evidence_refs, 2, 1, 10, "min_evidence_refs");
  const maxRecords = boundedInteger(payload.max_records_per_cycle === undefined ? current?.max_records_per_cycle : payload.max_records_per_cycle, 10, 1, 100, "max_records_per_cycle");
  const createTuning = payload.auto_create_tuning_proposals === undefined ? Boolean(current?.auto_create_tuning_proposals) : Boolean(payload.auto_create_tuning_proposals);
  const activateTuning = payload.auto_activate_tuning === undefined ? Boolean(current?.auto_activate_tuning) : Boolean(payload.auto_activate_tuning);
  if (activateTuning && mode !== "guarded") throw new HttpError(422, "invalid_tuning_policy", "Automatic tuning activation requires guarded mode");
  const now = nowIso();
  await db.prepare("UPDATE agent_triage_settings SET mode=?, selected_model=?, poll_interval_seconds=?, min_auto_close_confidence=?, min_evidence_refs=?, max_records_per_cycle=?, auto_create_tuning_proposals=?, auto_activate_tuning=?, updated_at=?, updated_by=? WHERE settings_id=1").bind(mode, selectedModel, interval, confidence, refs, maxRecords, Number(createTuning), Number(activateTuning), now, "mission-control").run();
  const settings = publicTriageSettings(await readSetting(db, "agent_triage_settings", "*"));
  await writeAudit(db, { requestId, action: "intelligence.autopilot.configured", actorRole: "intelligence_operator", result: "success", sourceInstance: "secopsai-core-edge", details: { mode, selected_model: selectedModel }, createdAt: now });
  return settings;
}

async function dailyAutomationStatus(db, limit) {
  const settingsRow = await readSetting(db, "daily_automation_settings", "*");
  const settings = settingsRow ? publicDailyAutomationSettings({ ...settingsRow, schema_version: DAILY_AUTOMATION_SCHEMA_VERSION, enabled: Boolean(settingsRow.enabled), auto_promote_candidates: Boolean(settingsRow.auto_promote_candidates), run_learning: Boolean(settingsRow.run_learning) }) : {};
  const runs = await db.prepare("SELECT * FROM daily_automation_runs ORDER BY started_at DESC, run_id DESC LIMIT ?").bind(limit).all();
  const runRows = runs.results || [];
  const steps = runRows.length ? await db.prepare(`SELECT * FROM daily_automation_steps WHERE run_id IN (${runRows.map(() => "?").join(",")}) ORDER BY step_id`).bind(...runRows.map((row) => row.run_id)).all() : { results: [] };
  const byRun = new Map(runRows.map((row) => [row.run_id, []]));
  for (const step of steps.results || []) byRun.get(step.run_id)?.push({ ...step, result: parseJson(step.result_json, {}) });
  const hydrated = runRows.map((row) => publicDailyAutomationRun({ ...row, summary: parseJson(row.summary_json, {}), steps: byRun.get(row.run_id) || [] }));
  const commands = await db.prepare("SELECT * FROM coordinator_commands WHERE command_type='daily-run' ORDER BY updated_at DESC LIMIT ?").bind(limit).all();
  return { schema_version: DAILY_AUTOMATION_SCHEMA_VERSION, settings, summary: { runs: hydrated.length, active: hydrated.some((row) => row.status === "running") ? 1 : 0, last_status: hydrated[0]?.status || "never_run", last_run_at: hydrated[0]?.completed_at || null, next_run_at: settings.next_run_at || null }, active_run: hydrated.find((row) => row.status === "running") || null, runs: hydrated, commands: (commands.results || []).map((row) => publicCommand(row, { includeResult: false })) };
}

function publicDailyAutomationRun(row) {
  const output = { ...row };
  delete output.lease_token;
  return output;
}

function publicDailyAutomationSettings(row) {
  const output = { ...row };
  delete output.updated_lease_token;
  return output;
}

async function configureDailyAutomation(request, db, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Daily automation configuration");
  const current = await readSetting(db, "daily_automation_settings", "*");
  const interval = boundedInteger(payload.interval_seconds === undefined ? current?.interval_seconds : payload.interval_seconds, 21600, 900, 604800, "interval_seconds");
  const alerts = boundedInteger(payload.max_alert_reviews === undefined ? current?.max_alert_reviews : payload.max_alert_reviews, 25, 1, 500, "max_alert_reviews");
  const investigations = boundedInteger(payload.max_investigations === undefined ? current?.max_investigations : payload.max_investigations, 5, 1, 100, "max_investigations");
  const candidates = boundedInteger(payload.max_candidate_cases === undefined ? current?.max_candidate_cases : payload.max_candidate_cases, 5, 1, 500, "max_candidate_cases");
  const enabled = payload.enabled === undefined ? Boolean(current?.enabled ?? true) : Boolean(payload.enabled);
  const promote = payload.auto_promote_candidates === undefined ? Boolean(current?.auto_promote_candidates ?? true) : Boolean(payload.auto_promote_candidates);
  const learning = payload.run_learning === undefined ? Boolean(current?.run_learning ?? true) : Boolean(payload.run_learning);
  const now = nowIso();
  await db.prepare("UPDATE daily_automation_settings SET enabled=?, interval_seconds=?, max_alert_reviews=?, max_investigations=?, max_candidate_cases=?, auto_promote_candidates=?, run_learning=?, updated_at=?, updated_by=? WHERE settings_id=1").bind(Number(enabled), interval, alerts, investigations, candidates, Number(promote), Number(learning), now, "mission-control").run();
  const updated = await readSetting(db, "daily_automation_settings", "*");
  const settings = publicDailyAutomationSettings({ ...updated, schema_version: DAILY_AUTOMATION_SCHEMA_VERSION, enabled, auto_promote_candidates: promote, run_learning: learning });
  await writeAudit(db, { requestId, action: "intelligence.daily.configured", actorRole: "intelligence_operator", result: "success", sourceInstance: "secopsai-core-edge", details: { enabled, interval_seconds: interval }, createdAt: now });
  return settings;
}

async function queueCoordinatorCommand(request, db, requestId, commandType, fixedPayload) {
  if (!COORDINATOR_COMMANDS.has(commandType)) throw new HttpError(422, "invalid_command", "Unsupported coordinator command");
  const body = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Coordinator command");
  const payload = { ...fixedPayload, ...(body.payload && typeof body.payload === "object" && !Array.isArray(body.payload) ? body.payload : {}) };
  if (commandType === "autopilot-rollback" && !clean(payload.run_id, 80)) throw new HttpError(422, "invalid_run_id", "run_id is required");
  if (commandType === "autopilot-rollback-tuning" && !clean(payload.proposal_id, 80)) throw new HttpError(422, "invalid_proposal_id", "proposal_id is required");
  const active = await db.prepare("SELECT * FROM coordinator_commands WHERE command_type=? AND status IN ('queued','running') ORDER BY queued_at LIMIT 1").bind(commandType).first();
  if (active) return publicCommand(active, { includeResult: false });
  const requestedBy = clean(body.requested_by, 160) || "mission-control";
  const idempotencyKey = clean(body.idempotency_key, 256) || await sha256Hex(`${commandType}|${JSON.stringify(payload)}|${requestedBy}|${Math.floor(Date.now() / 60000)}`);
  const existing = await db.prepare("SELECT * FROM coordinator_commands WHERE idempotency_key=?").bind(idempotencyKey).first();
  if (existing) return publicCommand(existing, { includeResult: false });
  const now = nowIso();
  const commandId = `CMD-${crypto.randomUUID().replace(/-/g, "").slice(0, 16).toUpperCase()}`;
  await db.prepare(`INSERT INTO coordinator_commands
    (command_id, command_type, status, requested_by, idempotency_key, payload_json, result_json, worker_id,
     queued_at, started_at, completed_at, updated_at, lease_until, error_message)
    VALUES (?, ?, 'queued', ?, ?, ?, '{}', '', ?, NULL, NULL, ?, NULL, NULL)`)
    .bind(commandId, commandType, requestedBy, idempotencyKey, boundedJson(payload, MAX_SUMMARY_BYTES, "Coordinator command"), now, now).run();
  await writeAudit(db, { requestId, action: `intelligence.coordinator.${commandType}`, actorRole: "intelligence_operator", result: "queued", sourceInstance: "secopsai-core-edge", details: { command_id: commandId }, createdAt: now });
  return { command_id: commandId, command_type: commandType, status: "queued", queued_at: now };
}

function publicCommand(row, { includeResult = true, includeLease = false } = {}) {
  const output = { ...row, payload: parseJson(row.payload_json, {}), result: includeResult ? parseJson(row.result_json, {}) : {}, schema_version: "secopsai.coordinator.command.v1" };
  delete output.payload_json;
  delete output.result_json;
  delete output.idempotency_key;
  if (!includeLease) {
    delete output.lease_token;
    delete output.lease_generation;
  }
  return output;
}

function boundedInteger(value, fallback, minimum, maximum, label) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new HttpError(422, "invalid_limit", `${label} must be between ${minimum} and ${maximum}`);
  return parsed;
}

function changed(result) {
  return Number(result?.meta?.changes || result?.changes || 0) > 0;
}

function assertLease(row, payload, label = "job") {
  const rawWorkerId = String(payload?.worker_id || "").trim();
  const workerId = rawWorkerId.length <= 160 ? rawWorkerId : "";
  const rawToken = String(payload?.lease_token || "").trim();
  const token = rawToken.length <= 160 ? rawToken : "";
  const generation = Number(payload?.lease_generation);
  if (!workerId || !token || !Number.isSafeInteger(generation) || generation < 1) {
    throw new HttpError(422, "lease_required", `A ${label} lease worker_id, lease_generation, and lease_token are required`);
  }
  if (clean(row?.worker_id, 160) !== workerId || Number(row?.lease_generation || 0) !== generation || String(row?.lease_token || "").trim() !== token) {
    throw new HttpError(409, "lease_lost", `The ${label} lease is no longer owned by this worker`);
  }
  const leaseUntil = Date.parse(String(row?.lease_until || ""));
  if (!Number.isFinite(leaseUntil) || leaseUntil <= Date.now()) {
    throw new HttpError(409, "lease_lost", `The ${label} lease has expired`);
  }
}

async function mcpGatewayStatus(db, limit) {
  const rows = await db.prepare("SELECT session_id, client_id, client_name, subject_id, organization_id, workspace_id, transport, scopes_json, status, first_seen_at, last_seen_at, revoked_at, revoked_by, last_tool, request_count FROM mcp_client_sessions ORDER BY last_seen_at DESC, session_id DESC LIMIT ?").bind(limit).all();
  const cutoff = Date.now() - 30 * 60 * 1000;
  const sessions = (rows.results || []).map((row) => ({ ...row, scopes: parseJson(row.scopes_json, []), connected: row.status !== "revoked" && Date.parse(row.last_seen_at) >= cutoff }));
  const active = sessions.filter((item) => item.connected);
  const revoked = sessions.filter((item) => item.status === "revoked");
  return { schema_version: MCP_GATEWAY_SCHEMA_VERSION, generated_at: nowIso(), active_window_minutes: 30, summary: { recent_clients: new Set(active.map((item) => item.client_id)).size, connected_sessions: active.length, revoked_sessions: revoked.length, tracked_sessions: sessions.length }, sessions, revoked_sessions: revoked };
}

async function syncRunnerState(request, db, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Runner heartbeat");
  const rawWorkerId = String(payload.worker_id || "").trim();
  const workerId = rawWorkerId.length <= 160 ? rawWorkerId : "";
  if (!workerId) throw new HttpError(422, "invalid_worker", "worker_id is required");
  const now = nowIso();
  const processGeneration = Number(payload.process_generation);
  const processRevision = clean(payload.process_revision, 200);
  const processStartedAt = clean(payload.process_started_at, 64);
  const rawLeaseToken = String(payload.lease_token || payload.process_lease_token || "").trim();
  const leaseToken = rawLeaseToken.length <= 160 ? rawLeaseToken : "";
  if (!Number.isSafeInteger(processGeneration) || processGeneration < 1 || !processRevision || !processStartedAt || !leaseToken) {
    throw new HttpError(422, "runner_lease_required", "Runner heartbeat requires process_generation, process_revision, process_started_at, and lease_token");
  }
  // Preflight the raw JSON before sanitization.  Sanitization is intentionally
  // lossy for telemetry, but a heartbeat must reject an oversized coordinator
  // result before the lease row becomes durable.
  const storageJson = preflightBoundedJson(payload.storage || {}, 16 * 1024, "Storage status");
  const coordinatorJson = preflightBoundedJson(payload.coordinator || {}, 16 * 1024, "Coordinator status");
  const storage = parseJson(storageJson, {});
  const coordinator = parseJson(coordinatorJson, {});
  preflightCoordinatorResults(coordinator);
  const current = await db.prepare("SELECT * FROM runner_heartbeats WHERE worker_id=?").bind(workerId).first();
  const leaseUntil = futureIso(1800);
  const heartbeatValues = [
    clean(payload.status, 40) || "healthy",
    now,
    clean(payload.last_cycle_at, 64) || null,
    clean(payload.last_cycle_status, 40),
    storageJson,
    coordinatorJson,
    clean(payload.error_message, 2000) || null,
    now,
    processGeneration,
    processRevision,
    processStartedAt,
    leaseToken,
    leaseUntil,
  ];
  if (!current) {
    try {
      await db.prepare(`INSERT INTO runner_heartbeats
        (worker_id, status, last_seen_at, last_cycle_at, last_cycle_status, storage_json, coordinator_json, error_message, updated_at,
         process_generation, process_revision, process_started_at, lease_token, lease_until)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(workerId, ...heartbeatValues).run();
    } catch (error) {
      // Another request may have established the process lease between the
      // read and insert. Re-read below and apply the same fenced path.
      const raced = await db.prepare("SELECT * FROM runner_heartbeats WHERE worker_id=?").bind(workerId).first();
      if (!raced) throw error;
      await updateRunnerHeartbeat(db, raced, workerId, heartbeatValues, processGeneration, leaseToken, now);
    }
  } else {
    await updateRunnerHeartbeat(db, current, workerId, heartbeatValues, processGeneration, leaseToken, now);
  }
  await syncCoordinatorResults(db, coordinator, workerId, processGeneration, leaseToken);
  await writeAudit(db, { requestId, action: "intelligence.runner.heartbeat", actorRole: "intelligence_bridge", result: "success", sourceInstance: workerId, details: { status: clean(payload.status, 40) || "healthy", last_cycle_status: clean(payload.last_cycle_status, 40), process_generation: processGeneration }, createdAt: now });
  return hostedCoordinatorState(db, 20);
}

async function updateRunnerHeartbeat(db, current, workerId, values, processGeneration, leaseToken, now = nowIso()) {
  const currentGeneration = Number(current?.process_generation || 0);
  const currentToken = String(current?.lease_token || "").trim();
  const sameLease = currentGeneration === processGeneration && currentToken === leaseToken;
  const newerProcess = processGeneration > currentGeneration && Boolean(leaseToken);
  if (!sameLease && !newerProcess) {
    throw new HttpError(409, "runner_lease_lost", "The runner process lease is no longer owned by this worker");
  }
  if (sameLease && (!current?.lease_until || Date.parse(String(current.lease_until)) <= Date.now())) {
    throw new HttpError(409, "runner_lease_lost", "The runner process lease has expired");
  }
  const where = sameLease
    ? "worker_id=? AND process_generation=? AND lease_token=? AND lease_until > ?"
    : "worker_id=? AND process_generation<?";
  const updated = await db.prepare(`UPDATE runner_heartbeats SET status=?, last_seen_at=?, last_cycle_at=?, last_cycle_status=?, storage_json=?, coordinator_json=?, error_message=?, updated_at=?, process_generation=?, process_revision=?, process_started_at=?, lease_token=?, lease_until=? WHERE ${where}`)
    .bind(...values, workerId, ...(sameLease ? [processGeneration, leaseToken, now] : [processGeneration])).run();
  if (!changed(updated)) throw new HttpError(409, "runner_lease_lost", "The runner process lease is no longer owned by this worker");
}

function preflightCoordinatorResults(coordinator) {
  const commands = Array.isArray(coordinator?.hosted_commands) ? coordinator.hosted_commands : [];
  for (const item of commands.slice(0, 5)) {
    const commandType = clean(item?.command_type, 80);
    const result = item?.result && typeof item.result === "object" ? item.result : {};
    if (commandType === "daily-run") {
      preflightBoundedJson(result.summary && typeof result.summary === "object" ? result.summary : { status: result.status }, MAX_SUMMARY_BYTES, "Daily summary");
      for (const step of (Array.isArray(result.steps) ? result.steps : []).slice(0, 32)) {
        if (!step || typeof step !== "object" || Array.isArray(step)) throw new HttpError(422, "invalid_coordinator_result", "Daily step result must be an object");
        preflightBoundedJson(step?.result || {}, MAX_SUMMARY_BYTES, "Daily step result");
      }
    }
  }
}

async function assertRunnerLease(db, workerId, processGeneration, leaseToken) {
  const row = await db.prepare("SELECT process_generation, lease_token, lease_until FROM runner_heartbeats WHERE worker_id=?").bind(workerId).first();
  if (!row || Number(row.process_generation || 0) !== Number(processGeneration) || String(row.lease_token || "").trim() !== String(leaseToken || "").trim()) {
    throw new HttpError(409, "runner_lease_lost", "The runner process lease is no longer owned by this worker");
  }
  const leaseUntil = Date.parse(String(row.lease_until || ""));
  if (!Number.isFinite(leaseUntil) || leaseUntil <= Date.now()) {
    throw new HttpError(409, "runner_lease_lost", "The runner process lease has expired");
  }
}

async function syncCoordinatorResults(db, coordinator, workerId, processGeneration, leaseToken) {
  await assertRunnerLease(db, workerId, processGeneration, leaseToken);
  const commands = Array.isArray(coordinator?.hosted_commands) ? coordinator.hosted_commands : [];
  for (const item of commands.slice(0, 5)) {
    await assertRunnerLease(db, workerId, processGeneration, leaseToken);
    const commandType = clean(item?.command_type, 80);
    const result = item?.result && typeof item.result === "object" ? item.result : {};
    if (commandType === "daily-run" && result.run_id) {
      const runId = clean(result.run_id, 80);
      const summary = result.summary && typeof result.summary === "object" ? result.summary : { status: result.status };
      const started = clean(result.started_at, 64) || nowIso();
      const completed = clean(result.completed_at, 64) || (result.status === "running" ? null : nowIso());
      const nextRun = clean(result.next_run_at, 64) || null;
      const leaseCheckAt = nowIso();
      const materialized = await db.prepare(`INSERT INTO daily_automation_runs
        (run_id, trigger, status, started_at, completed_at, next_run_at, summary_json, error_message, updated_at, owner_worker_id, process_generation, lease_token)
        SELECT ?, 'hosted-core', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (SELECT 1 FROM runner_heartbeats WHERE worker_id=? AND process_generation=? AND lease_token=? AND lease_until > ?)
        ON CONFLICT(run_id) DO UPDATE SET status=excluded.status, completed_at=excluded.completed_at,
          next_run_at=excluded.next_run_at, summary_json=excluded.summary_json,
          error_message=excluded.error_message, updated_at=excluded.updated_at,
          owner_worker_id=excluded.owner_worker_id, process_generation=excluded.process_generation,
          lease_token=excluded.lease_token
        WHERE EXISTS (SELECT 1 FROM runner_heartbeats WHERE worker_id=excluded.owner_worker_id AND process_generation=excluded.process_generation AND lease_token=excluded.lease_token AND lease_until > ?)`)
        .bind(runId, clean(result.status, 32) || "degraded", started, completed, nextRun, boundedJson(summary, MAX_SUMMARY_BYTES, "Daily summary"), clean(result.error, 2000) || null, nowIso(), workerId, processGeneration, leaseToken, workerId, processGeneration, leaseToken, leaseCheckAt, leaseCheckAt).run();
      if (!changed(materialized)) throw new HttpError(409, "runner_lease_lost", "The runner process lease is no longer owned by this worker");
      await assertRunnerLease(db, workerId, processGeneration, leaseToken);
      await db.prepare("DELETE FROM daily_automation_steps WHERE run_id=? AND EXISTS (SELECT 1 FROM runner_heartbeats WHERE worker_id=? AND process_generation=? AND lease_token=? AND lease_until > ?)").bind(runId, workerId, processGeneration, leaseToken, leaseCheckAt).run();
      const steps = Array.isArray(result.steps) ? result.steps : [];
      for (const step of steps.slice(0, 32)) {
        const materializedStep = await db.prepare("INSERT INTO daily_automation_steps (run_id, step_name, status, started_at, completed_at, result_json, error_message) SELECT ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM runner_heartbeats WHERE worker_id=? AND process_generation=? AND lease_token=? AND lease_until > ?)").bind(runId, clean(step.step_name, 120), clean(step.status, 32) || "succeeded", clean(step.started_at, 64) || started, clean(step.completed_at, 64) || null, boundedJson(step.result || {}, MAX_SUMMARY_BYTES, "Daily step result"), clean(step.error, 2000) || null, workerId, processGeneration, leaseToken, leaseCheckAt).run();
        if (!changed(materializedStep)) throw new HttpError(409, "runner_lease_lost", "The runner process lease is no longer owned by this worker");
      }
      await assertRunnerLease(db, workerId, processGeneration, leaseToken);
      await db.prepare("UPDATE daily_automation_settings SET last_run_at=?, next_run_at=?, updated_at=?, updated_by_worker_id=?, updated_process_generation=?, updated_lease_token=? WHERE settings_id=1 AND EXISTS (SELECT 1 FROM runner_heartbeats WHERE worker_id=? AND process_generation=? AND lease_token=? AND lease_until > ?)").bind(completed || started, nextRun, nowIso(), workerId, processGeneration, leaseToken, workerId, processGeneration, leaseToken, nowIso()).run();
    }
    if (commandType === "autopilot-run-now") {
      await assertRunnerLease(db, workerId, processGeneration, leaseToken);
      const queued = Array.isArray(result.queued) ? result.queued : [];
      for (const run of queued.slice(0, 100)) {
        const runId = clean(run.run_id, 80);
        if (!runId) continue;
        const timestamp = nowIso();
        const leaseCheckAt = nowIso();
        const materialized = await db.prepare(`INSERT INTO agent_triage_runs
          (run_id, target_type, target_id, status, intelligence_job_id, selected_model, provider,
           summary_json, recommendation_json, decision_json, final_action, reversible, queued_at, completed_at, updated_at)
          SELECT ?, 'finding', ?, 'awaiting_model', ?, '', 'hosted_core_bridge', '{}', '{}', '{}', '', 1, ?, NULL, ?
          WHERE EXISTS (SELECT 1 FROM runner_heartbeats WHERE worker_id=? AND process_generation=? AND lease_token=? AND lease_until > ?)
          ON CONFLICT(run_id) DO UPDATE SET intelligence_job_id=excluded.intelligence_job_id,
            updated_at=excluded.updated_at
          WHERE EXISTS (SELECT 1 FROM runner_heartbeats WHERE worker_id=? AND process_generation=? AND lease_token=? AND lease_until > ?)`)
          .bind(runId, clean(run.finding_id, 240), clean(run.job_id, 100), timestamp, timestamp, workerId, processGeneration, leaseToken, leaseCheckAt, workerId, processGeneration, leaseToken, leaseCheckAt).run();
        if (!changed(materialized)) throw new HttpError(409, "runner_lease_lost", "The runner process lease is no longer owned by this worker");
      }
    }
  }
}

async function hostedCoordinatorState(db, limit) {
  const triage = publicTriageSettings(await readSetting(db, "agent_triage_settings", "*"));
  const dailyRow = await readSetting(db, "daily_automation_settings", "*");
  const daily = dailyRow ? publicDailyAutomationSettings({ ...dailyRow, schema_version: DAILY_AUTOMATION_SCHEMA_VERSION, enabled: Boolean(dailyRow.enabled), auto_promote_candidates: Boolean(dailyRow.auto_promote_candidates), run_learning: Boolean(dailyRow.run_learning) }) : {};
  const heartbeat = await db.prepare("SELECT * FROM runner_heartbeats ORDER BY last_seen_at DESC LIMIT 1").first();
  const commands = await db.prepare("SELECT * FROM coordinator_commands ORDER BY updated_at DESC LIMIT ?").bind(limit).all();
  return { schema_version: "secopsai.coordinator.state.v1", generated_at: nowIso(), settings: { agent_triage: triage, daily_automation: daily }, runner: heartbeat ? publicRunnerHeartbeat(heartbeat) : null, commands: (commands.results || []).map((row) => publicCommand(row, { includeResult: false })) };
}

function publicRunnerHeartbeat(row) {
  const output = { ...row, storage: parseJson(row.storage_json, {}), coordinator: parseJson(row.coordinator_json, {}) };
  delete output.storage_json;
  delete output.coordinator_json;
  delete output.lease_token;
  return output;
}

async function claimCoordinatorCommand(request, db, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Coordinator claim");
  const workerId = clean(payload.worker_id, 160);
  if (!workerId) throw new HttpError(422, "invalid_worker", "worker_id is required");
  const now = nowIso();
  const stale = new Date(Date.now() - 30 * 60 * 1000).toISOString();
  await db.prepare("UPDATE coordinator_commands SET status='queued', worker_id='', started_at=NULL, lease_until=NULL, lease_token='', updated_at=?, error_message='Recovered after the coordinator runner stopped reporting.' WHERE status='running' AND (lease_until < ? OR (lease_until IS NULL AND updated_at < ?))").bind(now, now, stale).run();
  const leaseToken = crypto.randomUUID().replace(/-/g, "");
  const updated = await db.prepare(`UPDATE coordinator_commands SET status='running', worker_id=?, started_at=?, updated_at=?, lease_until=?, lease_generation=lease_generation+1, lease_token=?
    WHERE command_id=(SELECT command_id FROM coordinator_commands WHERE status='queued' ORDER BY queued_at, command_id LIMIT 1) AND status='queued'`).bind(workerId, now, now, futureIso(1800), leaseToken).run();
  if (!Number(updated?.meta?.changes || updated?.changes || 0)) return { status: "idle", command: null };
  const row = await db.prepare("SELECT * FROM coordinator_commands WHERE status='running' AND worker_id=? ORDER BY started_at DESC, command_id DESC LIMIT 1").bind(workerId).first();
  if (!row) return { status: "idle", command: null };
  await writeAudit(db, { requestId, action: "intelligence.coordinator.claimed", actorRole: "intelligence_bridge", result: "success", sourceInstance: workerId, details: { command_id: row.command_id, command_type: row.command_type }, createdAt: now });
  return { status: "claimed", command: publicCommand(row, { includeLease: true }) };
}

async function finishCoordinatorCommand(request, db, commandId, outcome, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_RESULT_BYTES, "Coordinator result");
  const normalized = clean(commandId, 100);
  const row = await db.prepare("SELECT * FROM coordinator_commands WHERE command_id=?").bind(normalized).first();
  if (!row) throw new HttpError(404, "not_found", `Coordinator command not found: ${normalized}`);
  if (COMMAND_FINAL_STATUSES.has(row.status)) return { status: row.status, command: publicCommand(row) };
  if (row.status !== "running") throw new HttpError(409, "command_not_running", `Command is ${row.status} and cannot be completed`);
  assertLease(row, payload, "coordinator command");
  const requestedStatus = String(payload.status || "succeeded").toLowerCase();
  // Preserve an explicitly reported terminal state.  Collapsing failed or
  // canceled work into succeeded makes the hosted operating picture claim
  // work completed when the runner actually stopped or lost the task.
  const status = outcome === "complete"
    ? (["succeeded", "degraded", "failed", "canceled", "recovered"].includes(requestedStatus) ? requestedStatus : "succeeded")
    : "failed";
  const now = nowIso();
  const resultJson = boundedJson(payload.result || {}, MAX_SUMMARY_BYTES, "Coordinator result");
  const errorMessage = clean(payload.error_message, 2000) || null;
  const updated = await db.prepare("UPDATE coordinator_commands SET status=?, result_json=?, error_message=?, completed_at=?, updated_at=?, lease_until=NULL, lease_token='' WHERE command_id=? AND status='running' AND worker_id=? AND lease_generation=? AND lease_token=? AND lease_until > ?").bind(status, resultJson, errorMessage, now, now, normalized, clean(payload.worker_id, 160), Number(payload.lease_generation), clean(payload.lease_token, 160), now).run();
  if (!changed(updated)) throw new HttpError(409, "lease_lost", "The coordinator command lease is no longer owned by this worker");
  await writeAudit(db, { requestId, action: `intelligence.coordinator.${status}`, actorRole: "intelligence_bridge", result: status, sourceInstance: clean(payload.worker_id, 160) || "bridge", details: { command_id: normalized }, createdAt: now });
  return { status, command: publicCommand(await db.prepare("SELECT * FROM coordinator_commands WHERE command_id=?").bind(normalized).first()) };
}

async function heartbeatCoordinatorCommand(payload, db, commandId, requestId) {
  const normalized = clean(commandId, 100);
  const row = await db.prepare("SELECT * FROM coordinator_commands WHERE command_id=?").bind(normalized).first();
  if (!row) throw new HttpError(404, "not_found", `Coordinator command not found: ${normalized}`);
  if (COMMAND_FINAL_STATUSES.has(row.status)) return { status: row.status, command: publicCommand(row) };
  if (row.status !== "running") throw new HttpError(409, "command_not_running", `Command is ${row.status} and cannot receive a heartbeat`);
  assertLease(row, payload, "coordinator command");
  const now = nowIso();
  const updated = await db.prepare("UPDATE coordinator_commands SET updated_at=?, lease_until=? WHERE command_id=? AND status='running' AND worker_id=? AND lease_generation=? AND lease_token=? AND lease_until > ?").bind(now, futureIso(1800), normalized, clean(payload.worker_id, 160), Number(payload.lease_generation), clean(payload.lease_token, 160), now).run();
  if (!changed(updated)) throw new HttpError(409, "lease_lost", "The coordinator command lease is no longer owned by this worker");
  await writeAudit(db, { requestId, action: "intelligence.coordinator.heartbeat", actorRole: "intelligence_bridge", result: "success", sourceInstance: clean(payload.worker_id, 160) || "bridge", details: { command_id: normalized }, createdAt: now });
  return { status: "running", command: publicCommand(await db.prepare("SELECT * FROM coordinator_commands WHERE command_id=?").bind(normalized).first()) };
}

async function workspacePayload(db, limit) {
  const metadataRows = await db.prepare("SELECT key, value_json FROM core_metadata").all();
  const metadata = Object.fromEntries(metadataRows.results.map((row) => [row.key, parseJson(row.value_json, null)]));
  const output = {
    schema_version: metadata.schema_version || "secopsai.core.workspace.v1",
    generated_at: new Date().toISOString(),
    data_classification: metadata.data_classification || "internal",
    summary: metadata.summary || {},
    assets: [],
    findings: [],
    changes: metadata.changes || {},
    sync_state: [],
    research_alerts: await listResearchAlerts(db, limit),
    sites: [],
    sensors: [],
    services: [],
    wifi_networks: [],
  };
  for (const recordType of WORKSPACE_TYPES) {
    const rows = await db.prepare(
      "SELECT payload_json FROM workspace_records WHERE record_type = ? ORDER BY updated_at DESC LIMIT ?",
    ).bind(recordType, limit).all();
    output[recordType] = rows.results.map((row) => parseJson(row.payload_json, {}));
  }
  output.summary = { ...output.summary, research_alerts: output.research_alerts.length };
  return output;
}

async function listResearchAlerts(db, limit) {
  const rows = await db.prepare(`
    SELECT alert_id, alert_type, severity, reason, status, owner, evidence_json,
           candidate_id, campaign_id, occurred_at, created_at, updated_at
    FROM research_alerts
    ORDER BY updated_at DESC
    LIMIT ?
  `).bind(limit).all();
  return rows.results.map((row) => ({
    alert_id: row.alert_id,
    alert_type: row.alert_type,
    severity: row.severity,
    reason: row.reason,
    status: row.status,
    owner: row.owner,
    candidate_id: row.candidate_id,
    campaign_id: row.campaign_id,
    occurred_at: row.occurred_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
    evidence: parseJson(row.evidence_json, {}),
  }));
}

function validateAlert(payload) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new HttpError(400, "invalid_json", "Request body must be a JSON object");
  if (payload.schema_version !== "secopsai.research.alert.v1") throw new HttpError(422, "invalid_schema", "Unsupported research alert schema");
  const alertId = clean(payload.alert_id, 128);
  const alertType = clean(payload.alert_type, 128);
  const severity = clean(payload.severity, 16).toLowerCase();
  const reason = clean(payload.reason, 2000);
  if (!alertId) throw new HttpError(422, "invalid_alert_id", "Research alert ID is invalid");
  if (!ACCEPTED_ALERT_TYPES.has(alertType)) throw new HttpError(422, "invalid_alert_type", "Research alert type is not accepted by this endpoint");
  if (!SEVERITIES.has(severity)) throw new HttpError(422, "invalid_severity", "Research alert severity is invalid");
  if (!reason) throw new HttpError(422, "invalid_reason", "Research alert reason is invalid");
  if (!payload.evidence || typeof payload.evidence !== "object" || Array.isArray(payload.evidence)) throw new HttpError(422, "invalid_evidence", "Research alert evidence must be an object");
  return {
    alert_id: alertId,
    alert_type: alertType,
    severity,
    candidate_id: clean(payload.candidate_id, 128),
    campaign_id: clean(payload.campaign_id, 128),
    reason,
    evidence: payload.evidence,
    occurred_at: clean(payload.occurred_at, 64) || new Date().toISOString(),
  };
}

async function verifySignature(headers, body, secret) {
  const timestampText = clean(headers.get("x-secopsai-timestamp"), 32);
  const signatureHeader = clean(headers.get("x-secopsai-signature"), 80);
  const timestamp = Number.parseInt(timestampText, 10);
  if (!Number.isFinite(timestamp) || Math.abs(Math.floor(Date.now() / 1000) - timestamp) > SIGNATURE_MAX_AGE_SECONDS) {
    throw new HttpError(401, "invalid_signature", "Webhook timestamp is outside the replay window");
  }
  if (!/^sha256=[a-f0-9]{64}$/i.test(signatureHeader)) throw new HttpError(401, "invalid_signature", "Invalid webhook signature");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const prefix = new TextEncoder().encode(`${timestampText}.`);
  const message = new Uint8Array(prefix.byteLength + body.byteLength);
  message.set(prefix); message.set(body, prefix.byteLength);
  const expected = hex(new Uint8Array(await crypto.subtle.sign("HMAC", key, message)));
  if (!timingSafeEqual(expected, signatureHeader.slice(7).toLowerCase())) throw new HttpError(401, "invalid_signature", "Invalid webhook signature");
}

async function writeAudit(db, entry) {
  await db.prepare(`
    INSERT INTO audit_logs (request_id, action, actor_role, result, source_instance, details_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(entry.requestId, entry.action, entry.actorRole, entry.result, entry.sourceInstance, JSON.stringify(entry.details), entry.createdAt).run();
}

function requireBearer(request, expected) {
  if (!expected) throw new HttpError(503, "not_configured", "Core read access is not configured");
  const supplied = request.headers.get("authorization") || "";
  if (!supplied.startsWith("Bearer ") || !timingSafeEqual(supplied.slice(7), expected)) throw new HttpError(401, "unauthorized", "Valid bearer authentication is required");
}

function response(status, payload, requestId) {
  return Response.json({ ...payload, request_id: requestId }, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
      "permissions-policy": "camera=(), microphone=(), geolocation=()",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      "x-request-id": requestId,
    },
  });
}

function sanitize(value, depth = 0) {
  if (depth > 8) return "[truncated]";
  if (Array.isArray(value)) return value.slice(0, 100).map((item) => sanitize(item, depth + 1));
  if (value && typeof value === "object") {
    const blocked = new Set(["artifact", "artifact_bytes", "artifact_content", "authorization", "password", "raw_content", "raw_package", "raw_output", "raw_scan", "packet_capture", "pcap", "secret", "token", "access_token", "api_key", "credential", "private_key", "cookie"]);
    return Object.fromEntries(Object.entries(value).filter(([key]) => {
      const normalizedKey = key.toLowerCase();
      return !blocked.has(normalizedKey) && !/(?:^|_)(?:token|secret|password|credential|private_key|api_key)(?:_|$)/.test(normalizedKey);
    }).map(([key, item]) => [key.slice(0, 128), /(?:^|_)(?:url|uri|locator)$/i.test(key) && typeof item === "string" ? ontologySafeLocatorSync(item) : sanitize(item, depth + 1)]));
  }
  if (typeof value === "string") return value.replace(/[\r\n]+/g, " ").slice(0, 2000);
  return value === null || ["boolean", "number"].includes(typeof value) ? value : String(value).slice(0, 2000);
}

function decodeAudit(row) {
  return { ...row, details: parseJson(row.details_json, {}), details_json: undefined };
}

function parseJson(value, fallback) {
  try { return JSON.parse(value); } catch { return fallback; }
}

function boundedLimit(value, fallback, maximum) {
  const parsed = Number.parseInt(String(value || ""), 10);
  return Math.max(1, Math.min(Number.isFinite(parsed) ? parsed : fallback, maximum));
}

function boundedHeader(value) {
  return clean(value, 128);
}

function clean(value, maximum) {
  return String(value || "").trim().slice(0, maximum);
}

async function sha256Hex(value) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

// Opaque locator redaction happens in synchronous sanitization paths. This
// compact digest is never used as an entity identity; canonical keys use
// SHA-256 in the async ingestion path above.
function shortDigest(value) {
  let first = 2166136261;
  let second = 2654435761;
  for (const char of String(value || "")) {
    const code = char.codePointAt(0) || 0;
    first ^= code;
    first = Math.imul(first, 16777619) >>> 0;
    second ^= code + 0x9e3779b9;
    second = Math.imul(second, 2246822519) >>> 0;
  }
  return `${first.toString(16).padStart(8, "0")}${second.toString(16).padStart(8, "0")}`;
}

function hex(bytes) {
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function timingSafeEqual(left, right) {
  const a = new TextEncoder().encode(String(left));
  const b = new TextEncoder().encode(String(right));
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < a.byteLength; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
}

function safeMessage(error) {
  return String(error?.message || "request failed").replace(/[\r\n]/g, " ").slice(0, 500);
}

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
