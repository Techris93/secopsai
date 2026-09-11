const MAX_ALERT_BYTES = 64 * 1024;
const SIGNATURE_MAX_AGE_SECONDS = 300;
const ACCEPTED_ALERT_TYPES = new Set([
  "collector_degraded",
  "collector_retention_risk",
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
const JOB_ACTIVE_STATUSES = new Set(["queued", "running", "awaiting_provider"]);
const JOB_FINAL_STATUSES = new Set(["succeeded", "failed", "canceled"]);
const COMMAND_ACTIVE_STATUSES = new Set(["queued", "running"]);
const COMMAND_FINAL_STATUSES = new Set(["succeeded", "degraded", "failed", "canceled"]);
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
      return response(200, { job: await heartbeatIntelligenceJob(env.DB, decodeURIComponent(jobMatch[1]), requestId) }, requestId);
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
      if (bridgeJobMatch[2] === "heartbeat") return response(200, { job: await heartbeatIntelligenceJob(env.DB, jobId, requestId) }, requestId);
      return response(200, await failIntelligenceJob(request, env.DB, jobId, requestId), requestId);
    }
    const bridgeCommandMatch = url.pathname.match(/^\/api\/v1\/intelligence\/bridge\/commands\/([^/]+)\/(complete|fail)$/);
    if (request.method === "POST" && bridgeCommandMatch) {
      requireBearer(request, env.CORE_BRIDGE_TOKEN);
      return response(200, await finishCoordinatorCommand(request, env.DB, decodeURIComponent(bridgeCommandMatch[1]), bridgeCommandMatch[2], requestId), requestId);
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

function nowIso() {
  return new Date().toISOString();
}

function futureIso(seconds) {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

function decodeRowJson(row, column, fallback = {}) {
  return parseJson(row?.[column], fallback);
}

function publicJob(row, { includeInput = true, includeResult = true } = {}) {
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
    await db.prepare("UPDATE intelligence_jobs SET status='canceled', completed_at=?, updated_at=?, lease_until=NULL WHERE job_id=? AND status IN ('queued','awaiting_provider')").bind(now, now, normalized).run();
    await writeJobEvent(db, normalized, "canceled", "mission-control", "Intelligence job canceled.", {});
    await writeAudit(db, { requestId, action: "intelligence.job.canceled", actorRole: "intelligence_operator", result: "success", sourceInstance: "secopsai-core-edge", details: { job_id: normalized }, createdAt: now });
  }
  return getIntelligenceJob(db, normalized, false);
}

async function heartbeatIntelligenceJob(db, jobId, requestId) {
  const normalized = clean(jobId, 100);
  const row = await db.prepare("SELECT status FROM intelligence_jobs WHERE job_id=?").bind(normalized).first();
  if (!row) throw new HttpError(404, "not_found", `Intelligence job not found: ${normalized}`);
  if (row.status !== "running") {
    if (JOB_FINAL_STATUSES.has(row.status)) return getIntelligenceJob(db, normalized, false);
    throw new HttpError(409, "job_not_running", "Only a running intelligence job can receive a heartbeat");
  }
  const now = nowIso();
  await db.prepare("UPDATE intelligence_jobs SET updated_at=?, lease_until=? WHERE job_id=? AND status='running'").bind(now, futureIso(900), normalized).run();
  await writeJobEvent(db, normalized, "heartbeat", "bridge", "Bridge renewed the running job lease.", {});
  return getIntelligenceJob(db, normalized, false);
}

async function claimIntelligenceJob(request, db, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Bridge claim");
  const workerId = clean(payload.worker_id, 160);
  if (!workerId) throw new HttpError(422, "invalid_worker", "worker_id is required");
  const now = nowIso();
  const stale = new Date(Date.now() - 900 * 1000).toISOString();
  await db.prepare("UPDATE intelligence_jobs SET status='queued', provider='', worker_id='', started_at=NULL, lease_until=NULL, updated_at=?, error_code='worker_recovered', error_message='Recovered after the bridge stopped reporting.' WHERE status='running' AND (lease_until < ? OR (lease_until IS NULL AND updated_at < ?))").bind(now, now, stale).run();
  const updated = await db.prepare(`UPDATE intelligence_jobs SET status='running', provider='hosted_core_bridge', worker_id=?, attempt=attempt+1,
    started_at=?, updated_at=?, lease_until=?, error_code=NULL, error_message=NULL
    WHERE job_id = (SELECT job_id FROM intelligence_jobs WHERE status='queued' ORDER BY queued_at, job_id LIMIT 1)
      AND status='queued'`).bind(workerId, now, now, futureIso(900)).run();
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
    job: { job_id: row.job_id, action: row.action, target_id: row.target_id, status: row.status, attempt: row.attempt, selected_model: clean(input.selected_model, 200), input: sanitize(input) },
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
  const result = payload.result;
  if (!result || typeof result !== "object" || Array.isArray(result)) throw new HttpError(422, "invalid_result", "Bridge result must be an object");
  const required = ["summary", "risk_assessment", "evidence", "recommended_actions", "limitations"];
  const missing = required.filter((key) => result[key] === undefined);
  if (missing.length) throw new HttpError(422, "invalid_result", `Bridge result is missing: ${missing.join(", ")}`);
  const resultJson = boundedJson(result, MAX_INTELLIGENCE_RESULT_BYTES, "Bridge result");
  const now = nowIso();
  const provider = clean(payload.provider, 120) || "hosted_core_bridge";
  await db.prepare("UPDATE intelligence_jobs SET status='succeeded', provider=?, result_json=?, completed_at=?, updated_at=?, lease_until=NULL, error_code=NULL, error_message=NULL WHERE job_id=? AND status='running'").bind(provider, resultJson, now, now, normalized).run();
  await writeJobEvent(db, normalized, "completed", clean(payload.worker_id, 160) || "bridge", "Bridge completed the intelligence job.", { provider, model: clean(payload.model, 200) });
  await writeAudit(db, { requestId, action: "intelligence.bridge.completed", actorRole: "intelligence_bridge", result: "success", sourceInstance: clean(payload.worker_id, 160) || "bridge", details: { job_id: normalized }, createdAt: now });
  return { status: "succeeded", job: await getIntelligenceJob(db, normalized, false) };
}

async function failIntelligenceJob(request, db, jobId, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Bridge failure");
  const normalized = clean(jobId, 100);
  const row = await db.prepare("SELECT status FROM intelligence_jobs WHERE job_id=?").bind(normalized).first();
  if (!row) throw new HttpError(404, "not_found", `Intelligence job not found: ${normalized}`);
  if (row.status === "failed") return { status: "failed", job: await getIntelligenceJob(db, normalized, false) };
  if (!JOB_ACTIVE_STATUSES.has(row.status)) throw new HttpError(409, "job_not_active", `Job is ${row.status} and cannot be failed`);
  const now = nowIso();
  const errorCode = clean(payload.error_code, 80) || "bridge_failed";
  const errorMessage = clean(payload.error_message, 2000) || "Remote bridge failed";
  await db.prepare("UPDATE intelligence_jobs SET status='failed', error_code=?, error_message=?, completed_at=?, updated_at=?, lease_until=NULL WHERE job_id=? AND status IN ('queued','running','awaiting_provider')").bind(errorCode, errorMessage, now, now, normalized).run();
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
  const settings = settingsRow ? { ...settingsRow, schema_version: DAILY_AUTOMATION_SCHEMA_VERSION, enabled: Boolean(settingsRow.enabled), auto_promote_candidates: Boolean(settingsRow.auto_promote_candidates), run_learning: Boolean(settingsRow.run_learning) } : {};
  const runs = await db.prepare("SELECT * FROM daily_automation_runs ORDER BY started_at DESC, run_id DESC LIMIT ?").bind(limit).all();
  const runRows = runs.results || [];
  const steps = runRows.length ? await db.prepare(`SELECT * FROM daily_automation_steps WHERE run_id IN (${runRows.map(() => "?").join(",")}) ORDER BY step_id`).bind(...runRows.map((row) => row.run_id)).all() : { results: [] };
  const byRun = new Map(runRows.map((row) => [row.run_id, []]));
  for (const step of steps.results || []) byRun.get(step.run_id)?.push({ ...step, result: parseJson(step.result_json, {}) });
  const hydrated = runRows.map((row) => ({ ...row, summary: parseJson(row.summary_json, {}), steps: byRun.get(row.run_id) || [] }));
  const commands = await db.prepare("SELECT * FROM coordinator_commands WHERE command_type='daily-run' ORDER BY updated_at DESC LIMIT ?").bind(limit).all();
  return { schema_version: DAILY_AUTOMATION_SCHEMA_VERSION, settings, summary: { runs: hydrated.length, active: hydrated.some((row) => row.status === "running") ? 1 : 0, last_status: hydrated[0]?.status || "never_run", last_run_at: hydrated[0]?.completed_at || null, next_run_at: settings.next_run_at || null }, active_run: hydrated.find((row) => row.status === "running") || null, runs: hydrated, commands: (commands.results || []).map((row) => publicCommand(row, { includeResult: false })) };
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
  const settings = { ...updated, schema_version: DAILY_AUTOMATION_SCHEMA_VERSION, enabled, auto_promote_candidates: promote, run_learning: learning };
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

function publicCommand(row, { includeResult = true } = {}) {
  const output = { ...row, payload: parseJson(row.payload_json, {}), result: includeResult ? parseJson(row.result_json, {}) : {}, schema_version: "secopsai.coordinator.command.v1" };
  delete output.payload_json;
  delete output.result_json;
  delete output.idempotency_key;
  return output;
}

function boundedInteger(value, fallback, minimum, maximum, label) {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) throw new HttpError(422, "invalid_limit", `${label} must be between ${minimum} and ${maximum}`);
  return parsed;
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
  const workerId = clean(payload.worker_id, 160);
  if (!workerId) throw new HttpError(422, "invalid_worker", "worker_id is required");
  const now = nowIso();
  const storage = sanitize(payload.storage || {});
  const coordinator = sanitize(payload.coordinator || {});
  await db.prepare(`INSERT INTO runner_heartbeats
    (worker_id, status, last_seen_at, last_cycle_at, last_cycle_status, storage_json, coordinator_json, error_message, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(worker_id) DO UPDATE SET status=excluded.status, last_seen_at=excluded.last_seen_at,
      last_cycle_at=excluded.last_cycle_at, last_cycle_status=excluded.last_cycle_status,
      storage_json=excluded.storage_json, coordinator_json=excluded.coordinator_json,
      error_message=excluded.error_message, updated_at=excluded.updated_at`)
    .bind(workerId, clean(payload.status, 40) || "healthy", now, clean(payload.last_cycle_at, 64) || null, clean(payload.last_cycle_status, 40), boundedJson(storage, MAX_SUMMARY_BYTES, "Storage status"), boundedJson(coordinator, MAX_SUMMARY_BYTES, "Coordinator status"), clean(payload.error_message, 2000) || null, now).run();
  await syncCoordinatorResults(db, coordinator, workerId);
  await writeAudit(db, { requestId, action: "intelligence.runner.heartbeat", actorRole: "intelligence_bridge", result: "success", sourceInstance: workerId, details: { status: clean(payload.status, 40) || "healthy", last_cycle_status: clean(payload.last_cycle_status, 40) }, createdAt: now });
  return hostedCoordinatorState(db, 20);
}

async function syncCoordinatorResults(db, coordinator, workerId) {
  const commands = Array.isArray(coordinator?.hosted_commands) ? coordinator.hosted_commands : [];
  for (const item of commands.slice(0, 5)) {
    const commandType = clean(item?.command_type, 80);
    const result = item?.result && typeof item.result === "object" ? item.result : {};
    if (commandType === "daily-run" && result.run_id) {
      const runId = clean(result.run_id, 80);
      const summary = result.summary && typeof result.summary === "object" ? result.summary : { status: result.status };
      const started = clean(result.started_at, 64) || nowIso();
      const completed = clean(result.completed_at, 64) || (result.status === "running" ? null : nowIso());
      const nextRun = clean(result.next_run_at, 64) || null;
      await db.prepare(`INSERT INTO daily_automation_runs
        (run_id, trigger, status, started_at, completed_at, next_run_at, summary_json, error_message, updated_at)
        VALUES (?, 'hosted-core', ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(run_id) DO UPDATE SET status=excluded.status, completed_at=excluded.completed_at,
          next_run_at=excluded.next_run_at, summary_json=excluded.summary_json,
          error_message=excluded.error_message, updated_at=excluded.updated_at`)
        .bind(runId, clean(result.status, 32) || "degraded", started, completed, nextRun, boundedJson(summary, MAX_SUMMARY_BYTES, "Daily summary"), clean(result.error, 2000) || null, nowIso()).run();
      await db.prepare("DELETE FROM daily_automation_steps WHERE run_id=?").bind(runId).run();
      const steps = Array.isArray(result.steps) ? result.steps : [];
      for (const step of steps.slice(0, 32)) {
        await db.prepare("INSERT INTO daily_automation_steps (run_id, step_name, status, started_at, completed_at, result_json, error_message) VALUES (?, ?, ?, ?, ?, ?, ?)").bind(runId, clean(step.step_name, 120), clean(step.status, 32) || "succeeded", clean(step.started_at, 64) || started, clean(step.completed_at, 64) || null, boundedJson(step.result || {}, MAX_SUMMARY_BYTES, "Daily step result"), clean(step.error, 2000) || null).run();
      }
      await db.prepare("UPDATE daily_automation_settings SET last_run_at=?, next_run_at=?, updated_at=? WHERE settings_id=1").bind(completed || started, nextRun, nowIso()).run();
    }
    if (commandType === "autopilot-run-now") {
      const queued = Array.isArray(result.queued) ? result.queued : [];
      for (const run of queued.slice(0, 100)) {
        const runId = clean(run.run_id, 80);
        if (!runId) continue;
        const timestamp = nowIso();
        await db.prepare(`INSERT INTO agent_triage_runs
          (run_id, target_type, target_id, status, intelligence_job_id, selected_model, provider,
           summary_json, recommendation_json, decision_json, final_action, reversible, queued_at, completed_at, updated_at)
          VALUES (?, 'finding', ?, 'awaiting_model', ?, '', 'hosted_core_bridge', '{}', '{}', '{}', '', 1, ?, NULL, ?)
          ON CONFLICT(run_id) DO UPDATE SET intelligence_job_id=excluded.intelligence_job_id,
            updated_at=excluded.updated_at`)
          .bind(runId, clean(run.finding_id, 240), clean(run.job_id, 100), timestamp, timestamp).run();
      }
    }
  }
}

async function hostedCoordinatorState(db, limit) {
  const triage = publicTriageSettings(await readSetting(db, "agent_triage_settings", "*"));
  const dailyRow = await readSetting(db, "daily_automation_settings", "*");
  const daily = dailyRow ? { ...dailyRow, schema_version: DAILY_AUTOMATION_SCHEMA_VERSION, enabled: Boolean(dailyRow.enabled), auto_promote_candidates: Boolean(dailyRow.auto_promote_candidates), run_learning: Boolean(dailyRow.run_learning) } : {};
  const heartbeat = await db.prepare("SELECT * FROM runner_heartbeats ORDER BY last_seen_at DESC LIMIT 1").first();
  const commands = await db.prepare("SELECT * FROM coordinator_commands ORDER BY updated_at DESC LIMIT ?").bind(limit).all();
  return { schema_version: "secopsai.coordinator.state.v1", generated_at: nowIso(), settings: { agent_triage: triage, daily_automation: daily }, runner: heartbeat ? { ...heartbeat, storage: parseJson(heartbeat.storage_json, {}), coordinator: parseJson(heartbeat.coordinator_json, {}) } : null, commands: (commands.results || []).map((row) => publicCommand(row, { includeResult: false })) };
}

async function claimCoordinatorCommand(request, db, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_BYTES, "Coordinator claim");
  const workerId = clean(payload.worker_id, 160);
  if (!workerId) throw new HttpError(422, "invalid_worker", "worker_id is required");
  const now = nowIso();
  const stale = new Date(Date.now() - 30 * 60 * 1000).toISOString();
  await db.prepare("UPDATE coordinator_commands SET status='queued', worker_id='', started_at=NULL, lease_until=NULL, updated_at=?, error_message='Recovered after the coordinator runner stopped reporting.' WHERE status='running' AND (lease_until < ? OR (lease_until IS NULL AND updated_at < ?))").bind(now, now, stale).run();
  const updated = await db.prepare(`UPDATE coordinator_commands SET status='running', worker_id=?, started_at=?, updated_at=?, lease_until=?
    WHERE command_id=(SELECT command_id FROM coordinator_commands WHERE status='queued' ORDER BY queued_at, command_id LIMIT 1) AND status='queued'`).bind(workerId, now, now, futureIso(1800)).run();
  if (!Number(updated?.meta?.changes || updated?.changes || 0)) return { status: "idle", command: null };
  const row = await db.prepare("SELECT * FROM coordinator_commands WHERE status='running' AND worker_id=? ORDER BY started_at DESC, command_id DESC LIMIT 1").bind(workerId).first();
  if (!row) return { status: "idle", command: null };
  await writeAudit(db, { requestId, action: "intelligence.coordinator.claimed", actorRole: "intelligence_bridge", result: "success", sourceInstance: workerId, details: { command_id: row.command_id, command_type: row.command_type }, createdAt: now });
  return { status: "claimed", command: publicCommand(row) };
}

async function finishCoordinatorCommand(request, db, commandId, outcome, requestId) {
  const payload = await readJsonObject(request, MAX_INTELLIGENCE_RESULT_BYTES, "Coordinator result");
  const normalized = clean(commandId, 100);
  const row = await db.prepare("SELECT * FROM coordinator_commands WHERE command_id=?").bind(normalized).first();
  if (!row) throw new HttpError(404, "not_found", `Coordinator command not found: ${normalized}`);
  if (COMMAND_FINAL_STATUSES.has(row.status)) return { status: row.status, command: publicCommand(row) };
  if (row.status !== "running") throw new HttpError(409, "command_not_running", `Command is ${row.status} and cannot be completed`);
  const status = outcome === "complete" ? (String(payload.status || "succeeded").toLowerCase() === "degraded" ? "degraded" : "succeeded") : "failed";
  const now = nowIso();
  const resultJson = boundedJson(payload.result || {}, MAX_SUMMARY_BYTES, "Coordinator result");
  const errorMessage = clean(payload.error_message, 2000) || null;
  await db.prepare("UPDATE coordinator_commands SET status=?, result_json=?, error_message=?, completed_at=?, updated_at=?, lease_until=NULL WHERE command_id=? AND status='running'").bind(status, resultJson, errorMessage, now, now, normalized).run();
  await writeAudit(db, { requestId, action: `intelligence.coordinator.${status}`, actorRole: "intelligence_bridge", result: status, sourceInstance: clean(payload.worker_id, 160) || "bridge", details: { command_id: normalized }, createdAt: now });
  return { status, command: publicCommand(await db.prepare("SELECT * FROM coordinator_commands WHERE command_id=?").bind(normalized).first()) };
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
    const blocked = new Set(["artifact", "artifact_bytes", "artifact_content", "authorization", "password", "raw_content", "raw_package", "secret", "token"]);
    return Object.fromEntries(Object.entries(value).filter(([key]) => !blocked.has(key.toLowerCase())).map(([key, item]) => [key.slice(0, 128), sanitize(item, depth + 1)]));
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
