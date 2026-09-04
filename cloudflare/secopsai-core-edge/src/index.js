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
