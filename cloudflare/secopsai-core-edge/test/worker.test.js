import assert from "node:assert/strict";
import { test } from "node:test";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

import { handleRequest } from "../src/index.js";

class Statement {
  constructor(db, sql) { this.db = db; this.sql = sql; this.values = []; }
  bind(...values) { this.values = values; return this; }
  async first() {
    if (this.sql.includes("SELECT 1 AS ready")) return { ready: 1 };
    if (this.sql.includes("WHERE source_alert_id")) return this.db.alerts.get(this.values[0]) || null;
    if (this.sql.includes("FROM ontology_ingest_receipts")) return this.db.ontologyReceipts.get(this.values[0]) || null;
    return null;
  }
  async all() {
    if (this.sql.includes("FROM core_metadata")) return { results: [] };
    if (this.sql.includes("FROM workspace_records")) return { results: [] };
    if (this.sql.includes("FROM research_alerts")) return { results: [...this.db.alerts.values()] };
    if (this.sql.includes("FROM audit_logs")) return { results: this.db.audit };
    return { results: [] };
  }
  async run() {
    if (this.sql.includes("INSERT INTO research_alerts")) {
      const [alert_id, source_alert_id, alert_type, severity, candidate_id, campaign_id, reason, evidence_json, occurred_at, created_at, updated_at] = this.values;
      this.db.alerts.set(source_alert_id, { alert_id, source_alert_id, alert_type, severity, candidate_id, campaign_id, reason, evidence_json, status: "open", owner: "", occurred_at, created_at, updated_at });
    }
    if (this.sql.includes("INSERT INTO audit_logs")) {
      const [request_id, action, actor_role, result, source_instance, details_json, created_at] = this.values;
      this.db.audit.push({ request_id, action, actor_role, result, source_instance, details_json, created_at });
    }
    if (this.sql.includes("INSERT INTO ontology_ingest_receipts")) {
      const [idempotency_key, request_hash, source_instance, response_json, created_at] = this.values;
      if (!this.db.ontologyReceipts.has(idempotency_key)) this.db.ontologyReceipts.set(idempotency_key, { idempotency_key, request_hash, source_instance, response_json, created_at });
    }
    return { success: true };
  }
}

class MockD1 {
  constructor() { this.alerts = new Map(); this.audit = []; this.ontologyReceipts = new Map(); }
  prepare(sql) { return new Statement(this, sql); }
}

async function signedRequest(secret, payload, timestamp = Math.floor(Date.now() / 1000)) {
  const raw = JSON.stringify(payload);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${raw}`));
  const hex = [...new Uint8Array(signature)].map((value) => value.toString(16).padStart(2, "0")).join("");
  return new Request("https://core.example/api/v1/research/alerts/webhook", { method: "POST", body: raw, headers: { "content-type": "application/json", "x-secopsai-timestamp": String(timestamp), "x-secopsai-signature": `sha256=${hex}` } });
}

test("health and readiness report the Cloudflare data store", async () => {
  const env = { DB: new MockD1() };
  assert.equal((await handleRequest(new Request("https://core.example/healthz"), env)).status, 200);
  const readiness = await (await handleRequest(new Request("https://core.example/readyz"), env)).json();
  assert.equal(readiness.status, "ready");
  assert.equal(readiness.data_store, "d1");
  assert.equal(typeof readiness.request_id, "string");
  assert.ok(readiness.request_id.length > 0);
});

test("signed alerts are accepted and idempotently updated", async () => {
  const env = { DB: new MockD1(), RESEARCH_WEBHOOK_SECRET: "s".repeat(44), CORE_READ_TOKEN: "r".repeat(44) };
  const payload = { schema_version: "secopsai.research.alert.v1", alert_id: "RAL-1", alert_type: "collector_degraded", severity: "high", reason: "Collector missed a window", evidence: { collector: "npm", token: "must-be-removed" }, occurred_at: new Date().toISOString() };
  const first = await handleRequest(await signedRequest(env.RESEARCH_WEBHOOK_SECRET, payload), env);
  assert.equal(first.status, 200);
  assert.equal((await first.json()).created, true);
  const second = await handleRequest(await signedRequest(env.RESEARCH_WEBHOOK_SECRET, { ...payload, reason: "Updated" }), env);
  assert.equal((await second.json()).created, false);
  assert.equal(env.DB.alerts.size, 1);
  assert.equal(JSON.parse([...env.DB.alerts.values()][0].evidence_json).token, undefined);
});

test("invalid signatures and unauthenticated reads fail closed", async () => {
  const env = { DB: new MockD1(), RESEARCH_WEBHOOK_SECRET: "s".repeat(44), CORE_READ_TOKEN: "r".repeat(44) };
  const bad = new Request("https://core.example/api/v1/research/alerts/webhook", { method: "POST", body: "{}", headers: { "x-secopsai-timestamp": String(Math.floor(Date.now() / 1000)), "x-secopsai-signature": `sha256=${"0".repeat(64)}` } });
  assert.equal((await handleRequest(bad, env)).status, 401);
  assert.equal((await handleRequest(new Request("https://core.example/api/v1/workspace"), env)).status, 401);
});

test("intelligence action catalog is read-token protected", async () => {
  const env = { DB: new MockD1(), CORE_READ_TOKEN: "r".repeat(44) };
  const unauthorized = await handleRequest(new Request("https://core.example/api/v1/intelligence/actions"), env);
  assert.equal(unauthorized.status, 401);
  const authorized = await handleRequest(new Request("https://core.example/api/v1/intelligence/actions", { headers: { authorization: `Bearer ${env.CORE_READ_TOKEN}` } }), env);
  assert.equal(authorized.status, 200);
  const body = await authorized.json();
  assert.equal(body.schema_version, "secopsai.intelligence.v1");
  assert.ok(body.actions.some((action) => action.name === "triage_finding"));
  assert.ok(body.actions.every((action) => action.read_only === true && action.requires_bridge === true));
});

test("coordinator bridge routes require their separate bridge token", async () => {
  const env = { DB: new MockD1(), CORE_BRIDGE_TOKEN: "b".repeat(44) };
  const unauthorized = await handleRequest(new Request("https://core.example/api/v1/intelligence/bridge/state", { method: "POST", body: "{}" }), env);
  assert.equal(unauthorized.status, 401);
  const missingWorker = await handleRequest(new Request("https://core.example/api/v1/intelligence/bridge/claim", { method: "POST", body: "{}", headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}` } }), env);
  assert.equal(missingWorker.status, 422);
});

test("ontology routes use read, intelligence, and bridge scopes", async () => {
  const env = {
    DB: new MockD1(),
    CORE_READ_TOKEN: "r".repeat(44),
    CORE_INTELLIGENCE_TOKEN: "i".repeat(44),
    CORE_BRIDGE_TOKEN: "b".repeat(44),
  };
  const unauthenticated = await handleRequest(new Request("https://core.example/api/v1/ontology/search"), env);
  assert.equal(unauthenticated.status, 401);

  const search = await handleRequest(new Request("https://core.example/api/v1/ontology/search?q=package", { headers: { authorization: `Bearer ${env.CORE_READ_TOKEN}` } }), env);
  assert.equal(search.status, 200);
  assert.deepEqual((await search.json()).entities, []);

  const riskWrongScope = await handleRequest(new Request("https://core.example/api/v1/ontology/entities/finding:test:F-1/risk", { headers: { authorization: `Bearer ${env.CORE_READ_TOKEN}` } }), env);
  assert.equal(riskWrongScope.status, 401);
  const riskMissing = await handleRequest(new Request("https://core.example/api/v1/ontology/entities/finding:test:F-1/risk", { headers: { authorization: `Bearer ${env.CORE_INTELLIGENCE_TOKEN}` } }), env);
  assert.equal(riskMissing.status, 404);

  const sync = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", {
    method: "POST",
    headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({ schema_version: "secopsai.ontology.v1", source_instance: "runner-test", entities: [], relationships: [], events: [], evidence_refs: [] }),
  }), env);
  assert.equal(sync.status, 200);
  assert.equal((await sync.json()).counts.entities, 0);

  const invalid = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", {
    method: "POST",
    headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({ entities: [{ entity_type: "not-a-type", namespace: "test", canonical_key: "x" }], relationships: [], events: [], evidence_refs: [] }),
  }), env);
  assert.equal(invalid.status, 422);
});

test("ontology quality route reports bounded empty-store metrics", async () => {
  const env = { DB: new MockD1(), CORE_READ_TOKEN: "r".repeat(44) };
  const response = await handleRequest(new Request("https://core.example/api/v1/ontology/quality", { headers: { authorization: `Bearer ${env.CORE_READ_TOKEN}` } }), env);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.schema_version, "secopsai.ontology.v1");
  assert.equal(typeof body.stale_entities, "number");
  assert.equal(typeof body.orphan_entities, "number");
});

test("ontology synchronization returns the original receipt on an idempotent retry", async () => {
  const env = { DB: new MockD1(), CORE_BRIDGE_TOKEN: "b".repeat(44) };
  const payload = { schema_version: "secopsai.ontology.v1", source_instance: "runner-test", entities: [], relationships: [], events: [], evidence_refs: [] };
  const init = { method: "POST", headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json", "Idempotency-Key": "ontology-retry-001" }, body: JSON.stringify(payload) };
  const first = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", init), env);
  const firstBody = await first.json();
  assert.equal(first.status, 200);
  assert.equal(firstBody.idempotent, undefined);
  const second = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", init), env);
  const secondBody = await second.json();
  assert.equal(second.status, 200);
  assert.equal(secondBody.idempotent, true);
  assert.equal(secondBody.idempotency_key, "ontology-retry-001");
  assert.equal(env.DB.ontologyReceipts.size, 1);
});

test("ontology synchronization rejects reuse of a key for a different payload", async () => {
  const env = { DB: new MockD1(), CORE_BRIDGE_TOKEN: "b".repeat(44) };
  const firstPayload = { schema_version: "secopsai.ontology.v1", source_instance: "runner-a", entities: [], relationships: [], events: [], evidence_refs: [] };
  const headers = { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json", "Idempotency-Key": "ontology-conflict-001" };
  const first = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", { method: "POST", headers, body: JSON.stringify(firstPayload) }), env);
  assert.equal(first.status, 200);
  const second = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", { method: "POST", headers, body: JSON.stringify({ ...firstPayload, source_instance: "runner-b" }) }), env);
  assert.equal(second.status, 409);
  assert.equal((await second.json()).error, "idempotency_conflict");
});

test("ontology synchronization rejects unnamespaced IDs and conflicting workspace reads", async () => {
  const env = { DB: new MockD1(), CORE_BRIDGE_TOKEN: "b".repeat(44), CORE_READ_TOKEN: "r".repeat(44), CORE_WORKSPACE_ID: "workspace-a" };
  const invalid = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", {
    method: "POST",
    headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({ entities: [{ entity_type: "package", namespace: "pypi", canonical_key: "x", entity_id: "legacy-id" }], relationships: [], events: [], evidence_refs: [] }),
  }), env);
  assert.equal(invalid.status, 422);
  const forbidden = await handleRequest(new Request("https://core.example/api/v1/ontology/search?workspace_id=workspace-b", { headers: { authorization: `Bearer ${env.CORE_READ_TOKEN}` } }), env);
  assert.equal(forbidden.status, 403);
});

test("ontology synchronization enforces organization binding on records", async () => {
  const env = { DB: new MockD1(), CORE_BRIDGE_TOKEN: "b".repeat(44), CORE_ORGANIZATION_ID: "org-a" };
  const response = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", {
    method: "POST",
    headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({
      schema_version: "secopsai.ontology.v1",
      organization_id: "org-a",
      entities: [{ entity_type: "package", namespace: "pypi", canonical_key: "demo", organization_id: "org-b" }],
      relationships: [], events: [], evidence_refs: [],
    }),
  }), env);
  assert.equal(response.status, 403);
});
