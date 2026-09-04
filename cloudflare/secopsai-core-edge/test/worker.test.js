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
    return { success: true };
  }
}

class MockD1 {
  constructor() { this.alerts = new Map(); this.audit = []; }
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
