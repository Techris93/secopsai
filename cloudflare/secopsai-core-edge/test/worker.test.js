import assert from "node:assert/strict";
import { test } from "node:test";
import { webcrypto } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";

let DatabaseSync = null;
try {
  ({ DatabaseSync } = await import("node:sqlite"));
} catch {
  // Older supported Node versions do not bundle node:sqlite. The production
  // Worker still uses D1; the migration-backed integration test is skipped
  // there and the route/unit tests below remain portable.
}

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
  async batch(statements) {
    const results = [];
    for (const statement of statements) results.push(await statement.run());
    return results;
  }
}

class CountingD1 extends MockD1 {
  constructor() {
    super();
    this.firstCalls = 0;
    this.batchCalls = 0;
    this.lastBatchSize = 0;
  }

  prepare(sql) {
    const statement = super.prepare(sql);
    const first = statement.first.bind(statement);
    statement.first = async (...values) => {
      this.firstCalls += 1;
      return first(...values);
    };
    return statement;
  }

  async batch(statements) {
    this.batchCalls += 1;
    this.lastBatchSize = statements.length;
    return super.batch(statements);
  }
}

class RunnerStatement extends Statement {
  async first() {
    if (this.sql.includes("FROM runner_heartbeats")) {
      if (this.sql.includes("WHERE worker_id=?")) {
        const row = this.db.runners.get(this.values[0]);
        if (!row) return null;
        if (this.sql.includes("SELECT process_generation")) return { process_generation: row.process_generation, lease_token: row.lease_token, lease_until: row.lease_until };
        return { ...row };
      }
      return [...this.db.runners.values()].sort((left, right) => String(right.last_seen_at).localeCompare(String(left.last_seen_at)))[0] || null;
    }
    return super.first();
  }

  async run() {
    if (this.sql.includes("INSERT INTO runner_heartbeats")) {
      const [worker_id, status, last_seen_at, last_cycle_at, last_cycle_status, storage_json, coordinator_json, error_message, updated_at, process_generation, process_revision, process_started_at, lease_token, lease_until] = this.values;
      this.db.runners.set(worker_id, { worker_id, status, last_seen_at, last_cycle_at, last_cycle_status, storage_json, coordinator_json, error_message, updated_at, process_generation, process_revision, process_started_at, lease_token, lease_until });
      return { success: true, meta: { changes: 1 } };
    }
    if (this.sql.includes("UPDATE runner_heartbeats SET")) {
      const row = this.db.runners.get(this.values[13]);
      const generation = Number(this.values[14]);
      const sameLease = this.sql.includes("lease_token=? AND lease_until > ?");
      const token = sameLease ? this.values[15] : null;
      const now = sameLease ? this.values[16] : null;
      const valid = row && (sameLease
        ? row.process_generation === generation && row.lease_token === token && row.lease_until > now
        : row.process_generation < generation);
      if (!valid) return { success: true, meta: { changes: 0 } };
      const [status, last_seen_at, last_cycle_at, last_cycle_status, storage_json, coordinator_json, error_message, updated_at, process_generation, process_revision, process_started_at, lease_token, lease_until] = this.values;
      Object.assign(row, { status, last_seen_at, last_cycle_at, last_cycle_status, storage_json, coordinator_json, error_message, updated_at, process_generation, process_revision, process_started_at, lease_token, lease_until });
      return { success: true, meta: { changes: 1 } };
    }
    if (this.sql.includes("INSERT INTO daily_automation_runs")) {
      const [run_id, status, started_at, completed_at, next_run_at, summary_json, error_message, updated_at, owner_worker_id, process_generation, lease_token, guard_worker_id, guard_generation, guard_token, guard_now, conflict_now] = this.values;
      const runner = this.db.runners.get(guard_worker_id);
      const leaseValid = runner && runner.process_generation === Number(guard_generation) && runner.lease_token === guard_token && runner.lease_until > guard_now;
      if (!leaseValid) return { success: true, meta: { changes: 0 } };
      const existing = this.db.dailyRuns.get(run_id);
      if (existing) {
        const conflictValid = runner.process_generation === Number(process_generation) && runner.lease_token === lease_token && runner.lease_until > conflict_now;
        if (!conflictValid) return { success: true, meta: { changes: 0 } };
        Object.assign(existing, { status, completed_at, next_run_at, summary_json, error_message, updated_at, owner_worker_id, process_generation, lease_token });
      } else {
        this.db.dailyRuns.set(run_id, { run_id, status, started_at, completed_at, next_run_at, summary_json, error_message, updated_at, owner_worker_id, process_generation, lease_token });
      }
      return { success: true, meta: { changes: 1 } };
    }
    return super.run();
  }
}

class RunnerLeaseD1 extends MockD1 {
  constructor() { super(); this.runners = new Map(); this.dailyRuns = new Map(); }
  prepare(sql) { return new RunnerStatement(this, sql); }
}

class SqliteD1Statement {
  constructor(db, sql) { this.db = db; this.sql = sql; this.values = []; }
  bind(...values) { this.values = values; return this; }
  async first() { return this.db.prepare(this.sql).get(...this.values) ?? null; }
  async all() { return { results: this.db.prepare(this.sql).all(...this.values) }; }
  async run() {
    const result = this.db.prepare(this.sql).run(...this.values);
    return { success: true, meta: { changes: Number(result.changes || 0), last_row_id: Number(result.lastInsertRowid || 0) } };
  }
}

class SqliteD1 {
  constructor(db) { this.db = db; }
  prepare(sql) { return new SqliteD1Statement(this.db, sql); }
  async batch(statements) {
    this.db.exec("BEGIN");
    try {
      const results = [];
      for (const statement of statements) results.push(await statement.run());
      this.db.exec("COMMIT");
      return results;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
}

function migratedSqliteD1() {
  if (!DatabaseSync) return null;
  const db = new DatabaseSync(":memory:");
  const migrationsUrl = new URL("../migrations/", import.meta.url);
  for (const file of readdirSync(migrationsUrl).filter((name) => name.endsWith(".sql")).sort()) {
    db.exec(readFileSync(new URL(file, migrationsUrl), "utf8"));
  }
  return { db, d1: new SqliteD1(db) };
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

test("runner heartbeat route fences stale process generations", async () => {
  const env = { DB: new RunnerLeaseD1(), CORE_BRIDGE_TOKEN: "b".repeat(44) };
  const base = {
    worker_id: "runner-a",
    process_generation: 1,
    process_revision: "revision-a",
    process_started_at: "2026-09-12T00:00:00Z",
    lease_token: "lease-a",
    status: "healthy",
    storage: {},
    coordinator: {},
  };
  const request = (payload) => handleRequest(new Request("https://core.example/api/v1/intelligence/bridge/state", {
    method: "POST",
    headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify(payload),
  }), env);
  const initial = await request(base);
  assert.equal(initial.status, 200);
  const initialBody = await initial.json();
  assert.equal(initialBody.runner.process_revision, "revision-a");
  assert.equal(initialBody.runner.process_started_at, "2026-09-12T00:00:00Z");
  const oversized = await request({ ...base, worker_id: "runner-large", storage: { detail: "x".repeat(17000) } });
  assert.equal(oversized.status, 413);
  assert.equal(env.DB.runners.has("runner-large"), false);
  const stale = await request({ ...base, lease_token: "old-lease" });
  assert.equal(stale.status, 409);
  const replacement = await request({ ...base, process_generation: 2, process_revision: "revision-b", lease_token: "lease-b" });
  assert.equal(replacement.status, 200);
  const oldAfterReplacement = await request(base);
  assert.equal(oldAfterReplacement.status, 409);
  assert.equal(env.DB.runners.get("runner-a").process_generation, 2);
});

test("runner result materialization keeps the current leased schedule", async () => {
  const env = { DB: new RunnerLeaseD1(), CORE_BRIDGE_TOKEN: "b".repeat(44) };
  const base = {
    worker_id: "runner-a",
    process_revision: "revision-a",
    process_started_at: "2026-09-12T00:00:00Z",
    lease_token: "lease-a",
    status: "healthy",
    storage: {},
  };
  const request = (payload) => handleRequest(new Request("https://core.example/api/v1/intelligence/bridge/state", {
    method: "POST",
    headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify(payload),
  }), env);
  const result = (status, summary) => ({
    command_type: "daily-run",
    result: { run_id: "daily-1", status, summary: { status: summary } },
  });
  assert.equal((await request({ ...base, process_generation: 1, coordinator: { hosted_commands: [result("succeeded", "first")] } })).status, 200);
  assert.equal((await request({ ...base, process_generation: 2, process_revision: "revision-b", process_started_at: "2026-09-12T00:01:00Z", lease_token: "lease-b", coordinator: { hosted_commands: [result("succeeded", "current")] } })).status, 200);
  const stale = await request({ ...base, process_generation: 1, coordinator: { hosted_commands: [result("failed", "stale")] } });
  assert.equal(stale.status, 409);
  const stored = env.DB.dailyRuns.get("daily-1");
  assert.equal(stored.process_generation, 2);
  assert.equal(stored.lease_token, "lease-b");
  assert.equal(JSON.parse(stored.summary_json).status, "current");
});

test("coordinator completion preserves failed and canceled terminal states", { skip: !DatabaseSync }, async () => {
  const migrated = migratedSqliteD1();
  const env = { DB: migrated.d1, CORE_BRIDGE_TOKEN: "b".repeat(44), CORE_INTELLIGENCE_TOKEN: "i".repeat(44) };
  const base = {
    worker_id: "runner-a",
    process_generation: 1,
    process_revision: "revision-a",
    process_started_at: "2026-09-12T00:00:00Z",
    lease_token: "lease-a",
    status: "healthy",
    storage: {},
    coordinator: {},
  };
  const request = (payload) => handleRequest(new Request("https://core.example/api/v1/intelligence/bridge/state", {
    method: "POST",
    headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify(payload),
  }), env);
  const command = async (status, id) => {
    const insert = await handleRequest(new Request("https://core.example/api/v1/intelligence/daily/run", {
      method: "POST",
      headers: { authorization: `Bearer ${env.CORE_INTELLIGENCE_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ idempotency_key: id }),
    }), env);
    assert.equal(insert.status, 200);
    const commandId = (await insert.json()).result.command_id;
    const claim = await handleRequest(new Request("https://core.example/api/v1/intelligence/bridge/commands/claim", {
      method: "POST",
      headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ worker_id: base.worker_id }),
    }), env);
    const claimed = (await claim.json()).command;
    const complete = await handleRequest(new Request(`https://core.example/api/v1/intelligence/bridge/commands/${commandId}/complete`, {
      method: "POST",
      headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ worker_id: base.worker_id, lease_generation: claimed.lease_generation, lease_token: claimed.lease_token, status, result: { status } }),
    }), env);
    assert.equal(complete.status, 200);
    assert.equal((await complete.json()).status, status);
  };
  assert.equal((await request(base)).status, 200);
  await command("failed", "command-failed");
  await command("canceled", "command-canceled");
});

test("ontology synchronization is migration-safe, replay-idempotent, and preflighted", { skip: !DatabaseSync }, async () => {
  const migrated = migratedSqliteD1();
  const env = { DB: migrated.d1, CORE_BRIDGE_TOKEN: "b".repeat(44) };
  const headers = { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" };
  const send = (payload, idempotencyKey) => handleRequest(new Request("https://core.example/api/v1/ontology/sync", {
    method: "POST",
    headers: { ...headers, "Idempotency-Key": idempotencyKey },
    body: JSON.stringify(payload),
  }), env);
  const entities = [
    { entity_id: "pkg:pypi:edge-a", entity_type: "package", namespace: "pypi", canonical_key: "edge-a", source: "registry" },
    { entity_id: "pkg:pypi:edge-b", entity_type: "package", namespace: "pypi", canonical_key: "edge-b", source: "registry" },
  ];
  const relation = { relationship_id: "caller-rel-one", relationship_type: "PACKAGE_HAS_VERSION", from_entity_id: "pkg:pypi:edge-a", to_entity_id: "pkg:pypi:edge-b", source: "registry", source_record_id: "record-1" };
  const event = { event_id: "caller-event-one", entity_id: "pkg:pypi:edge-a", event_type: "observed", source: "registry", source_record_id: "event-1", summary: { note: "replay-safe" } };
  const first = await send({ schema_version: "secopsai.ontology.v1", source_instance: "runner-test", entities, relationships: [relation], events: [event], evidence_refs: [] }, "ontology-rehearsal-1");
  assert.equal(first.status, 200);
  const replay = await send({ schema_version: "secopsai.ontology.v1", source_instance: "runner-test", entities, relationships: [{ ...relation, relationship_id: "caller-rel-two" }], events: [{ ...event, event_id: "caller-event-two" }], evidence_refs: [] }, "ontology-rehearsal-2");
  assert.equal(replay.status, 200);
  const counts = migrated.db.prepare("SELECT (SELECT COUNT(*) FROM ontology_entities) AS entities, (SELECT COUNT(*) FROM ontology_relationships) AS relationships, (SELECT COUNT(*) FROM ontology_events) AS events, (SELECT COUNT(*) FROM ontology_change_log) AS changes, (SELECT COUNT(*) FROM ontology_ingest_receipts) AS receipts").get();
  assert.deepEqual({ entities: Number(counts.entities), relationships: Number(counts.relationships), events: Number(counts.events), changes: Number(counts.changes), receipts: Number(counts.receipts) }, { entities: 2, relationships: 1, events: 1, changes: 3, receipts: 2 });
  assert.equal(migrated.db.prepare("SELECT occurred_at FROM ontology_events").get().occurred_at, "1970-01-01T00:00:00Z");
  const beforeLate = migrated.db.prepare("SELECT (SELECT COUNT(*) FROM ontology_entities) AS entities, (SELECT COUNT(*) FROM ontology_evidence_refs) AS evidence, (SELECT COUNT(*) FROM ontology_relationships) AS relationships, (SELECT COUNT(*) FROM ontology_events) AS events, (SELECT COUNT(*) FROM ontology_change_log) AS changes, (SELECT COUNT(*) FROM ontology_ingest_receipts) AS receipts").get();
  const oversized = await send({ schema_version: "secopsai.ontology.v1", source_instance: "runner-test", entities: [{ entity_id: "pkg:pypi:late", entity_type: "package", namespace: "pypi", canonical_key: "late", source: "registry" }], relationships: [], events: [{ entity_id: "pkg:pypi:late", event_type: "observed", source: "registry", summary: { oversized: "x".repeat(40000) } }], evidence_refs: [] }, "ontology-rehearsal-late");
  assert.equal(oversized.status, 413);
  const afterLate = migrated.db.prepare("SELECT (SELECT COUNT(*) FROM ontology_entities) AS entities, (SELECT COUNT(*) FROM ontology_evidence_refs) AS evidence, (SELECT COUNT(*) FROM ontology_relationships) AS relationships, (SELECT COUNT(*) FROM ontology_events) AS events, (SELECT COUNT(*) FROM ontology_change_log) AS changes, (SELECT COUNT(*) FROM ontology_ingest_receipts) AS receipts").get();
  assert.deepEqual(afterLate, beforeLate);
  const rewired = await send({ schema_version: "secopsai.ontology.v1", source_instance: "runner-test", entities: [{ entity_id: "pkg:pypi:edge-a", entity_type: "repository", namespace: "pypi", canonical_key: "edge-a", source: "registry" }], relationships: [], events: [], evidence_refs: [] }, "ontology-rehearsal-rewire");
  assert.equal(rewired.status, 409);
  assert.equal(migrated.db.prepare("SELECT entity_type FROM ontology_entities WHERE entity_id=?").get("pkg:pypi:edge-a").entity_type, "package");
});

test("ontology aliases tolerate source variants and preserve same-batch conflicts", { skip: !DatabaseSync }, async () => {
  const migrated = migratedSqliteD1();
  const env = { DB: migrated.d1, CORE_BRIDGE_TOKEN: "b".repeat(44) };
  const response = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", {
    method: "POST",
    headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({
      schema_version: "secopsai.ontology.v1",
      source_instance: "runner-alias-test",
      entities: [
        {
          entity_id: "pkg:pypi:alias-a",
          entity_type: "package",
          namespace: "pypi",
          canonical_key: "alias-a",
          aliases: [
            { type: "name", value: "shared-name", source: "registry" },
            { type: "name", value: "shared-name", source: "research" },
          ],
        },
        {
          entity_id: "pkg:pypi:alias-b",
          entity_type: "package",
          namespace: "pypi",
          canonical_key: "alias-b",
          aliases: [{ type: "name", value: "shared-name", source: "registry" }],
        },
      ],
      relationships: [],
      events: [],
      evidence_refs: [],
    }),
  }), env);
  assert.equal(response.status, 200);
  assert.equal(migrated.db.prepare("SELECT COUNT(*) AS count FROM ontology_aliases").get().count, 1);
  assert.equal(migrated.db.prepare("SELECT entity_id FROM ontology_aliases").get().entity_id, "pkg:pypi:alias-a");
  assert.equal(migrated.db.prepare("SELECT COUNT(*) AS count FROM ontology_conflicts WHERE conflict_type='duplicate_alias'").get().count, 1);
});

test("ontology synchronization rejects oversized record counts and mutation batches before D1 work", async () => {
  const env = { DB: new CountingD1(), CORE_BRIDGE_TOKEN: "b".repeat(44) };
  const headers = { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" };
  const oversizedCount = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", {
    method: "POST",
    headers,
    body: JSON.stringify({
      schema_version: "secopsai.ontology.v1",
      entities: Array.from({ length: 501 }, (_, index) => ({ entity_id: `pkg:pypi:count-${index}`, entity_type: "package", namespace: "pypi", canonical_key: `count-${index}` })),
      relationships: [],
      events: [],
      evidence_refs: [],
    }),
  }), env);
  assert.equal(oversizedCount.status, 413);
  assert.equal(env.DB.firstCalls, 0);
  assert.equal(env.DB.batchCalls, 0);

  const oversizedBatch = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", {
    method: "POST",
    headers,
    body: JSON.stringify({
      schema_version: "secopsai.ontology.v1",
      entities: [],
      relationships: Array.from({ length: 500 }, () => ({ relationship_type: "CASE_HAS_SUBJECT", from_entity_id: "a:a", to_entity_id: "b:b" })),
      events: [],
      evidence_refs: [],
    }),
  }), env);
  assert.equal(oversizedBatch.status, 413);
  assert.match((await oversizedBatch.json()).detail, /D1 statement limit/);
  assert.equal(env.DB.firstCalls, 0);
  assert.equal(env.DB.batchCalls, 0);
});

test("ontology synchronization enforces the portable D1 read query budget", async () => {
  const env = { DB: new CountingD1(), CORE_BRIDGE_TOKEN: "b".repeat(44) };
  const response = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", {
    method: "POST",
    headers: { authorization: `Bearer ${"b".repeat(44)}`, "content-type": "application/json" },
    body: JSON.stringify({
      schema_version: "secopsai.ontology.v1",
      entities: Array.from({ length: 30 }, (_, index) => ({ entity_id: `pkg:pypi:budget-${index}`, entity_type: "package", namespace: "pypi", canonical_key: `budget-${index}` })),
      relationships: [],
      events: [],
      evidence_refs: [],
    }),
  }), env);
  assert.equal(response.status, 413);
  assert.equal((await response.json()).error, "d1_query_budget_exceeded");
  assert.equal(env.DB.firstCalls, 50);
  assert.equal(env.DB.batchCalls, 0);
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
  const trailingSearch = await handleRequest(new Request("https://core.example/api/v1/ontology/search/?q=package", { headers: { authorization: `Bearer ${env.CORE_READ_TOKEN}` } }), env);
  assert.equal(trailingSearch.status, 200);
  const baseSearch = await handleRequest(new Request("https://core.example/api/v1/ontology/", { headers: { authorization: `Bearer ${env.CORE_READ_TOKEN}` } }), env);
  assert.equal(baseSearch.status, 200);

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

test("ontology bridge binds runner-local projections to the configured hosted workspace", { skip: !DatabaseSync }, async () => {
  const migrated = migratedSqliteD1();
  const env = {
    DB: migrated.d1,
    CORE_BRIDGE_TOKEN: "b".repeat(44),
    CORE_READ_TOKEN: "r".repeat(44),
    CORE_WORKSPACE_ID: "hosted",
  };
  const payload = {
    schema_version: "secopsai.ontology.v1",
    source_instance: "research-runner",
    // The local runner labels its source records local.  The bridge must
    // project those records into the authenticated Core workspace so hosted
    // reads can see them without widening tenant scope.
    entities: [{
      entity_id: "pkg:pypi:runner-local",
      entity_type: "package",
      namespace: "pypi",
      canonical_key: "runner-local",
      source: "secopsai-research",
    }],
    relationships: [],
    events: [],
    evidence_refs: [],
  };
  const sync = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", {
    method: "POST",
    headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify(payload),
  }), env);
  assert.equal(sync.status, 200);
  const stored = migrated.db.prepare("SELECT workspace_id FROM ontology_entities WHERE entity_id=?").get("pkg:pypi:runner-local");
  assert.equal(stored.workspace_id, "hosted");

  const search = await handleRequest(new Request("https://core.example/api/v1/ontology/search?q=runner-local", {
    headers: { authorization: `Bearer ${env.CORE_READ_TOKEN}` },
  }), env);
  assert.equal(search.status, 200);
  const result = await search.json();
  assert.equal(result.entities.length, 1);
  assert.equal(result.entities[0].workspace_id, "hosted");
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

test("ontology synchronization rolls back all writes when a transactional batch fails", { skip: !DatabaseSync }, async () => {
  const migrated = migratedSqliteD1();
  class FailingBatchD1 extends SqliteD1 {
    async batch(statements) {
      this.db.exec("BEGIN");
      try {
        await statements[0].run();
        throw new Error("injected batch failure");
      } catch (error) {
        this.db.exec("ROLLBACK");
        throw error;
      }
    }
  }
  const env = { DB: new FailingBatchD1(migrated.db), CORE_BRIDGE_TOKEN: "b".repeat(44) };
  const response = await handleRequest(new Request("https://core.example/api/v1/ontology/sync", {
    method: "POST",
    headers: { authorization: `Bearer ${env.CORE_BRIDGE_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({
      schema_version: "secopsai.ontology.v1",
      source_instance: "rollback-test",
      entities: [{ entity_id: "pkg:pypi:rollback", entity_type: "package", namespace: "pypi", canonical_key: "rollback" }],
      relationships: [],
      events: [],
      evidence_refs: [],
    }),
  }), env);
  assert.equal(response.status, 500);
  assert.equal(migrated.db.prepare("SELECT COUNT(*) AS count FROM ontology_entities WHERE entity_id=?").get("pkg:pypi:rollback").count, 0);
  assert.equal(migrated.db.prepare("SELECT COUNT(*) AS count FROM ontology_ingest_receipts").get().count, 0);
});
