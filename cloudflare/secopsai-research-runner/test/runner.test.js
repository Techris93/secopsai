import assert from "node:assert/strict";
import test from "node:test";
import worker, { ResearchRunner, LedgerStore, containerEnv, handleLedgerRequest } from "../src/index.js";

function memoryBucket() {
  const objects = new Map();
  const uploads = new Map();
  return {
    objects,
    async get(key) {
      if (!objects.has(key)) return null;
      const value = objects.get(key);
      return { body: value, text: async () => String(value) };
    },
    async put(key, value) { objects.set(key, value); },
    async delete(keys) { for (const key of [].concat(keys)) objects.delete(key); },
    async list({ prefix }) { return { objects: [...objects.keys()].filter((key) => key.startsWith(prefix)).map((key) => ({ key })) }; },
    async createMultipartUpload(key) { const id = `u${uploads.size + 1}`; uploads.set(id, { key, parts: [] }); return { uploadId: id }; },
    resumeMultipartUpload(key, id) {
      const upload = uploads.get(id);
      return {
        async uploadPart(number, body) { upload.parts[number - 1] = new Uint8Array(body); return { etag: `e${number}` }; },
        async complete() { objects.set(key, Buffer.concat(upload.parts)); },
      };
    },
  };
}

function fakeContainer() {
  return {
    running: false,
    images: { base: "registry/secopsai@sha256:abc" },
    started: null,
    intercepts: [],
    timeouts: [],
    start(options) { this.started = options; this.running = true; },
    async interceptOutboundHttp(host, fetcher) { this.intercepts.push([host, fetcher]); },
    async setInactivityTimeout(ms) { this.timeouts.push(ms); },
    monitor: () => new Promise(() => {}),
    signal(value) { this.signalled = value; },
  };
}

function fakeCtx(container) {
  const storage = new Map();
  return {
    container,
    storage: { get: async (key) => storage.get(key), put: async (key, value) => storage.set(key, value) },
    exports: { LedgerStore: ({ props }) => ({ props }) },
    waitUntil() {},
    blockConcurrencyWhile: (fn) => fn(),
  };
}

test("container env forwards only allowlisted names and pins the data dir", () => {
  const env = containerEnv({ SECOPSAI_CORE_BRIDGE_TOKEN: "b", RUNNER_ADMIN_TOKEN: "admin", CLOUDFLARE_API_TOKEN: "x", LEDGER: {} }, "tok");
  assert.equal(env.SECOPSAI_CORE_BRIDGE_TOKEN, "b");
  assert.equal("RUNNER_ADMIN_TOKEN" in env, false);
  assert.equal("CLOUDFLARE_API_TOKEN" in env, false);
  assert.equal(env.SECOPS_FINDINGS_DIR, "/home/secops/research");
  assert.equal(env.LEDGER_STORE_TOKEN, "tok");
});

test("ensureRunning starts one sized container with the ledger intercept", async () => {
  const container = fakeContainer();
  const runner = new ResearchRunner(fakeCtx(container), { SECOPSAI_CORE_BRIDGE_TOKEN: "b" });
  const first = await runner.ensureRunning("cron");
  assert.equal(first.status, "started");
  assert.deepEqual(container.started.instance, { vcpu: 1, memoryMib: 2048, diskMb: 16000 });
  assert.equal(container.started.enableInternet, true);
  assert.equal(container.intercepts[0][0], "ledger.internal");
  assert.equal(container.intercepts[0][1].props.token, container.started.env.LEDGER_STORE_TOKEN);
  const second = await runner.ensureRunning("cron");
  assert.equal(second.status, "running");
});

test("ledger store requires the per-start token", async () => {
  const store = new LedgerStore({ props: { token: "secret" } }, { LEDGER: memoryBucket() });
  const denied = await store.fetch(new Request("http://ledger.internal/snapshot"));
  assert.equal(denied.status, 401);
  const missing = await store.fetch(new Request("http://ledger.internal/snapshot", { headers: { authorization: "Bearer secret" } }));
  assert.equal(missing.status, 404);
});

test("multipart checkpoint advances LATEST only on completion and prunes old snapshots", async () => {
  const bucket = memoryBucket();
  for (let index = 0; index < 5; index += 1) bucket.objects.set(`ledger/snapshots/2026-01-0${index}.db.gz`, "old");
  const created = await (await handleLedgerRequest(new Request("http://ledger.internal/uploads", { method: "POST" }), bucket)).json();
  const part = await handleLedgerRequest(new Request(`http://ledger.internal/uploads/${created.upload_id}/parts/1?key=${created.key}`, { method: "PUT", body: "gzip-bytes" }), bucket);
  const { etag } = await part.json();
  assert.equal(bucket.objects.has("ledger/LATEST"), false);
  const done = await handleLedgerRequest(new Request(`http://ledger.internal/uploads/${created.upload_id}/complete?key=${created.key}`, {
    method: "POST", body: JSON.stringify({ parts: [{ partNumber: 1, etag }] }),
  }), bucket);
  assert.equal(done.status, 200);
  assert.equal(bucket.objects.get("ledger/LATEST"), created.key);
  const snapshots = [...bucket.objects.keys()].filter((key) => key.startsWith("ledger/snapshots/"));
  assert.equal(snapshots.length, 4);
  assert.ok(snapshots.includes(created.key));
});

test("ledger keys outside the snapshot prefix are refused", async () => {
  const response = await handleLedgerRequest(new Request("http://ledger.internal/uploads/u1/complete?key=../secrets", { method: "POST", body: "{}" }), memoryBucket());
  assert.equal(response.status, 404);
});

test("admin routes need the runner token; cron is a no-op until enabled", async () => {
  const env = { RUNNER_ADMIN_TOKEN: "admin", RESEARCH_RUNNER: { getByName: () => ({ status: async () => ({ running: false }) }) } };
  assert.equal((await worker.fetch(new Request("https://runner.example/status"), env)).status, 401);
  assert.equal((await worker.fetch(new Request("https://runner.example/status", { headers: { authorization: "Bearer admin" } }), env)).status, 200);
  let called = false;
  await worker.scheduled({}, { RUNNER_ENABLED: "false", RESEARCH_RUNNER: { getByName: () => { called = true; } } }, { waitUntil() {} });
  assert.equal(called, false);
});
