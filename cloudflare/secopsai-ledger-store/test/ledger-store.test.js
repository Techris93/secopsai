import assert from "node:assert/strict";
import test from "node:test";
import worker from "../src/index.js";

test("ledger store requires its bearer token", async () => {
  const env = { LEDGER_STORE_TOKEN: "secret", LEDGER: { get: async () => null } };
  assert.equal((await worker.fetch(new Request("https://ls.example/healthz"), env)).status, 200);
  assert.equal((await worker.fetch(new Request("https://ls.example/snapshot"), env)).status, 401);
  assert.equal((await worker.fetch(new Request("https://ls.example/snapshot", { headers: { authorization: "Bearer wrong" } }), env)).status, 401);
  assert.equal((await worker.fetch(new Request("https://ls.example/snapshot", { headers: { authorization: "Bearer secret" } }), env)).status, 404);
  assert.equal((await worker.fetch(new Request("https://ls.example/snapshot", { headers: { authorization: "Bearer x" } }), {})).status, 401, "fails closed without a configured token");
});

test("bridge tokens may upload only while the migration window is open", async () => {
  const core = { fetch: async (_url, init) => new Response(null, { status: new Headers(init.headers).get("authorization") === "Bearer bridge" ? 200 : 401 }) };
  const bucket = { createMultipartUpload: async () => ({ uploadId: "u1" }), get: async () => null };
  const upload = (token) => new Request("https://ls.example/uploads", { method: "POST", headers: { authorization: `Bearer ${token}` } });
  const closed = { LEDGER_STORE_TOKEN: "secret", LEDGER: bucket, CORE: core, LEDGER_MIGRATION_OPEN: "false" };
  const open = { ...closed, LEDGER_MIGRATION_OPEN: "true" };
  assert.equal((await worker.fetch(upload("bridge"), closed)).status, 401);
  assert.equal((await worker.fetch(upload("bridge"), open)).status, 200);
  assert.equal((await worker.fetch(upload("other"), open)).status, 401);
  // Bridge tokens can never read the ledger back.
  const read = new Request("https://ls.example/snapshot", { headers: { authorization: "Bearer bridge" } });
  assert.equal((await worker.fetch(read, open)).status, 401);
});
