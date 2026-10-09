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
