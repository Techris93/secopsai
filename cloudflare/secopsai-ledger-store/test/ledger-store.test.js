import assert from "node:assert/strict";
import test from "node:test";
import worker, { dispatchResearchWorker } from "../src/index.js";

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

test("cron dispatches the research worker only when a token is configured", async () => {
  const calls = [];
  const fetcher = async (url, init) => { calls.push({ url, init }); return new Response(null, { status: 204 }); };
  assert.equal((await dispatchResearchWorker({}, fetcher)).status, "skipped");
  assert.equal(calls.length, 0);
  const result = await dispatchResearchWorker({ GITHUB_DISPATCH_TOKEN: "gh" }, fetcher);
  assert.equal(result.status, "dispatched");
  assert.equal(calls[0].url, "https://api.github.com/repos/Techris93/secopsai/actions/workflows/research-worker.yml/dispatches");
  assert.equal(calls[0].init.headers.authorization, "Bearer gh");
  assert.ok(calls[0].init.headers["user-agent"], "GitHub rejects requests without a User-Agent");
  assert.deepEqual(JSON.parse(calls[0].init.body), { ref: "main", inputs: { trigger: "cloudflare-cron" } });
  const failed = await dispatchResearchWorker({ GITHUB_DISPATCH_TOKEN: "gh" }, async () => new Response("{}", { status: 401 }));
  assert.equal(failed.status, "failed");
});

import { fastlaneTick, parsePypiRss } from "../src/fastlane.js";

function memoryBucket(initial = {}) {
  const store = new Map(Object.entries(initial).map(([k, v]) => [k, JSON.stringify(v)]));
  const etags = new Map([...store.keys()].map((k) => [k, "e0"]));
  let version = 0;
  return {
    store,
    get: async (key) => (store.has(key) ? { etag: etags.get(key), text: async () => store.get(key) } : null),
    put: async (key, value, options = {}) => {
      if (options.onlyIf?.etagMatches && options.onlyIf.etagMatches !== etags.get(key)) return null;
      version += 1;
      store.set(key, value);
      etags.set(key, `e${version}`);
      return { etag: etags.get(key) };
    },
  };
}

test("fast lane dispatches only new releases of watchlisted packages, once", async () => {
  const bucket = memoryBucket({
    "fastlane/watchlist/npm.json": { names: ["axios", "lodash"] },
    "fastlane/watchlist/pypi.json": { names: ["requests"] },
    "fastlane/state.json": { npm_seq: 100, pypi_seen: [], dispatched: {} },
  });
  const rss = "<rss><channel><item><title>Requests 2.40.0</title></item><item><title>random-pkg 0.1</title></item></channel></rss>";
  const fetcher = async (url) => {
    if (url.startsWith("https://replicate.npmjs.com/_changes")) {
      return new Response(JSON.stringify({ results: [{ seq: 101, id: "axios" }, { seq: 102, id: "not-watched" }, { seq: 103, id: "lodash", deleted: true }], last_seq: 103 }));
    }
    if (url === "https://registry.npmjs.org/axios/latest") return new Response(JSON.stringify({ version: "9.9.9" }));
    if (url === "https://pypi.org/rss/updates.xml") return new Response(rss);
    throw new Error(`unexpected ${url}`);
  };
  const dispatches = [];
  const dispatch = async (workflow, inputs) => { dispatches.push({ workflow, targets: JSON.parse(inputs.targets) }); return { status: "dispatched" }; };
  const env = { LEDGER: bucket };
  const first = await fastlaneTick(env, { fetcher, now: 1_000_000, dispatch });
  assert.equal(first.targets, 2);
  assert.equal(dispatches[0].workflow, "fast-lane.yml");
  assert.deepEqual(dispatches[0].targets.map((t) => `${t.ecosystem}:${t.package}@${t.version}`).sort(), ["npm:axios@9.9.9", "pypi:Requests@2.40.0"]);
  assert.equal(JSON.parse(bucket.store.get("fastlane/state.json")).npm_seq, 103);
  const second = await fastlaneTick(env, { fetcher, now: 1_060_000, dispatch });
  assert.equal(second.targets, 0, "same releases are not dispatched twice");
});

test("fast lane retries targets when the dispatch fails", async () => {
  const bucket = memoryBucket({ "fastlane/watchlist/npm.json": { names: [] }, "fastlane/watchlist/pypi.json": { names: ["requests"] } });
  const fetcher = async () => new Response("<item><title>requests 3.0.0</title></item>");
  let calls = 0;
  const env = { LEDGER: bucket };
  await fastlaneTick(env, { fetcher, now: 5_000_000, dispatch: async () => { calls += 1; return { status: "failed" }; } });
  const state = JSON.parse(bucket.store.get("fastlane/state.json"));
  assert.equal(Object.keys(state.dispatched).length, 0, "failed dispatch is forgotten for retry");
  assert.equal(calls, 1);
  await fastlaneTick(env, { fetcher, now: 5_060_000, dispatch: async () => { calls += 1; return { status: "dispatched" }; } });
  assert.equal(calls, 2, "the failed PyPI release is retried on the next tick");
  assert.deepEqual(parsePypiRss("<item><title>a-b 1.0</title></item>"), [{ package: "a-b", version: "1.0" }]);
});

test("overlapping fast lane ticks dispatch a release once", async () => {
  const bucket = memoryBucket({
    "fastlane/watchlist/npm.json": { names: [] },
    "fastlane/watchlist/pypi.json": { names: ["requests"] },
    "fastlane/state.json": { npm_seq: 1, pypi_seen: [], dispatched: {} },
  });
  const fetcher = async () => new Response("<item><title>requests 4.0.0</title></item>");
  let calls = 0;
  const dispatch = async () => { calls += 1; return { status: "dispatched" }; };
  const env = { LEDGER: bucket };
  const results = await Promise.all([1, 2, 3].map(() => fastlaneTick(env, { fetcher, now: 9_000_000, dispatch })));
  assert.equal(calls, 1, "only the lease holder dispatches");
  assert.equal(results.filter((r) => r.skipped).length, 2);
  assert.equal(JSON.parse(bucket.store.get("fastlane/state.json")).lease_until, undefined, "lease released");
  await fastlaneTick(env, { fetcher, now: 9_060_000, dispatch });
  assert.equal(calls, 1, "the next tick sees the release as dispatched");
});
