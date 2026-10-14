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

test("authenticated checkpoint status uses metadata without downloading the snapshot", async () => {
  const calls = [];
  const env = { LEDGER_STORE_TOKEN: "secret", LEDGER: {
    get: async key => { calls.push(key); if(key === "ledger/LATEST_CHUNKED") return null; assert.equal(key, "ledger/LATEST"); return {text: async () => "ledger/snapshots/fixture.db.gz"}; },
    head: async key => { calls.push(key); return {size: 1450000000, uploaded: new Date("2026-10-13T09:00:00Z")}; },
  }};
  assert.equal((await worker.fetch(new Request("https://ls.example/status"), env)).status, 401);
  const result = await worker.fetch(new Request("https://ls.example/status", {headers: {authorization: "Bearer secret"}}), env);
  const status = await result.json();
  assert.equal(status.checkpoint_available, true);
  assert.equal(status.completion_retry_safe, true);
  assert.equal(status.size_bytes, 1450000000);
  assert.equal(status.uploaded_at, "2026-10-13T09:00:00.000Z");
  assert.equal(calls.length, 3);
});

import {createHash} from 'node:crypto';
test('private artifact objects validate checksum, bounds and immutable retries', async () => {
  const objects = new Map();
  const env = {LEDGER_STORE_TOKEN: 'secret', LEDGER: {
    put: async (key, stream, options) => {
      if (objects.has(key)) return null;
      const bytes = Buffer.from(await new Response(stream).arrayBuffer());
      if (createHash('sha256').update(bytes).digest('hex') !== options.sha256) throw new Error('checksum mismatch');
      const object = {size: bytes.length, customMetadata: options.customMetadata, body: bytes};
      objects.set(key, object); return object;
    }, head: async key => objects.get(key), get: async key => objects.get(key),
  }};
  const bytes = Buffer.from('benign synthetic recovery fixture');
  const hash = createHash('sha256').update(bytes).digest('hex');
  const url = `https://ls.example/artifact-objects/${hash}`;
  const put = (body, length = body.length) => new Request(url, {method:'PUT', headers:{authorization:'Bearer secret','content-length':String(length)},body});
  assert.equal((await worker.fetch(new Request(url),env)).status,401);
  assert.equal((await worker.fetch(put(bytes),env)).status,200);
  assert.equal((await worker.fetch(put(bytes),env)).status,200);
  const get = await worker.fetch(new Request(url,{headers:{authorization:'Bearer secret'}}),env);
  assert.deepEqual(Buffer.from(await get.arrayBuffer()),bytes);
  assert.equal((await worker.fetch(put(bytes,33*1024*1024),env)).status,413);
  assert.equal((await worker.fetch(put(Buffer.from('changed')),env)).status,409);
  const bad = new Request('https://ls.example/artifact-objects/'+ 'a'.repeat(64),{method:'PUT',headers:{authorization:'Bearer secret','content-length':'3'},body:'bad'});
  assert.equal((await worker.fetch(bad,env)).status,400);
  assert.equal(objects.size,1);
  assert.equal((await worker.fetch(new Request(url,{method:'DELETE',headers:{authorization:'Bearer secret'}}),env)).status,405);
});

test('fixed source relay preserves source identity and never forwards private credentials', async () => {
  const {fetchPublicSource} = await import('../src/index.js');
  let called = 0;
  const result = await fetchPublicSource('cisa-news', async (url, opts) => {
    called++;
    assert.equal(url, 'https://www.cisa.gov/news.xml');
    assert.equal(opts.redirect, 'manual');
    assert.equal(opts.headers.authorization, undefined);
    return new Response('<rss>fixture</rss>', {headers:{'content-type':'application/xml'}});
  });
  assert.equal(result.status,200);
  assert.equal(result.headers.get('x-secopsai-source-url'),'https://www.cisa.gov/news.xml');
  assert.match(result.headers.get('x-secopsai-source-sha256'),/^[a-f0-9]{64}$/);
  assert.equal((await fetchPublicSource('https://attacker.example', () => assert.fail('open proxy'))).status,404);
  assert.equal(called,1);
  assert.equal((await worker.fetch(new Request('https://ls.example/public-sources/cisa-news'),{LEDGER_STORE_TOKEN:'secret'})).status,401);
  assert.equal((await worker.fetch(new Request('https://ls.example/public-sources/cisa-news?url=https://attacker.example',{headers:{authorization:'Bearer secret'}}),{LEDGER_STORE_TOKEN:'secret'})).status,400);
});

test('source relay refuses challenges, redirects and oversized streams', async () => {
  const {fetchPublicSource} = await import('../src/index.js');
  for (const response of [new Response('denied',{status:403}),new Response('',{status:302}),new Response(new Uint8Array(4*1024*1024+1))]) {
    assert.equal((await fetchPublicSource('cisa-news', async () => response)).status,502);
  }
});

test('incremental checkpoint commits only complete immutable chunks and cannot regress the pointer', async () => {
  const {handleLedgerRequest} = await import('../../secopsai-research-runner/src/ledger.js');
  const objects = new Map();
  const bucket = {
    head: async key => objects.get(key) || null,
    get: async key => objects.has(key) ? {text:async()=>objects.get(key).text,body:objects.get(key).text} : null,
    put: async (key,text,options={}) => {objects.set(key,{text,customMetadata:options.customMetadata,size:String(text).length,uploaded:new Date()});},
  };
  const hash = 'a'.repeat(64);
  const m = {version:3,sha256:'b'.repeat(64),size_bytes:100,captured_at:'2026-10-14T10:00:00Z',chunks:[{sha256:hash,size_bytes:50,raw_sha256:'c'.repeat(64),raw_size_bytes:100}]};
  const post = value => new Request('https://ls.example/checkpoints',{method:'POST',headers:{'content-length':String(JSON.stringify(value).length)},body:JSON.stringify(value)});
  assert.equal((await handleLedgerRequest(post(m),bucket)).status,409);
  assert.equal(objects.has('ledger/LATEST_CHUNKED'),false);
  objects.set('artifacts/sha256/'+hash,{size:50,customMetadata:{sha256:hash}});
  const result = await handleLedgerRequest(post(m),bucket);
  assert.equal(result.status,200);
  const latest = objects.get('ledger/LATEST_CHUNKED').text;
  assert.equal((await handleLedgerRequest(post({...m,captured_at:'2026-10-13T10:00:00Z'}),bucket)).status,200);
  assert.equal(objects.get('ledger/LATEST_CHUNKED').text,latest);
  assert.equal((await handleLedgerRequest(post({...m,size_bytes:101}),bucket)).status,400);
  const status = await (await handleLedgerRequest(new Request('https://ls.example/status'),bucket)).json();
  assert.equal(status.protocol,'ledger-checkpoint-v3');
  assert.equal(status.captured_at,m.captured_at);
  const drillBody = JSON.stringify({...m,captured_at:'2026-10-14T11:00:00Z'});
  const drillRequest = new Request('https://ls.example/recovery-drill/checkpoints', {method:'POST',headers:{'content-length':String(drillBody.length)},body:drillBody});
  assert.equal((await handleLedgerRequest(drillRequest,bucket)).status,200);
  assert.equal(objects.get('ledger/LATEST_CHUNKED').text,latest);
  assert.ok(objects.get('ledger/recovery-drills/LATEST').text.startsWith('ledger/recovery-drills/manifests/'));
  const drill = await (await handleLedgerRequest(new Request('https://ls.example/recovery-drill/checkpoint-manifest'),bucket)).json();
  assert.equal(drill.captured_at,'2026-10-14T11:00:00Z');

});
