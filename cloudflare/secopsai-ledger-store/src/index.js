// Free-plan Worker that stores research-ledger checkpoints in R2 for the
// GitHub Actions research worker.  Every request needs LEDGER_STORE_TOKEN,
// except uploads during an explicit migration window (LEDGER_MIGRATION_OPEN),
// which accept a runner bridge token verified by Core Edge over a service
// binding.  That lets the old Render worker upload its ledger without anyone
// copying a credential between providers.
import { bearer, handleLedgerRequest, json, timingSafeEqual } from "../../secopsai-research-runner/src/ledger.js";
import { FastlaneCompletionError, completeFastlaneTargets, enqueueFastlaneTargets, fastlaneQueueStatus, fastlaneTick, startFastlaneTargets } from "./fastlane.js";

const FASTLANE_CRON = "* * * * *";
const WATCHLIST_CRON = "17 3 * * *";

function isUpload(request, url) {
  return (request.method === "POST" && url.pathname === "/uploads")
    || (url.pathname.startsWith("/uploads/") && (request.method === "PUT" || request.method === "POST"));
}

async function bridgeVerified(request, env) {
  if (String(env.LEDGER_MIGRATION_OPEN || "").toLowerCase() !== "true" || !env.CORE) return false;
  const token = bearer(request);
  if (!token) return false;
  const response = await env.CORE.fetch("https://core.internal/api/v1/bridge/whoami", { headers: { authorization: `Bearer ${token}` } });
  return response.status === 200;
}

// GitHub's schedule trigger is best-effort and may never start a half-hourly
// workflow, so this Worker's Cron Trigger dispatches the research worker
// instead.  GITHUB_DISPATCH_TOKEN is a fine-grained token limited to Actions
// read/write on the repository; without it the cron does nothing.
export async function dispatchWorkflow(env, workflow, inputs, fetcher = fetch) {
  if (!env.GITHUB_DISPATCH_TOKEN) return { status: "skipped", reason: "GITHUB_DISPATCH_TOKEN is not set" };
  const repo = env.RESEARCH_WORKER_REPO || "Techris93/secopsai";
  const response = await fetcher(`https://api.github.com/repos/${repo}/actions/workflows/${workflow}/dispatches`, {
    method: "POST",
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${env.GITHUB_DISPATCH_TOKEN}`,
      "user-agent": "secopsai-ledger-store",
      "x-github-api-version": "2022-11-28",
      "content-type": "application/json",
    },
    body: JSON.stringify({ ref: "main", inputs }),
  });
  const result = { status: response.status === 204 ? "dispatched" : "failed", http_status: response.status, workflow };
  console.log(JSON.stringify({ component: "workflow-dispatch", ...result }));
  return result;
}

const ACTIVE_RUN_STATUSES = new Set(["queued", "in_progress", "waiting", "pending", "requested"]);
const DEFAULT_MIN_INTERVAL_MINUTES = 30;

// Research Worker runs share one concurrency group, and GitHub keeps only one
// pending run there: dispatching on a fixed clock while a long run is going
// queued a run that a later dispatch then cancelled.  This cron fires every few
// minutes and starts the next run only after the previous one has finished and
// at least RESEARCH_WORKER_MIN_INTERVAL_MINUTES after it started, so runs never
// queue behind each other.  If GitHub cannot be asked, it falls back to
// dispatching (the concurrency group still keeps a single ledger writer).
export async function researchWorkerDispatchDecision(env, now = Date.now(), fetcher = fetch) {
  const repo = env.RESEARCH_WORKER_REPO || "Techris93/secopsai";
  const workflow = env.RESEARCH_WORKER_WORKFLOW || "research-worker.yml";
  const minutes = Number(env.RESEARCH_WORKER_MIN_INTERVAL_MINUTES || DEFAULT_MIN_INTERVAL_MINUTES);
  try {
    const response = await fetcher(`https://api.github.com/repos/${repo}/actions/workflows/${workflow}/runs?branch=main&per_page=10`, {
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${env.GITHUB_DISPATCH_TOKEN}`,
        "user-agent": "secopsai-ledger-store",
        "x-github-api-version": "2022-11-28",
      },
    });
    // Fail closed: starting a run we cannot see queues it behind an active one.
    if (response.status !== 200) return { dispatch: false, reason: `run check returned HTTP ${response.status}` };
    const runs = (await response.json()).workflow_runs || [];
    const active = runs.find((run) => ACTIVE_RUN_STATUSES.has(run.status));
    if (active) return { dispatch: false, reason: `run ${active.id} is ${active.status}` };
    const last = runs.reduce((latest, run) => Math.max(latest, Date.parse(run.created_at) || 0), 0);
    if (last && now - last < minutes * 60_000) {
      return { dispatch: false, reason: `last run started ${Math.round((now - last) / 60_000)} min ago (< ${minutes})` };
    }
    return { dispatch: true, reason: "previous run finished" };
  } catch (error) {
    return { dispatch: false, reason: `run check failed: ${String(error).slice(0, 120)}` };
  }
}

// GitHub's schedule trigger is best-effort and may never start a half-hourly
// workflow, so this Worker's Cron Trigger dispatches the research worker
// instead.  GITHUB_DISPATCH_TOKEN is a fine-grained token limited to Actions
// read/write on the repository; without it the cron does nothing.
// Install firewall blocklist (frontier phase 5): 4,096 shards per ecosystem,
// read directly from R2 by the registry firewall Worker.
const SHARD_LIMIT_BYTES = 2 * 1024 * 1024;

export async function firewallShard(request, env, ecosystem, shard) {
  // ecosystem "manifest" with no shard: the builder's record of shard hashes.
  const key = shard ? `firewall/${ecosystem}/${shard}.json` : "firewall/manifest.json";
  if (request.method === "GET") {
    const object = await env.LEDGER.get(key);
    if (!object) return json({ error: "not found" }, 404);
    return new Response(object.body, { headers: { "content-type": "application/json", "cache-control": "no-store" } });
  }
  if (request.method !== "PUT") return json({ error: "method not allowed" }, 405);
  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > SHARD_LIMIT_BYTES) return json({ error: "shard too large" }, 413);
  let value;
  try { value = JSON.parse(body); } catch { return json({ error: "invalid json" }, 400); }
  if (!value || typeof value !== "object" || Array.isArray(value)) return json({ error: "shard must be an object" }, 400);
  await env.LEDGER.put(key, body, { httpMetadata: { contentType: "application/json" } });
  return json({ status: "stored", key, bytes: body.length });
}

// Alert digest: one object per held-back alert per day, written by the Fast
// Lane and the research worker, read once a day by scripts/alert_digest.py.
const DIGEST_MAX_ENTRIES = 100;
const DIGEST_MAX_READ = 3000;

async function digestKey(day, entry) {
  const bytes = new TextEncoder().encode(`${entry.source}|${entry.alert_id}`);
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (b) => b.toString(16).padStart(2, "0")).join("");
  return `digest/${day}/${hash.slice(0, 32)}.json`;
}

export async function digestAdd(request, env) {
  if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > 256 * 1024) return json({ error: "digest batch too large" }, 413);
  let value;
  try { value = JSON.parse(body); } catch { return json({ error: "invalid json" }, 400); }
  const entries = Array.isArray(value?.entries) ? value.entries : null;
  if (!entries || entries.length > DIGEST_MAX_ENTRIES) return json({ error: `entries must be a list of at most ${DIGEST_MAX_ENTRIES}` }, 400);
  let stored = 0;
  for (const entry of entries) {
    if (!entry || typeof entry !== "object" || typeof entry.source !== "string" || typeof entry.alert_id !== "string" || !entry.alert_id) {
      return json({ error: "each entry needs source and alert_id" }, 400);
    }
    const day = /^\d{4}-\d{2}-\d{2}/.test(String(entry.occurred_at || "")) ? String(entry.occurred_at).slice(0, 10) : new Date().toISOString().slice(0, 10);
    const text = JSON.stringify(entry);
    if (text.length > 8192) return json({ error: "digest entry too large" }, 413);
    // Same alert, same day: the later write wins, so a retried run does not duplicate it.
    await env.LEDGER.put(await digestKey(day, entry), text, { httpMetadata: { contentType: "application/json" } });
    stored += 1;
  }
  return json({ status: "stored", stored });
}

export async function digestRead(env, day) {
  const entries = [];
  let cursor;
  let truncated = false;
  do {
    const page = await env.LEDGER.list({ prefix: `digest/${day}/`, cursor, limit: 1000 });
    for (const object of page.objects) {
      if (entries.length >= DIGEST_MAX_READ) { truncated = true; break; }
      const item = await env.LEDGER.get(object.key);
      if (item) { try { entries.push(JSON.parse(await item.text())); } catch { /* skip a damaged entry */ } }
    }
    cursor = page.truncated && !truncated ? page.cursor : undefined;
  } while (cursor);
  return json({ day, entries, truncated });
}

// Public frontier scorecard: the one object anyone may read (aggregate
// measurements only). Only the owner writes it.
const SCORECARD_KEY = "public/frontier-scorecard.json";
const SCORECARD_LIMIT_BYTES = 512 * 1024;
const PUBLIC_HEADERS = { "content-type": "application/json", "cache-control": "public, max-age=300",
  "access-control-allow-origin": "https://secopsai.dev", "x-content-type-options": "nosniff" };

export async function publicScorecard(request, env, isOwner) {
  if (request.method === "GET" || request.method === "HEAD") {
    const object = await env.LEDGER.get(SCORECARD_KEY);
    if (!object) return new Response(JSON.stringify({ error: "not found" }), { status: 404, headers: PUBLIC_HEADERS });
    return new Response(request.method === "HEAD" ? null : object.body, { headers: PUBLIC_HEADERS });
  }
  if (request.method !== "PUT") return json({ error: "method not allowed" }, 405);
  if (!isOwner) return json({ error: "unauthorized" }, 401);
  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > SCORECARD_LIMIT_BYTES) return json({ error: "scorecard too large" }, 413);
  let value;
  try { value = JSON.parse(body); } catch { return json({ error: "invalid json" }, 400); }
  if (value?.schema_version !== "secopsai.frontier-scorecard.v1" || !Array.isArray(value.results)) {
    return json({ error: "not a frontier scorecard" }, 400);
  }
  await env.LEDGER.put(SCORECARD_KEY, body, { httpMetadata: { contentType: "application/json" } });
  return json({ status: "stored", key: SCORECARD_KEY, bytes: body.length });
}

// Stream scan (frontier phase 1): its cursor/backlog state and per-hour
// coverage statistics, one JSON document each, written once per run.
const STREAM_LIMIT_BYTES = 8 * 1024 * 1024;

export async function streamDocument(request, env, name) {
  const key = `stream/${name}.json`;
  if (request.method === "GET") {
    const object = await env.LEDGER.get(key);
    if (!object) return json({ error: "not found" }, 404);
    return new Response(object.body, { headers: { "content-type": "application/json", "cache-control": "no-store" } });
  }
  if (request.method !== "PUT") return json({ error: "method not allowed" }, 405);
  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > STREAM_LIMIT_BYTES) return json({ error: "stream document too large" }, 413);
  let value;
  try { value = JSON.parse(body); } catch { return json({ error: "invalid json" }, 400); }
  if (!value || typeof value !== "object" || Array.isArray(value)) return json({ error: "stream document must be an object" }, 400);
  await env.LEDGER.put(key, body, { httpMetadata: { contentType: "application/json" } });
  return json({ status: "stored", name, bytes: body.length });
}

// Every five minutes, start the stream scan unless one is still running.
export async function dispatchStreamScan(env, fetcher = fetch, now = Date.now()) {
  if (!env.GITHUB_DISPATCH_TOKEN) return { status: "skipped", reason: "GITHUB_DISPATCH_TOKEN is not set" };
  const streamEnv = { ...env, RESEARCH_WORKER_WORKFLOW: "stream-scan.yml", RESEARCH_WORKER_MIN_INTERVAL_MINUTES: "4" };
  const decision = await researchWorkerDispatchDecision(streamEnv, now, fetcher);
  if (!decision.dispatch) return { status: "skipped", reason: decision.reason };
  return dispatchWorkflow(env, "stream-scan.yml", { trigger: "cloudflare-cron" }, fetcher);
}

export async function dispatchResearchWorker(env, fetcher = fetch, now = Date.now()) {
  if (!env.GITHUB_DISPATCH_TOKEN) return { status: "skipped", reason: "GITHUB_DISPATCH_TOKEN is not set" };
  const decision = await researchWorkerDispatchDecision(env, now, fetcher);
  if (!decision.dispatch) {
    const result = { status: "skipped", reason: decision.reason };
    console.log(JSON.stringify({ component: "workflow-dispatch", workflow: env.RESEARCH_WORKER_WORKFLOW || "research-worker.yml", ...result }));
    return result;
  }
  console.log(JSON.stringify({ component: "workflow-dispatch-decision", reason: decision.reason }));
  return dispatchWorkflow(env, env.RESEARCH_WORKER_WORKFLOW || "research-worker.yml", { trigger: "cloudflare-cron" }, fetcher);
}

const WATCHLIST_ECOSYSTEMS = new Set(["npm", "pypi"]);
const MAX_WATCHLIST_BYTES = 4 * 1024 * 1024;

async function putWatchlist(request, env, ecosystem) {
  if (!WATCHLIST_ECOSYSTEMS.has(ecosystem)) return json({ error: "unknown ecosystem" }, 404);
  const body = await request.text();
  if (body.length > MAX_WATCHLIST_BYTES) return json({ error: "watchlist too large" }, 413);
  let doc;
  try { doc = JSON.parse(body); } catch { return json({ error: "invalid json" }, 400); }
  const names = Array.isArray(doc.names) ? doc.names.filter((name) => typeof name === "string" && name.length > 0 && name.length <= 214) : [];
  if (names.length < 100) return json({ error: "watchlist too small" }, 422);
  await env.LEDGER.put(`fastlane/watchlist/${ecosystem}.json`, JSON.stringify({ ecosystem, names, count: names.length, updated_at: new Date().toISOString() }));
  return json({ status: "stored", ecosystem, count: names.length });
}

// Fixed upstream identities only: this is a source collector, never an open proxy.
export const PUBLIC_SOURCES = Object.freeze({
  "cisa-news": "https://www.cisa.gov/news.xml",
  "cisa-advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
});
export async function fetchPublicSource(identity, fetcher = fetch) {
  const upstream = PUBLIC_SOURCES[identity];
  if (!upstream) return json({error: "unknown source"}, 404);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15000);
  try {
    const response = await fetcher(upstream, {redirect: "manual", signal: controller.signal,
      headers: {"user-agent": "SecOpsAI-Research/1.0 (+https://secopsai.dev)",
        accept: "application/rss+xml, application/atom+xml, application/xml;q=0.9"}});
    if (response.status !== 200) return json({error: "source_unavailable", upstream_status: response.status}, 502);
    if (!response.body) return json({error: "empty_source"}, 502);
    const reader = response.body.getReader(), pieces = [];
    let size = 0;
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 4 * 1024 * 1024) { await reader.cancel(); return json({error: "source_too_large"}, 502); }
      pieces.push(value);
    }
    if (!size) return json({error: "empty_source"}, 502);
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const piece of pieces) { bytes.set(piece, offset); offset += piece.byteLength; }
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), b => b.toString(16).padStart(2, "0")).join("");
    return new Response(bytes, {headers: {"content-type": response.headers.get("content-type") || "application/octet-stream",
      "cache-control": "no-store", "x-secopsai-source-url": upstream, "x-secopsai-source-sha256": hash,
      "x-secopsai-acquired-at": new Date().toISOString()}});
  } catch { return json({error: "source_transport_failure"}, 502); }
  finally { clearTimeout(timer); }
}

export default {
  async scheduled(controller, env, ctx) {
    if (controller.cron === FASTLANE_CRON) {
      ctx.waitUntil(fastlaneTick(env, { dispatch: (workflow, inputs) => dispatchWorkflow(env, workflow, inputs) }).catch((error) => console.log(JSON.stringify({ component: "fastlane", error: String(error).slice(0, 300) }))));
    } else if (controller.cron === WATCHLIST_CRON) {
      ctx.waitUntil(dispatchWorkflow(env, "fast-lane-watchlist.yml", {}));
    } else {
      ctx.waitUntil(dispatchResearchWorker(env));
      ctx.waitUntil(dispatchStreamScan(env));
    }
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return json({ status: "ok", service: "secopsai-ledger-store", checkpoint_protocol: "ledger-checkpoint-v2", completion_retry_safe: true });
    if (url.pathname === "/fastlane/start") {
      const isOwner = Boolean(env.LEDGER_STORE_TOKEN) && timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN);
      if (!isOwner) return json({ error: "unauthorized" }, 401);
      if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
      const body = await request.text();
      if (new TextEncoder().encode(body).byteLength > 16 * 1024) return json({ error: "start batch too large" }, 413);
      let value;
      try { value = JSON.parse(body); } catch { return json({ error: "invalid json" }, 400); }
      try {
        return json(await startFastlaneTargets(env.LEDGER, value.queue_ids, {runId: value.run_id || ""}));
      } catch (error) {
        const message = String(error?.message || error).slice(0, 200);
        if (error instanceof FastlaneCompletionError) return json({ error: message }, 422);
        return json({ error: "start_storage_unavailable", detail: message }, 503);
      }
    }
    if (url.pathname === "/fastlane/enqueue") {
      const isOwner = Boolean(env.LEDGER_STORE_TOKEN) && timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN);
      if (!isOwner) return json({ error: "unauthorized" }, 401);
      if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
      const body = await request.text();
      if (new TextEncoder().encode(body).byteLength > 64 * 1024) return json({ error: "enqueue batch too large" }, 413);
      let value;
      try { value = JSON.parse(body); } catch { return json({ error: "invalid json" }, 400); }
      try {
        return json(await enqueueFastlaneTargets(env.LEDGER, value.targets));
      } catch (error) {
        const message = String(error?.message || error).slice(0, 200);
        if (error instanceof FastlaneCompletionError) return json({ error: message }, 422);
        return json({ error: "enqueue_storage_unavailable", detail: message }, 503);
      }
    }
    if (url.pathname === "/fastlane/complete") {
      const isOwner = Boolean(env.LEDGER_STORE_TOKEN) && timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN);
      if (!isOwner) return json({ error: "unauthorized" }, 401);
      if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
      const body = await request.text();
      if (new TextEncoder().encode(body).byteLength > 64 * 1024) return json({ error: "completion batch too large" }, 413);
      let value;
      try { value = JSON.parse(body); } catch { return json({ error: "invalid json" }, 400); }
      try {
        return json(await completeFastlaneTargets(env.LEDGER, value.results, {runId: value.run_id || ""}));
      } catch (error) {
        const message = String(error?.message || error).slice(0, 200);
        if (error instanceof FastlaneCompletionError) return json({ error: message }, 422);
        console.log(JSON.stringify({ component: "fastlane-complete", error: message }));
        return json({ error: "completion_storage_unavailable", detail: message }, 503);
      }
    }
    if (url.pathname === "/digest/add" || /^\/digest\/\d{4}-\d{2}-\d{2}$/.test(url.pathname)) {
      const isOwner = Boolean(env.LEDGER_STORE_TOKEN) && timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN);
      if (!isOwner) return json({ error: "unauthorized" }, 401);
      if (url.pathname === "/digest/add") return digestAdd(request, env);
      if (request.method !== "GET") return json({ error: "method not allowed" }, 405);
      return digestRead(env, url.pathname.slice("/digest/".length));
    }
    if (url.pathname === "/public/frontier-scorecard") {
      const isOwner = Boolean(env.LEDGER_STORE_TOKEN) && timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN);
      return publicScorecard(request, env, isOwner);
    }
    const firewallMatch = url.pathname.match(/^\/firewall\/(?:(npm|pypi)\/([0-9a-f]{3})|(manifest))$/);
    if (firewallMatch) {
      const isOwner = Boolean(env.LEDGER_STORE_TOKEN) && timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN);
      if (!isOwner) return json({ error: "unauthorized" }, 401);
      return firewallMatch[3] ? firewallShard(request, env, "manifest", "") : firewallShard(request, env, firewallMatch[1], firewallMatch[2]);
    }
    const streamMatch = url.pathname.match(/^\/stream\/(state|stats)$/);
    if (streamMatch) {
      const isOwner = Boolean(env.LEDGER_STORE_TOKEN) && timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN);
      if (!isOwner) return json({ error: "unauthorized" }, 401);
      return streamDocument(request, env, streamMatch[1]);
    }
    const watchlistMatch = url.pathname.match(/^\/fastlane\/watchlist\/([a-z]+)$/);
    if (watchlistMatch || url.pathname === "/fastlane/status") {
      const isOwner = Boolean(env.LEDGER_STORE_TOKEN) && timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN);
      if (!isOwner) return json({ error: "unauthorized" }, 401);
      if (watchlistMatch && request.method === "PUT") return putWatchlist(request, env, watchlistMatch[1]);
      if (url.pathname === "/fastlane/status" && request.method === "POST") {
        // Run one tick now (operations / diagnosis); the error is returned.
        try {
          const result = await fastlaneTick(env, { dispatch: (workflow, inputs) => dispatchWorkflow(env, workflow, inputs) });
          return json({ status: "ok", ...result });
        } catch (error) {
          return json({ status: "error", error: String(error && error.stack || error).slice(0, 1000) }, 500);
        }
      }
      if (url.pathname === "/fastlane/status") {
        const object = await env.LEDGER.get("fastlane/state.json");
        const state = object ? JSON.parse(await object.text()) : {};
        return json({ npm_seq: state.npm_seq ?? null, pypi_seen: (state.pypi_seen || []).length,
          queue: await fastlaneQueueStatus(env.LEDGER) });
      }
      return json({ error: "method not allowed" }, 405);
    }
    const owner = Boolean(env.LEDGER_STORE_TOKEN) && timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN);
    if (!owner && !(isUpload(request, url) && await bridgeVerified(request, env))) {
      return json({ error: "unauthorized" }, 401);
    }
    if (url.pathname.startsWith("/public-sources/")) {
      if (!owner) return json({error: "unauthorized"}, 401);
      if (request.method !== "GET" || url.search) return json({error: "invalid source request"}, 400);
      return fetchPublicSource(url.pathname.slice("/public-sources/".length));
    }
    return handleLedgerRequest(request, env.LEDGER);
  },
};
