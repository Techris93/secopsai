// Free-plan Worker that stores research-ledger checkpoints in R2 for the
// GitHub Actions research worker.  Every request needs LEDGER_STORE_TOKEN,
// except uploads during an explicit migration window (LEDGER_MIGRATION_OPEN),
// which accept a runner bridge token verified by Core Edge over a service
// binding.  That lets the old Render worker upload its ledger without anyone
// copying a credential between providers.
import { bearer, handleLedgerRequest, json, timingSafeEqual } from "../../secopsai-research-runner/src/ledger.js";
import { FastlaneCompletionError, completeFastlaneTargets, fastlaneQueueStatus, fastlaneTick } from "./fastlane.js";

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
    }
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return json({ status: "ok", service: "secopsai-ledger-store", checkpoint_protocol: "ledger-checkpoint-v2", completion_retry_safe: true });
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
