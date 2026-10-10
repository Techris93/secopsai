// Free-plan Worker that stores research-ledger checkpoints in R2 for the
// GitHub Actions research worker.  Every request needs LEDGER_STORE_TOKEN,
// except uploads during an explicit migration window (LEDGER_MIGRATION_OPEN),
// which accept a runner bridge token verified by Core Edge over a service
// binding.  That lets the old Render worker upload its ledger without anyone
// copying a credential between providers.
import { bearer, handleLedgerRequest, json, timingSafeEqual } from "../../secopsai-research-runner/src/ledger.js";
import { fastlaneTick } from "./fastlane.js";

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

// GitHub's schedule trigger is best-effort and may never start a half-hourly
// workflow, so this Worker's Cron Trigger dispatches the research worker
// instead.  GITHUB_DISPATCH_TOKEN is a fine-grained token limited to Actions
// read/write on the repository; without it the cron does nothing.
export async function dispatchResearchWorker(env, fetcher = fetch) {
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
    if (url.pathname === "/healthz") return json({ status: "ok", service: "secopsai-ledger-store" });
    const watchlistMatch = url.pathname.match(/^\/fastlane\/watchlist\/([a-z]+)$/);
    if (watchlistMatch || url.pathname === "/fastlane/status") {
      const isOwner = Boolean(env.LEDGER_STORE_TOKEN) && timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN);
      if (!isOwner) return json({ error: "unauthorized" }, 401);
      if (watchlistMatch && request.method === "PUT") return putWatchlist(request, env, watchlistMatch[1]);
      if (url.pathname === "/fastlane/status") {
        const object = await env.LEDGER.get("fastlane/state.json");
        const state = object ? JSON.parse(await object.text()) : {};
        return json({ npm_seq: state.npm_seq ?? null, dispatched_recently: Object.keys(state.dispatched || {}).length, pypi_seen: (state.pypi_seen || []).length });
      }
      return json({ error: "method not allowed" }, 405);
    }
    const owner = Boolean(env.LEDGER_STORE_TOKEN) && timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN);
    if (!owner && !(isUpload(request, url) && await bridgeVerified(request, env))) {
      return json({ error: "unauthorized" }, 401);
    }
    return handleLedgerRequest(request, env.LEDGER);
  },
};
