// Free-plan Worker that stores research-ledger checkpoints in R2 for the
// GitHub Actions research worker.  Every request needs LEDGER_STORE_TOKEN,
// except uploads during an explicit migration window (LEDGER_MIGRATION_OPEN),
// which accept a runner bridge token verified by Core Edge over a service
// binding.  That lets the old Render worker upload its ledger without anyone
// copying a credential between providers.
import { bearer, handleLedgerRequest, json, timingSafeEqual } from "../../secopsai-research-runner/src/ledger.js";

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
export async function dispatchResearchWorker(env, fetcher = fetch) {
  if (!env.GITHUB_DISPATCH_TOKEN) return { status: "skipped", reason: "GITHUB_DISPATCH_TOKEN is not set" };
  const repo = env.RESEARCH_WORKER_REPO || "Techris93/secopsai";
  const workflow = env.RESEARCH_WORKER_WORKFLOW || "research-worker.yml";
  const response = await fetcher(`https://api.github.com/repos/${repo}/actions/workflows/${workflow}/dispatches`, {
    method: "POST",
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${env.GITHUB_DISPATCH_TOKEN}`,
      "user-agent": "secopsai-ledger-store",
      "x-github-api-version": "2022-11-28",
      "content-type": "application/json",
    },
    body: JSON.stringify({ ref: "main", inputs: { trigger: "cloudflare-cron" } }),
  });
  const result = { status: response.status === 204 ? "dispatched" : "failed", http_status: response.status };
  console.log(JSON.stringify({ component: "research-dispatch", ...result }));
  return result;
}

export default {
  async scheduled(_controller, env, ctx) {
    ctx.waitUntil(dispatchResearchWorker(env));
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return json({ status: "ok", service: "secopsai-ledger-store" });
    const owner = Boolean(env.LEDGER_STORE_TOKEN) && timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN);
    if (!owner && !(isUpload(request, url) && await bridgeVerified(request, env))) {
      return json({ error: "unauthorized" }, 401);
    }
    return handleLedgerRequest(request, env.LEDGER);
  },
};
