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

export default {
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
