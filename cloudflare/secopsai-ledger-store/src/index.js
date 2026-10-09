// Free-plan Worker that stores research-ledger checkpoints in R2 for the
// GitHub Actions research runner.  Every request needs LEDGER_STORE_TOKEN.
import { bearer, handleLedgerRequest, json, timingSafeEqual } from "../../secopsai-research-runner/src/ledger.js";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return json({ status: "ok", service: "secopsai-ledger-store" });
    if (!env.LEDGER_STORE_TOKEN || !timingSafeEqual(bearer(request), env.LEDGER_STORE_TOKEN)) {
      return json({ error: "unauthorized" }, 401);
    }
    return handleLedgerRequest(request, env.LEDGER);
  },
};
