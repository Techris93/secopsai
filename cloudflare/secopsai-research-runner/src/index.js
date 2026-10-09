// SecOpsAI research runner: replaces the Render background worker.
//
// A Cron Trigger asks one named Durable Object to keep a single Container
// running the Python research worker.  The SQLite ledger lives on the
// container's ephemeral disk and is checkpointed to R2 through LedgerStore,
// a Worker entrypoint reached from the container at http://ledger.internal
// via interceptOutboundHttp.  The container never holds R2 credentials.
import { DurableObject, WorkerEntrypoint } from "cloudflare:workers";

const RUNNER_NAME = "research-runner";
const LEDGER_HOST = "ledger.internal";
const SNAPSHOT_PREFIX = "ledger/snapshots/";
const LATEST_POINTER = "ledger/LATEST";
const KEEP_SNAPSHOTS = 4;
const MAX_PART_BYTES = 64 * 1024 * 1024;
const INACTIVITY_TIMEOUT_MS = 24 * 60 * 60 * 1000;
// Custom instance: the 512 MB Render plan was OOM-killed; the ledger is
// ~4 GB and a checkpoint needs a second copy plus its gzip on disk.
const INSTANCE = { vcpu: 1, memoryMib: 2048, diskMb: 16000 };
// Only these names are forwarded from Worker vars/secrets into the container.
const FORWARDED_ENV = /^(SECOPSAI_|SECOPS_|TYPESAFE_|SENTRY_DSN$)/;

function json(payload, status = 200) {
  return Response.json(payload, {
    status,
    headers: {
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    },
  });
}

function timingSafeEqual(left, right) {
  const a = new TextEncoder().encode(String(left));
  const b = new TextEncoder().encode(String(right));
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < a.byteLength; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
}

function bearer(request) {
  const header = request.headers.get("authorization") || "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

export function containerEnv(env, token) {
  const forwarded = {};
  for (const [name, value] of Object.entries(env)) {
    if (FORWARDED_ENV.test(name) && typeof value === "string") forwarded[name] = value;
  }
  return {
    ...forwarded,
    SECOPS_FINDINGS_DIR: "/home/secops/research",
    SECOPSAI_CORE_WORKER_ID: env.SECOPSAI_CORE_WORKER_ID || "cloudflare-secopsai-research-runner",
    LEDGER_STORE_URL: `http://${LEDGER_HOST}`,
    LEDGER_STORE_TOKEN: token,
  };
}

export class ResearchRunner extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    // A restarted Durable Object starts without a timeout; re-apply it so a
    // deploy of this Worker does not let the running container be reaped.
    if (ctx.container?.running) {
      ctx.blockConcurrencyWhile(() => ctx.container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS));
    }
  }

  async ensureRunning(reason = "cron") {
    const container = this.ctx.container;
    if (container.running) {
      await container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS);
      return { status: "running", reason };
    }
    const token = crypto.randomUUID() + crypto.randomUUID();
    await this.ctx.storage.put("ledgerToken", token);
    container.start({
      image: container.images.base,
      instance: INSTANCE,
      enableInternet: true,
      entrypoint: ["python", "-u", "cloudflare/secopsai-research-runner/container/supervisor.py"],
      env: containerEnv(this.env, token),
      labels: { app: "secopsai-research" },
    });
    await container.interceptOutboundHttp(LEDGER_HOST, this.ctx.exports.LedgerStore({ props: { token } }));
    await container.setInactivityTimeout(INACTIVITY_TIMEOUT_MS);
    const startedAt = new Date().toISOString();
    await this.ctx.storage.put("lastStart", { at: startedAt, reason });
    this.ctx.waitUntil(this.watch(startedAt));
    return { status: "started", reason, started_at: startedAt };
  }

  async watch(startedAt) {
    try {
      await this.ctx.container.monitor();
      await this.ctx.storage.put("lastExit", { at: new Date().toISOString(), started_at: startedAt, error: null });
    } catch (error) {
      await this.ctx.storage.put("lastExit", { at: new Date().toISOString(), started_at: startedAt, error: String(error?.message || error).slice(0, 500) });
    }
  }

  async status() {
    return {
      running: Boolean(this.ctx.container?.running),
      last_start: (await this.ctx.storage.get("lastStart")) || null,
      last_exit: (await this.ctx.storage.get("lastExit")) || null,
    };
  }

  async stop() {
    if (this.ctx.container.running) this.ctx.container.signal(15);
    return { status: "stopping" };
  }
}

// R2-backed ledger checkpoints.  Reached only from the runner container via
// interceptOutboundHttp; the per-start token is defence in depth.
export class LedgerStore extends WorkerEntrypoint {
  async fetch(request) {
    if (!this.ctx.props?.token || !timingSafeEqual(bearer(request), this.ctx.props.token)) {
      return json({ error: "unauthorized" }, 401);
    }
    return handleLedgerRequest(request, this.env.LEDGER);
  }
}

export async function handleLedgerRequest(request, bucket) {
  const url = new URL(request.url);
  const parts = url.pathname.split("/").filter(Boolean);

  if (request.method === "GET" && url.pathname === "/snapshot") {
    const pointer = await bucket.get(LATEST_POINTER);
    if (!pointer) return json({ error: "no_snapshot" }, 404);
    const object = await bucket.get(await pointer.text());
    if (!object) return json({ error: "snapshot_missing" }, 404);
    return new Response(object.body, { headers: { "content-type": "application/gzip" } });
  }

  if (request.method === "POST" && url.pathname === "/uploads") {
    const key = `${SNAPSHOT_PREFIX}${new Date().toISOString().replace(/[:.]/g, "-")}.db.gz`;
    const upload = await bucket.createMultipartUpload(key, { httpMetadata: { contentType: "application/gzip" } });
    return json({ upload_id: upload.uploadId, key });
  }

  const key = url.searchParams.get("key") || "";
  if (parts[0] === "uploads" && parts[1] && key.startsWith(SNAPSHOT_PREFIX) && !key.includes("..")) {
    const upload = bucket.resumeMultipartUpload(key, parts[1]);
    if (request.method === "PUT" && parts[2] === "parts" && /^\d{1,5}$/.test(parts[3] || "")) {
      const length = Number(request.headers.get("content-length") || 0);
      if (length > MAX_PART_BYTES) return json({ error: "part_too_large" }, 413);
      // R2 parts need a known length; parts are 32 MiB, well inside memory.
      const body = await request.arrayBuffer();
      if (body.byteLength > MAX_PART_BYTES) return json({ error: "part_too_large" }, 413);
      const uploaded = await upload.uploadPart(Number(parts[3]), body);
      return json({ etag: uploaded.etag });
    }
    if (request.method === "POST" && parts[2] === "complete") {
      const body = await request.json().catch(() => null);
      if (!Array.isArray(body?.parts) || !body.parts.length) return json({ error: "parts_required" }, 400);
      await upload.complete(body.parts);
      // Advance the pointer only after the snapshot object is complete.
      await bucket.put(LATEST_POINTER, key);
      await pruneSnapshots(bucket, key);
      return json({ key });
    }
  }
  return json({ error: "not_found" }, 404);
}

async function pruneSnapshots(bucket, latestKey) {
  const listing = await bucket.list({ prefix: SNAPSHOT_PREFIX });
  const keys = (listing.objects || []).map((object) => object.key).sort();
  const stale = keys.filter((key) => key !== latestKey).slice(0, Math.max(0, keys.length - KEEP_SNAPSHOTS));
  if (stale.length) await bucket.delete(stale);
}

export default {
  async scheduled(controller, env, ctx) {
    if (String(env.RUNNER_ENABLED || "").toLowerCase() !== "true") return;
    ctx.waitUntil(env.RESEARCH_RUNNER.getByName(RUNNER_NAME).ensureRunning("cron"));
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return json({ status: "ok", service: "secopsai-research-runner" });
    const token = env.RUNNER_ADMIN_TOKEN;
    if (!token || !timingSafeEqual(bearer(request), token)) return json({ error: "unauthorized" }, 401);
    const runner = env.RESEARCH_RUNNER.getByName(RUNNER_NAME);
    if (request.method === "GET" && url.pathname === "/status") return json(await runner.status());
    if (request.method === "POST" && url.pathname === "/start") return json(await runner.ensureRunning("manual"));
    if (request.method === "POST" && url.pathname === "/stop") return json(await runner.stop());
    return json({ error: "not_found" }, 404);
  },
};
