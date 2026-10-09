import assert from "node:assert/strict";
import test from "node:test";
import worker from "../../blog/_worker.js";

const ORIGIN = "https://blog.secopsai.dev";

function fakeD1() {
  const rows = [];
  return {
    rows,
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async all() {
              return { results: rows.filter((row) => row.slug === args[0] && row.status === "approved") };
            },
            async run() {
              assert.match(sql, /INSERT INTO blog_comments/);
              const [id, slug, name, email, body, userAgent, ipHash, createdAt] = args;
              rows.push({ id, slug, name, email, body, status: "pending", user_agent: userAgent, ip_hash_hint: ipHash, created_at: createdAt });
              return { success: true };
            },
          };
        },
      };
    },
  };
}

const assets = {
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === "/404.html") return new Response("<h1>Page not found</h1>", { status: 200 });
    return new Response(`asset:${path}`, { status: 200 });
  },
};

function comment(overrides = {}) {
  return { slug: "mini-shai-hulud-emergency-advisory", name: "Analyst", email: "a@example.com", body: "Useful IOC list, thanks.", ...overrides };
}

function post(body, headers = {}) {
  return new Request(`${ORIGIN}/api/comments`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: ORIGIN, "cf-connecting-ip": "203.0.113.7", ...headers },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

test("public health never names missing secrets", async () => {
  const response = await worker.fetch(new Request(`${ORIGIN}/api/comments?health=1`), { ASSETS: assets });
  const payload = await response.json();
  assert.equal(payload.ok, true);
  assert.equal("required_missing" in payload, false);
  assert.equal("optional_missing" in payload, false);
});

test("comments fail closed without a Turnstile secret", async () => {
  const db = fakeD1();
  const response = await worker.fetch(post(comment({ turnstileToken: "x" })), { ASSETS: assets, COMMENTS_DB: db });
  assert.equal(response.status, 403);
  assert.equal(db.rows.length, 0);
});

test("verified comments are stored as pending in D1 with a salted IP hash", async () => {
  const db = fakeD1();
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ success: true, hostname: "blog.secopsai.dev" });
  try {
    const response = await worker.fetch(post(comment({ turnstileToken: "token" })), {
      ASSETS: assets, COMMENTS_DB: db, TURNSTILE_SECRET_KEY: "secret", BLOG_COMMENT_IP_SALT: "salt",
    });
    assert.equal(response.status, 200);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(db.rows.length, 1);
  assert.equal(db.rows[0].status, "pending");
  assert.match(db.rows[0].ip_hash_hint, /^[a-f0-9]{64}$/);
  // Pending comments are never returned to readers.
  const list = await worker.fetch(new Request(`${ORIGIN}/api/comments?slug=mini-shai-hulud-emergency-advisory`), { ASSETS: assets, COMMENTS_DB: db });
  assert.deepEqual((await list.json()).comments, []);
});

test("Turnstile tokens minted for another hostname are rejected", async () => {
  const db = fakeD1();
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => Response.json({ success: true, hostname: "attacker.example" });
  try {
    const response = await worker.fetch(post(comment({ turnstileToken: "token" })), { ASSETS: assets, COMMENTS_DB: db, TURNSTILE_SECRET_KEY: "secret" });
    assert.equal(response.status, 403);
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.equal(db.rows.length, 0);
});

test("oversized bodies are rejected even without content-length", async () => {
  const big = JSON.stringify(comment({ body: "x".repeat(20000) }));
  const stream = new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode(big)); controller.close(); } });
  const request = new Request(`${ORIGIN}/api/comments`, { method: "POST", headers: { "content-type": "application/json" }, body: stream, duplex: "half" });
  const response = await worker.fetch(request, { ASSETS: assets, COMMENTS_DB: fakeD1(), BLOG_COMMENTS_ALLOW_UNVERIFIED: "true" });
  assert.equal(response.status, 413);
});

test("cross-origin posts and rate-limited clients are refused", async () => {
  const env = { ASSETS: assets, COMMENTS_DB: fakeD1(), BLOG_COMMENTS_ALLOW_UNVERIFIED: "true" };
  assert.equal((await worker.fetch(post(comment(), { origin: "https://evil.example" }), env)).status, 403);
  const limited = { ...env, COMMENT_RATE_LIMITER: { limit: async () => ({ success: false }) } };
  assert.equal((await worker.fetch(post(comment()), limited)).status, 429);
});

test("repository files are not served", async () => {
  for (const path of ["/README.md", "/_worker.js", "/functions/api/comments.js", "/data/news-cache.json"]) {
    const response = await worker.fetch(new Request(`${ORIGIN}${path}`), { ASSETS: assets });
    assert.equal(response.status, 404, path);
  }
  const ok = await worker.fetch(new Request(`${ORIGIN}/feed.xml`), { ASSETS: assets });
  assert.equal(ok.status, 200);
});
