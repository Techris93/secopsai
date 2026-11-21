import assert from "node:assert/strict";
import {createHmac} from "node:crypto";
import {readFileSync} from "node:fs";
import {DatabaseSync} from "node:sqlite";
import test from "node:test";
import worker from "../../blog/_worker.js";

const ORIGIN = "https://blog.secopsai.dev";
const MIGRATION = readFileSync(new URL("../../migrations/blog-subscribers/0001_blog_subscribers.sql", import.meta.url), "utf8");
const SECRET = "newsletter-test-secret";

// D1's prepare/bind/first/all/run over a real SQLite database, so the SQL is tested too.
function d1() {
  const db = new DatabaseSync(":memory:");
  db.exec(MIGRATION);
  return {
    db,
    prepare(sql) {
      const statement = db.prepare(sql);
      const bound = (args) => ({
        async first() {
          return statement.get(...args) ?? null;
        },
        async all() {
          return {results: statement.all(...args)};
        },
        async run() {
          return {meta: {changes: Number(statement.run(...args).changes)}};
        },
      });
      return {bind: (...args) => bound(args), ...bound([])};
    },
  };
}

const NOW = Date.now();
const FEED = {
  items: [
    {url: `${ORIGIN}/posts/fresh-post`, title: "Fresh <post>", summary: "Two advisories.", date_published: new Date(NOW - 3600e3).toISOString()},
    {url: `${ORIGIN}/posts/old-post.html`, title: "Old post", summary: "Old.", date_published: new Date(NOW - 10 * 86400e3).toISOString()},
  ],
};

const assets = {
  async fetch(request) {
    const path = new URL(request.url).pathname;
    if (path === "/subscribe-status") return new Response("<title>__STATUS_TITLE__</title><h1>__STATUS_TITLE__</h1><p>__STATUS_MESSAGE__</p><div>__STATUS_FORM__</div>");
    if (path === "/feed.json") return Response.json(FEED);
    if (path === "/404.html") return new Response("<h1>Page not found</h1>");
    return new Response(`asset:${path}`, {headers: {"content-type": "text/plain"}});
  },
};

function harness({resendFails = 0} = {}) {
  const store = d1();
  const sent = [];
  let failures = resendFails;
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const target = String(url);
    if (target.includes("turnstile")) return Response.json({success: true, hostname: "blog.secopsai.dev"});
    if (target.startsWith("https://api.resend.com/")) {
      if (failures > 0) {
        failures -= 1;
        return new Response("{}", {status: 500});
      }
      sent.push({path: new URL(target).pathname, key: init.headers["idempotency-key"], body: JSON.parse(init.body)});
      return Response.json({id: "email"});
    }
    throw new Error(`unexpected fetch ${target}`);
  };
  const env = {ASSETS: assets, COMMENTS_DB: store, TURNSTILE_SECRET_KEY: "t", RESEND_API_KEY: "re_test", BLOG_NEWSLETTER_SECRET: SECRET};
  return {store, sent, env, restore: () => { globalThis.fetch = realFetch; }};
}

const subscribe = (email, extra = {}, headers = {}) =>
  new Request(`${ORIGIN}/api/subscribe`, {
    method: "POST",
    headers: {"content-type": "application/json", origin: ORIGIN, "cf-connecting-ip": "203.0.113.9", ...headers},
    body: JSON.stringify({email, turnstileToken: "ok", ...extra}),
  });

const form = (path, fields, headers = {}) =>
  new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: {"content-type": "application/x-www-form-urlencoded", origin: ORIGIN, ...headers},
    body: new URLSearchParams(fields).toString(),
  });

const confirmToken = (h) => new URL(h.sent.findLast((mail) => mail.path === "/emails").body.text.match(/https:\S+/)[0]).searchParams.get("token");

function signed(body, {secret = SECRET, timestamp = Math.floor(Date.now() / 1000)} = {}) {
  const text = JSON.stringify(body);
  const signature = `sha256=${createHmac("sha256", secret).update(`${timestamp}.${text}`).digest("hex")}`;
  return new Request(`${ORIGIN}/api/newsletter/send`, {
    method: "POST",
    headers: {"content-type": "application/json", "x-newsletter-timestamp": String(timestamp), "x-newsletter-signature": signature},
    body: text,
  });
}

async function confirmed(h, email) {
  await worker.fetch(subscribe(email), h.env);
  const token = confirmToken(h);
  h.sent.length = 0;
  await worker.fetch(form("/subscribe/confirm", {token}), h.env);
  return h.store.db.prepare("SELECT * FROM blog_subscribers WHERE email = ?").get(email);
}

test("signup stores a pending address and emails a confirmation link once", async () => {
  const h = harness();
  try {
    const first = await worker.fetch(subscribe(" Reader@Example.com "), h.env);
    assert.deepEqual(await first.json(), {ok: true, pending: true});
    const row = h.store.db.prepare("SELECT * FROM blog_subscribers").get();
    assert.equal(row.email, "reader@example.com");
    assert.equal(row.status, "pending");
    assert.match(row.unsubscribe_token, /^[a-f0-9]{64}$/);
    assert.equal(h.sent.length, 1);
    assert.deepEqual(h.sent[0].body.to, ["reader@example.com"]);
    const token = confirmToken(h);
    assert.match(token, /^[a-f0-9]{64}$/);
    assert.notEqual(row.confirm_hash, token, "only the token's hash is stored");
    // A repeat inside ten minutes gets the same answer and no second email.
    const again = await worker.fetch(subscribe("reader@example.com"), h.env);
    assert.deepEqual(await again.json(), {ok: true, pending: true});
    assert.equal(h.sent.length, 1);
  } finally {
    h.restore();
  }
});

test("signup refuses bad input and fails closed without email or spam checks", async () => {
  const h = harness();
  try {
    assert.equal((await worker.fetch(subscribe("not-an-email"), h.env)).status, 400);
    assert.equal((await worker.fetch(subscribe("a@example.com", {}, {origin: "https://evil.example"}), h.env)).status, 403);
    assert.equal((await worker.fetch(subscribe("a@example.com"), {...h.env, RESEND_API_KEY: ""})).status, 503);
    assert.equal((await worker.fetch(subscribe("a@example.com"), {...h.env, TURNSTILE_SECRET_KEY: ""})).status, 403);
    const trapped = await worker.fetch(subscribe("bot@example.com", {website: "spam"}), h.env);
    assert.equal(trapped.status, 200);
    const limited = {...h.env, COMMENT_RATE_LIMITER: {limit: async () => ({success: false})}};
    assert.equal((await worker.fetch(subscribe("a@example.com"), limited)).status, 429);
    assert.equal(h.store.db.prepare("SELECT COUNT(*) n FROM blog_subscribers").get().n, 0);
    assert.equal(h.sent.length, 0);
  } finally {
    h.restore();
  }
});

test("a confirmation link asks first, then confirms only on POST", async () => {
  const h = harness();
  try {
    await worker.fetch(subscribe("reader@example.com"), h.env);
    const token = confirmToken(h);
    const page = await worker.fetch(new Request(`${ORIGIN}/subscribe/confirm?token=${token}`), h.env);
    const html = await page.text();
    assert.equal(page.status, 200);
    assert.match(html, /Confirm your subscription/);
    assert.match(html, new RegExp(`name="token" value="${token}"`));
    assert.equal(page.headers.get("referrer-policy"), "no-referrer");
    assert.equal(h.store.db.prepare("SELECT status FROM blog_subscribers").get().status, "pending", "a link prefetch must not confirm");
    const done = await worker.fetch(form("/subscribe/confirm", {token}), h.env);
    assert.match(await done.text(), /You&#39;re subscribed/);
    assert.equal(h.store.db.prepare("SELECT status FROM blog_subscribers").get().status, "confirmed");
    const twice = await worker.fetch(new Request(`${ORIGIN}/subscribe/confirm?token=${token}`), h.env);
    assert.match(await twice.text(), /You&#39;re subscribed/);
    assert.equal((await worker.fetch(new Request(`${ORIGIN}/subscribe/confirm?token=nope`), h.env)).status, 400);
    assert.equal((await worker.fetch(new Request(`${ORIGIN}/subscribe/confirm?token=${"0".repeat(64)}`), h.env)).status, 410);
    // A confirmed address asking again gets the same answer and no email.
    h.sent.length = 0;
    assert.deepEqual(await (await worker.fetch(subscribe("reader@example.com"), h.env)).json(), {ok: true, pending: true});
    assert.equal(h.sent.length, 0);
  } finally {
    h.restore();
  }
});

test("expired confirmation links do not confirm", async () => {
  const h = harness();
  try {
    await worker.fetch(subscribe("late@example.com"), h.env);
    const token = confirmToken(h);
    h.store.db.prepare("UPDATE blog_subscribers SET confirm_expires_at = ?").run(new Date(Date.now() - 1000).toISOString());
    const response = await worker.fetch(form("/subscribe/confirm", {token}), h.env);
    assert.equal(response.status, 410);
    assert.equal(h.store.db.prepare("SELECT status FROM blog_subscribers").get().status, "pending");
  } finally {
    h.restore();
  }
});

test("unsubscribe asks on GET and works as an RFC 8058 one-click POST", async () => {
  const h = harness();
  try {
    const row = await confirmed(h, "reader@example.com");
    const url = `/unsubscribe?token=${row.unsubscribe_token}`;
    const ask = await worker.fetch(new Request(`${ORIGIN}${url}`), h.env);
    assert.match(await ask.text(), /Stop getting an email/);
    assert.equal(h.store.db.prepare("SELECT status FROM blog_subscribers").get().status, "confirmed");
    // Mail providers post from their own servers, with no Origin and the token in the URL.
    const oneClick = await worker.fetch(form(url, {"List-Unsubscribe": "One-Click"}, {origin: ""}), h.env);
    assert.equal(oneClick.status, 200);
    assert.equal(h.store.db.prepare("SELECT status FROM blog_subscribers").get().status, "unsubscribed");
    assert.match(await (await worker.fetch(new Request(`${ORIGIN}${url}`), h.env)).text(), /You&#39;re unsubscribed/);
    assert.equal((await worker.fetch(new Request(`${ORIGIN}/unsubscribe?token=${"a".repeat(64)}`), h.env)).status, 404);
  } finally {
    h.restore();
  }
});

test("new posts go once to confirmed subscribers, with an unsubscribe header", async () => {
  const h = harness();
  try {
    await confirmed(h, "one@example.com");
    await confirmed(h, "two@example.com");
    await worker.fetch(subscribe("pending@example.com"), h.env);
    const gone = await confirmed(h, "gone@example.com");
    await worker.fetch(form(`/unsubscribe?token=${gone.unsubscribe_token}`, {}), h.env);
    h.sent.length = 0;

    assert.equal((await worker.fetch(signed({slugs: ["fresh-post"]}, {secret: "wrong"}), h.env)).status, 401);
    assert.equal((await worker.fetch(signed({slugs: ["fresh-post"]}, {timestamp: Math.floor(Date.now() / 1000) - 3600}), h.env)).status, 401);
    assert.equal(h.sent.length, 0);

    const response = await worker.fetch(signed({slugs: ["fresh-post", "old-post", "missing-post"]}), h.env);
    const payload = await response.json();
    assert.deepEqual(payload.results.map((result) => result.status), ["sent", "too_old", "not_in_feed"]);
    assert.equal(payload.results[0].recipients, 2);
    assert.equal(h.sent.length, 1);
    const batch = h.sent[0].body;
    assert.deepEqual(batch.map((mail) => mail.to[0]), ["one@example.com", "two@example.com"]);
    assert.match(batch[0].headers["List-Unsubscribe"], /^<https:\/\/blog\.secopsai\.dev\/unsubscribe\?token=[a-f0-9]{64}>$/);
    assert.equal(batch[0].headers["List-Unsubscribe-Post"], "List-Unsubscribe=One-Click");
    assert.match(batch[0].html, /Fresh &lt;post&gt;/, "post titles are escaped in the email");

    const again = await (await worker.fetch(signed({slugs: ["fresh-post"]}), h.env)).json();
    assert.equal(again.results[0].status, "already_sent");
    assert.equal(h.sent.length, 1);
  } finally {
    h.restore();
  }
});

test("a failed send resumes with the same idempotency key and mails nobody twice", async () => {
  const h = harness();
  try {
    await confirmed(h, "one@example.com");
    h.sent.length = 0;
    const realFetch = globalThis.fetch;
    let fail = true;
    globalThis.fetch = async (url, init) => {
      if (String(url).includes("/emails/batch") && fail) {
        fail = false;
        return new Response("{}", {status: 500});
      }
      return realFetch(url, init);
    };
    const failed = await (await worker.fetch(signed({slugs: ["fresh-post"]}), h.env)).json();
    assert.equal(failed.ok, false);
    assert.equal(failed.results[0].status, "failed");
    const retried = await (await worker.fetch(signed({slugs: ["fresh-post"]}), h.env)).json();
    assert.equal(retried.results[0].status, "sent");
    assert.equal(retried.results[0].recipients, 1);
    assert.equal(h.sent.length, 1);
    assert.match(h.sent[0].key, /^post:fresh-post:[a-f0-9]{24}$/);
  } finally {
    h.restore();
  }
});

test("browsers opening a feed get a page; feed readers and ?raw=1 get the feed", async () => {
  const browser = {accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "sec-fetch-dest": "document"};
  const cases = [
    ["/feed.xml", browser, "asset:/subscribe"],
    ["/feed.json", browser, "asset:/json-feed"],
    ["/feed.xml", {accept: "application/rss+xml, application/xml;q=0.9, */*;q=0.8"}, "asset:/feed.xml"],
    ["/feed.xml", {accept: "application/rss+xml, text/html;q=0.1"}, "asset:/feed.xml"],
    ["/feed.json", {accept: "application/feed+json"}, JSON.stringify(FEED)],
    ["/feed.xml?raw=1", browser, "asset:/feed.xml"],
  ];
  for (const [path, headers, expected] of cases) {
    const response = await worker.fetch(new Request(`${ORIGIN}${path}`, {headers}), {ASSETS: assets});
    assert.equal(await response.text(), expected, `${path} ${headers.accept}`);
    assert.match(response.headers.get("vary") || "", /Accept/);
  }
});

test("the status page template is not public and wrong methods are refused", async () => {
  for (const path of ["/subscribe-status", "/subscribe-status.html"]) {
    assert.equal((await worker.fetch(new Request(`${ORIGIN}${path}`), {ASSETS: assets})).status, 404, path);
  }
  assert.equal((await worker.fetch(new Request(`${ORIGIN}/api/subscribe`), {ASSETS: assets})).status, 405);
  assert.equal((await worker.fetch(new Request(`${ORIGIN}/api/newsletter/send`), {ASSETS: assets})).status, 405);
  assert.equal((await worker.fetch(signed({slugs: ["fresh-post"]}), {ASSETS: assets})).status, 503);
});
