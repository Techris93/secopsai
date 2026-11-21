const MAX_COMMENT_BYTES = 16384;
const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
};
// Repository files that are uploaded with the Pages output but are not part
// of the public site.  Without an explicit 404 they are served as-is.
const PRIVATE_PATHS = [/^\/README\.md$/i, /^\/_worker\.js$/, /^\/_headers$/, /^\/functions(\/|$)/, /^\/drafts(\/|$)/, /^\/migrations(\/|$)/, /^\/data\/news-cache\.json$/, /^\/subscribe-status(\.html)?$/];

const json = (payload, init = {}) =>
  new Response(JSON.stringify(payload), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...SECURITY_HEADERS,
      ...(init.headers || {}),
    },
  });

const clean = (value, max) => String(value || "").replace(/\s+/g, " ").trim().slice(0, max);
const validSlug = (value) => /^[a-z0-9][a-z0-9-]{1,158}[a-z0-9]$/.test(value);
const d1Configured = (env) => Boolean(env.COMMENTS_DB && typeof env.COMMENTS_DB.prepare === "function");
const supabaseConfigured = (env) => Boolean(env.SUPABASE_URL && env.SUPABASE_SERVICE_ROLE_KEY);
const configured = (env) => d1Configured(env) || supabaseConfigured(env);
const turnstileRequired = (env) => String(env.BLOG_COMMENTS_ALLOW_UNVERIFIED || "").toLowerCase() !== "true";

const sha256 = async (value) => {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
};

// Comments live in D1 when the COMMENTS_DB binding is present.  The Supabase
// REST path is retained only so an existing deployment keeps working until
// its comments are migrated.
const commentStore = (env) => {
  const table = /^[a-z_][a-z0-9_]{0,62}$/.test(env.BLOG_COMMENTS_TABLE || "") ? env.BLOG_COMMENTS_TABLE : "blog_comments";
  if (d1Configured(env)) {
    return {
      async listApproved(slug) {
        const result = await env.COMMENTS_DB
          .prepare(`SELECT id, slug, name, body, created_at FROM ${table} WHERE slug = ? AND status = 'approved' ORDER BY created_at DESC LIMIT 50`)
          .bind(slug)
          .all();
        return result.results || [];
      },
      async insertPending(comment) {
        await env.COMMENTS_DB
          .prepare(`INSERT INTO ${table} (id, slug, name, email, body, status, user_agent, ip_hash_hint, created_at) VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?)`)
          .bind(crypto.randomUUID(), comment.slug, comment.name, comment.email, comment.body, comment.user_agent, comment.ip_hash_hint, new Date().toISOString())
          .run();
      },
    };
  }
  const request = async (path, init = {}) => {
    const key = env.SUPABASE_SERVICE_ROLE_KEY;
    if (!supabaseConfigured(env)) throw new Error("comments backend is not configured");
    const response = await fetch(`${env.SUPABASE_URL}/rest/v1/${path}`, {
      ...init,
      redirect: "manual",
      headers: {
        apikey: key,
        authorization: `Bearer ${key}`,
        "content-type": "application/json",
        prefer: "return=minimal",
        ...(init.headers || {}),
      },
    });
    if (!response.ok) throw new Error("comments backend unavailable");
    return response;
  };
  return {
    async listApproved(slug) {
      const response = await request(
        `${table}?select=id,slug,name,body,created_at&slug=eq.${encodeURIComponent(slug)}&status=eq.approved&order=created_at.desc&limit=50`,
        {method: "GET"},
      );
      return response.json();
    },
    async insertPending(comment) {
      await request(table, {method: "POST", body: JSON.stringify([{...comment, status: "pending"}])});
    },
  };
};

const verifyTurnstile = async (request, env, token) => {
  if (!turnstileRequired(env)) return true;
  // Fail closed: a missing secret must not silently accept unverified posts.
  if (!env.TURNSTILE_SECRET_KEY) return false;
  const responseToken = clean(token, 2048);
  if (!responseToken) return false;
  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET_KEY);
  form.append("response", responseToken);
  const ip = clean(request.headers.get("cf-connecting-ip"), 80);
  if (ip) form.append("remoteip", ip);
  try {
    const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: form,
    });
    if (!response.ok) return false;
    const result = await response.json();
    // A token minted for another site that shares the widget must not count.
    const host = new URL(request.url).hostname;
    if (result.hostname && result.hostname !== host) return false;
    return result.success === true;
  } catch {
    return false;
  }
};

const rateLimited = async (env, key) => {
  if (!env.COMMENT_RATE_LIMITER || typeof env.COMMENT_RATE_LIMITER.limit !== "function") return false;
  try {
    const {success} = await env.COMMENT_RATE_LIMITER.limit({key});
    return !success;
  } catch {
    return false;
  }
};

const readBoundedText = async (request, maxBytes) => {
  if (Number(request.headers.get("content-length") || "0") > maxBytes) return null;
  if (!request.body) return "";
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const {value, done} = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
};

const commentsGet = async (request, env) => {
  const url = new URL(request.url);
  if (url.searchParams.get("health") === "1") {
    // Public health is a liveness signal only; it never names missing secrets.
    return json({ok: true, configured: configured(env), turnstile_required: turnstileRequired(env)});
  }
  if (url.searchParams.get("config") === "1") {
    return json({
      ok: true,
      turnstile_site_key: clean(env.TURNSTILE_SITE_KEY, 200),
      turnstile_required: turnstileRequired(env),
    });
  }
  const slug = clean(url.searchParams.get("slug"), 160);
  if (!slug || !validSlug(slug)) return json({ok: false, error: "invalid slug"}, {status: 400});
  try {
    return json({ok: true, comments: await commentStore(env).listApproved(slug)});
  } catch {
    return json({ok: false, error: "comments backend unavailable"}, {status: 503});
  }
};

const commentsPost = async (request, env) => {
  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return json({ok: false, error: "content-type must be application/json"}, {status: 415});
  }
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin) {
    return json({ok: false, error: "cross-origin comments are not accepted"}, {status: 403});
  }
  const ip = clean(request.headers.get("cf-connecting-ip"), 80);
  if (await rateLimited(env, ip || "unknown")) {
    return json({ok: false, error: "too many comments; try again later"}, {status: 429, headers: {"retry-after": "60"}});
  }
  const text = await readBoundedText(request, MAX_COMMENT_BYTES);
  if (text === null) return json({ok: false, error: "payload too large"}, {status: 413});
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    return json({ok: false, error: "invalid JSON"}, {status: 400});
  }
  if (!payload || typeof payload !== "object") return json({ok: false, error: "invalid JSON"}, {status: 400});
  if (clean(payload.website, 200)) return json({ok: true, moderated: true});

  const slug = clean(payload.slug, 160);
  const name = clean(payload.name, 80);
  const email = clean(payload.email, 160);
  const body = clean(payload.body, 2000);
  if (!slug || !validSlug(slug) || !name || !email || body.length < 8) {
    return json({ok: false, error: "missing required fields"}, {status: 400});
  }
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return json({ok: false, error: "invalid email"}, {status: 400});
  }
  if (!configured(env)) return json({ok: false, error: "comments backend unavailable"}, {status: 503});
  if (!(await verifyTurnstile(request, env, payload.turnstileToken))) {
    return json({ok: false, error: "turnstile verification failed"}, {status: 403});
  }

  try {
    // Without a per-deployment salt the hash is a reversible IPv4 lookup.
    const ipHash = ip && env.BLOG_COMMENT_IP_SALT ? await sha256(`${env.BLOG_COMMENT_IP_SALT}:${ip}`) : "";
    await commentStore(env).insertPending({
      slug,
      name,
      email,
      body,
      user_agent: clean(request.headers.get("user-agent"), 240),
      ip_hash_hint: ipHash,
    });
    return json({ok: true, moderated: true});
  } catch {
    return json({ok: false, error: "comments backend unavailable"}, {status: 503});
  }
};

// ── Email subscriptions ────────────────────────────────────────────────────
// Double opt-in: /api/subscribe stores a pending address and emails a link;
// the address gets posts only after that link's page is confirmed with a POST
// (mail scanners that prefetch links cannot confirm). Every post email carries
// a one-click unsubscribe link (RFC 8058). Mail goes through Resend.
const SITE = "https://blog.secopsai.dev";
const MAX_SUBSCRIBE_BYTES = 2048;
const CONFIRM_TTL_MS = 48 * 3600 * 1000;
const CONFIRM_RESEND_MS = 10 * 60 * 1000;
const NEWSLETTER_BATCH = 100;
const NEWSLETTER_MAX_POST_AGE_MS = 3 * 86400 * 1000;
const NEWSLETTER_LOCK_MS = 5 * 60 * 1000;
const NEWSLETTER_CLOCK_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_SENDER = "SecOpsAI Security Blog <research@secopsai.dev>";
const STATUS_CSP = "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'";

const iso = (ms) => new Date(ms).toISOString();
const toHex = (buffer) => [...new Uint8Array(buffer)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
const randomToken = () => toHex(crypto.getRandomValues(new Uint8Array(32)));
const validToken = (value) => /^[a-f0-9]{64}$/.test(value || "");
const validEmail = (value) => value.length <= 254 && /^[^@\s"<>]+@[^@\s"<>]+\.[^@\s"<>]+$/.test(value);
const emailReady = (env) => d1Configured(env) && Boolean(env.RESEND_API_KEY);
const escapeHtml = (value) =>
  String(value ?? "").replace(/[&<>"']/g, (char) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"})[char]);

const hmacHex = async (secret, message) => {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  return toHex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
};

const sameText = (a, b) => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
};

const resend = async (env, path, payload, idempotencyKey) => {
  const response = await fetch(`https://api.resend.com${path}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.RESEND_API_KEY}`,
      "content-type": "application/json",
      "idempotency-key": idempotencyKey,
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) throw new Error(`email provider returned HTTP ${response.status}`);
};

const emailHtml = ({heading, text, action, footer}) => `<!doctype html>
<html lang="en"><body style="margin:0;background:#FBFAF6;color:#16191D;font-family:Inter,Arial,sans-serif">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0"><tr><td align="center" style="padding:32px 16px">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:#FFFFFF;border:1px solid #C9CDD2">
<tr><td style="padding:24px">
<p style="margin:0 0 16px;font-size:12px;color:#67707B">SecOpsAI Security Blog</p>
<h1 style="margin:0 0 12px;font-size:22px;line-height:1.3">${escapeHtml(heading)}</h1>
<p style="margin:0 0 20px;font-size:15px;line-height:1.5;color:#3E4650">${escapeHtml(text)}</p>
<a href="${escapeHtml(action.href)}" style="display:inline-block;background:#16191D;color:#FBFAF6;padding:12px 20px;text-decoration:none;font-size:14px">${escapeHtml(action.label)}</a>
</td></tr>
<tr><td style="padding:16px 24px;border-top:1px solid #C9CDD2;font-size:12px;line-height:1.5;color:#67707B">${footer}</td></tr>
</table></td></tr></table></body></html>`;

const sender = (env) => clean(env.BLOG_NEWSLETTER_FROM, 200) || DEFAULT_SENDER;

const sendConfirmation = (env, email, token, tokenHash) => {
  const link = `${SITE}/subscribe/confirm?token=${token}`;
  const text = "Confirm to get an email whenever a new post is published on the SecOpsAI Security Blog.";
  const footer = "The link expires in 48 hours. If you did not ask for this, ignore this email and nothing more will be sent.";
  return resend(env, "/emails", {
    from: sender(env),
    to: [email],
    subject: "Confirm your SecOpsAI Security Blog subscription",
    html: emailHtml({heading: "Confirm your subscription", text, action: {href: link, label: "Confirm subscription"}, footer: escapeHtml(footer)}),
    text: `${text}\n\nConfirm: ${link}\n\n${footer}\n`,
  }, `confirm:${tokenHash}`);
};

const postEmail = (env, item, subscriber) => {
  const unsubscribe = `${SITE}/unsubscribe?token=${subscriber.unsubscribe_token}`;
  const title = clean(item.title, 200);
  const summary = clean(item.summary, 600);
  return {
    from: sender(env),
    to: [subscriber.email],
    subject: title,
    html: emailHtml({
      heading: title,
      text: summary,
      action: {href: item.url, label: "Read the post"},
      footer: `You subscribed to new posts on <a href="${SITE}/" style="color:#0F4C81">blog.secopsai.dev</a>. <a href="${escapeHtml(unsubscribe)}" style="color:#0F4C81">Unsubscribe</a>.`,
    }),
    text: `${title}\n\n${summary}\n\nRead the post: ${item.url}\n\nUnsubscribe: ${unsubscribe}\n`,
    headers: {"List-Unsubscribe": `<${unsubscribe}>`, "List-Unsubscribe-Post": "List-Unsubscribe=One-Click"},
  };
};

const subscribePost = async (request, env) => {
  const unavailable = () => json({ok: false, error: "Email signup is unavailable right now. Try again later."}, {status: 503});
  if (!(request.headers.get("content-type") || "").toLowerCase().includes("application/json")) {
    return json({ok: false, error: "content-type must be application/json"}, {status: 415});
  }
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin) {
    return json({ok: false, error: "cross-origin requests are not accepted"}, {status: 403});
  }
  const ip = clean(request.headers.get("cf-connecting-ip"), 80);
  if (await rateLimited(env, `subscribe:${ip || "unknown"}`)) {
    return json({ok: false, error: "Too many attempts. Try again in a minute."}, {status: 429, headers: {"retry-after": "60"}});
  }
  const text = await readBoundedText(request, MAX_SUBSCRIBE_BYTES);
  if (text === null) return json({ok: false, error: "payload too large"}, {status: 413});
  let payload;
  try {
    payload = JSON.parse(text);
  } catch {
    return json({ok: false, error: "invalid JSON"}, {status: 400});
  }
  if (!payload || typeof payload !== "object") return json({ok: false, error: "invalid JSON"}, {status: 400});
  if (clean(payload.website, 200)) return json({ok: true, pending: true});
  const email = clean(payload.email, 300).toLowerCase();
  if (!validEmail(email)) return json({ok: false, error: "Enter a valid email address."}, {status: 400});
  if (!emailReady(env)) return unavailable();
  if (!(await verifyTurnstile(request, env, payload.turnstileToken))) {
    return json({ok: false, error: "The spam check failed. Try again."}, {status: 403});
  }

  const db = env.COMMENTS_DB;
  const now = Date.now();
  try {
    const existing = await db.prepare("SELECT status, confirm_sent_at FROM blog_subscribers WHERE email = ?").bind(email).first();
    // Every address gets the same answer, so the form never reveals who is
    // subscribed, and one address gets at most one confirmation per window.
    if (existing?.status === "confirmed") return json({ok: true, pending: true});
    if (existing?.status === "pending" && now - Date.parse(existing.confirm_sent_at || "") < CONFIRM_RESEND_MS) {
      return json({ok: true, pending: true});
    }
    const token = randomToken();
    const tokenHash = await sha256(token);
    const expires = iso(now + CONFIRM_TTL_MS);
    if (existing) {
      await db.prepare("UPDATE blog_subscribers SET status = 'pending', confirm_hash = ?, confirm_expires_at = ? WHERE email = ? AND status != 'confirmed'")
        .bind(tokenHash, expires, email).run();
    } else {
      const ipHash = ip && env.BLOG_COMMENT_IP_SALT ? await sha256(`${env.BLOG_COMMENT_IP_SALT}:${ip}`) : "";
      await db.prepare("INSERT INTO blog_subscribers (email, status, confirm_hash, confirm_expires_at, unsubscribe_token, ip_hash_hint, created_at) VALUES (?, 'pending', ?, ?, ?, ?, ?)")
        .bind(email, tokenHash, expires, randomToken(), ipHash, iso(now)).run();
    }
    await sendConfirmation(env, email, token, tokenHash);
    await db.prepare("UPDATE blog_subscribers SET confirm_sent_at = ? WHERE email = ?").bind(iso(now), email).run();
    return json({ok: true, pending: true});
  } catch {
    return unavailable();
  }
};

const STATUS = {
  confirmAsk: {title: "Confirm your subscription", message: "Confirm to get an email when a new post is published.", button: "Confirm subscription"},
  confirmed: {title: "You're subscribed", message: "You'll get an email when a new post is published."},
  expired: {title: "This link has expired", message: "Subscribe again from the blog to get a new confirmation link."},
  unsubscribeAsk: {title: "Unsubscribe", message: "Stop getting an email for each new post?", button: "Unsubscribe"},
  unsubscribed: {title: "You're unsubscribed", message: "You won't get any more emails from the blog."},
  invalid: {title: "This link isn't valid", message: "Use the unsubscribe link in the latest email from the blog."},
  error: {title: "Something went wrong", message: "Try the link again in a few minutes."},
};

const statusPage = async (request, env, state, {form = null, status = 200} = {}) => {
  let page = "<!doctype html><title>__STATUS_TITLE__</title><h1>__STATUS_TITLE__</h1><p>__STATUS_MESSAGE__</p>__STATUS_FORM__";
  try {
    const template = await env.ASSETS.fetch(new Request(new URL("/subscribe-status", request.url), {method: "GET"}));
    if (template.ok) page = await template.text();
  } catch {
    /* fall back to the bare page */
  }
  const formHtml = form
    ? `<form method="post" action="${escapeHtml(form.action)}"><input type="hidden" name="token" value="${escapeHtml(form.token)}" /><button class="button" type="submit">${escapeHtml(state.button)}</button></form>`
    : "";
  const body = page
    .replaceAll("__STATUS_TITLE__", escapeHtml(state.title))
    .replaceAll("__STATUS_MESSAGE__", escapeHtml(state.message))
    .replaceAll("__STATUS_FORM__", formHtml);
  return new Response(request.method === "HEAD" ? null : body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      // The URL carries a token: keep it out of Referer headers and indexes.
      "referrer-policy": "no-referrer",
      "x-robots-tag": "noindex",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "content-security-policy": STATUS_CSP,
    },
  });
};

const formToken = async (request) => {
  const text = await readBoundedText(request, 1024);
  return text ? new URLSearchParams(text).get("token") || "" : "";
};

const confirmSubscription = async (request, env) => {
  const post = request.method === "POST";
  if (post) {
    const origin = request.headers.get("origin");
    if (origin && origin !== new URL(request.url).origin) return statusPage(request, env, STATUS.error, {status: 403});
  }
  const token = post ? await formToken(request) : new URL(request.url).searchParams.get("token") || "";
  if (!validToken(token)) return statusPage(request, env, STATUS.expired, {status: 400});
  if (!d1Configured(env)) return statusPage(request, env, STATUS.error, {status: 503});
  try {
    const db = env.COMMENTS_DB;
    const row = await db.prepare("SELECT email, status, confirm_expires_at FROM blog_subscribers WHERE confirm_hash = ?").bind(await sha256(token)).first();
    if (row?.status === "confirmed") return statusPage(request, env, STATUS.confirmed);
    if (row?.status !== "pending" || !(Date.parse(row.confirm_expires_at || "") > Date.now())) {
      return statusPage(request, env, STATUS.expired, {status: 410});
    }
    if (!post) return statusPage(request, env, STATUS.confirmAsk, {form: {action: "/subscribe/confirm", token}});
    await db.prepare("UPDATE blog_subscribers SET status = 'confirmed', confirmed_at = ? WHERE email = ? AND status = 'pending'")
      .bind(iso(Date.now()), row.email).run();
    return statusPage(request, env, STATUS.confirmed);
  } catch {
    return statusPage(request, env, STATUS.error, {status: 503});
  }
};

const unsubscribe = async (request, env) => {
  const post = request.method === "POST";
  // One-click unsubscribe (RFC 8058) posts "List-Unsubscribe=One-Click" to the
  // link itself, so the token can be in the URL or in the form body.
  let token = new URL(request.url).searchParams.get("token") || "";
  if (post && !validToken(token)) token = await formToken(request);
  if (!validToken(token)) return statusPage(request, env, STATUS.invalid, {status: 400});
  if (!d1Configured(env)) return statusPage(request, env, STATUS.error, {status: 503});
  try {
    const db = env.COMMENTS_DB;
    const row = await db.prepare("SELECT status FROM blog_subscribers WHERE unsubscribe_token = ?").bind(token).first();
    if (!row) return statusPage(request, env, STATUS.invalid, {status: 404});
    if (row.status === "unsubscribed") return statusPage(request, env, STATUS.unsubscribed);
    if (!post) return statusPage(request, env, STATUS.unsubscribeAsk, {form: {action: "/unsubscribe", token}});
    await db.prepare("UPDATE blog_subscribers SET status = 'unsubscribed', unsubscribed_at = ? WHERE unsubscribe_token = ? AND status != 'unsubscribed'")
      .bind(iso(Date.now()), token).run();
    return statusPage(request, env, STATUS.unsubscribed);
  } catch {
    return statusPage(request, env, STATUS.error, {status: 503});
  }
};

// Called by the Blog Ops deploy job with an HMAC over "<timestamp>.<body>".
const sendPost = async (env, item, slug) => {
  const db = env.COMMENTS_DB;
  const now = Date.now();
  await db.prepare("INSERT OR IGNORE INTO blog_newsletter_sends (slug, started_at) VALUES (?, ?)").bind(slug, iso(now)).run();
  const claim = await db.prepare("UPDATE blog_newsletter_sends SET locked_until = ? WHERE slug = ? AND finished_at IS NULL AND (locked_until IS NULL OR locked_until < ?)")
    .bind(iso(now + NEWSLETTER_LOCK_MS), slug, iso(now)).run();
  const row = await db.prepare("SELECT started_at, cursor, recipients, finished_at FROM blog_newsletter_sends WHERE slug = ?").bind(slug).first();
  if (!claim?.meta?.changes) {
    return {slug, status: row?.finished_at ? "already_sent" : "in_progress", recipients: Number(row?.recipients) || 0};
  }
  let cursor = row.cursor || "";
  let sent = Number(row.recipients) || 0;
  try {
    for (;;) {
      const {results = []} = await db
        .prepare("SELECT email, unsubscribe_token FROM blog_subscribers WHERE status = 'confirmed' AND confirmed_at <= ? AND email > ? ORDER BY email LIMIT ?")
        .bind(row.started_at, cursor, NEWSLETTER_BATCH)
        .all();
      if (!results.length) break;
      // The key repeats on a retry of the same batch, so the provider drops duplicates.
      const key = `post:${slug}:${(await sha256(cursor)).slice(0, 24)}`;
      await resend(env, "/emails/batch", results.map((subscriber) => postEmail(env, item, subscriber)), key);
      cursor = results[results.length - 1].email;
      sent += results.length;
      await db.prepare("UPDATE blog_newsletter_sends SET cursor = ?, recipients = ?, locked_until = ? WHERE slug = ?")
        .bind(cursor, sent, iso(Date.now() + NEWSLETTER_LOCK_MS), slug).run();
      if (results.length < NEWSLETTER_BATCH) break;
      await new Promise((resolve) => setTimeout(resolve, 600));
    }
  } catch (error) {
    await db.prepare("UPDATE blog_newsletter_sends SET locked_until = NULL WHERE slug = ?").bind(slug).run().catch(() => {});
    return {slug, status: "failed", recipients: sent, error: clean(error?.message || error, 200)};
  }
  await db.prepare("UPDATE blog_newsletter_sends SET finished_at = ?, locked_until = NULL WHERE slug = ?").bind(iso(Date.now()), slug).run();
  return {slug, status: "sent", recipients: sent};
};

const newsletterSend = async (request, env) => {
  if (!env.BLOG_NEWSLETTER_SECRET || !emailReady(env)) return json({ok: false, error: "newsletter is not configured"}, {status: 503});
  const text = await readBoundedText(request, 4096);
  if (text === null) return json({ok: false, error: "payload too large"}, {status: 413});
  const timestamp = request.headers.get("x-newsletter-timestamp") || "";
  const signature = request.headers.get("x-newsletter-signature") || "";
  const expected = `sha256=${await hmacHex(env.BLOG_NEWSLETTER_SECRET, `${timestamp}.${text}`)}`;
  if (!/^\d{10}$/.test(timestamp) || Math.abs(Date.now() - Number(timestamp) * 1000) > NEWSLETTER_CLOCK_SKEW_MS || !sameText(signature, expected)) {
    return json({ok: false, error: "invalid signature"}, {status: 401});
  }
  let slugs;
  try {
    slugs = JSON.parse(text).slugs;
  } catch {
    return json({ok: false, error: "invalid JSON"}, {status: 400});
  }
  if (!Array.isArray(slugs) || slugs.length > 10 || !slugs.every((slug) => typeof slug === "string" && validSlug(slug))) {
    return json({ok: false, error: "slugs must be up to 10 post slugs"}, {status: 400});
  }
  // The email repeats the live feed's title, summary and link for the post.
  let items = [];
  try {
    const feed = await env.ASSETS.fetch(new Request(new URL("/feed.json", request.url), {method: "GET"}));
    items = (await feed.json()).items || [];
  } catch {
    return json({ok: false, error: "feed unavailable"}, {status: 503});
  }
  const results = [];
  for (const slug of [...new Set(slugs)]) {
    // Feed URLs dropped the .html suffix; accept both while older builds are cached.
    const item = items.find((entry) => entry.url === `${SITE}/posts/${slug}` || entry.url === `${SITE}/posts/${slug}.html`);
    if (!item) {
      results.push({slug, status: "not_in_feed"});
    } else if (!(Date.now() - Date.parse(item.date_published || "") < NEWSLETTER_MAX_POST_AGE_MS)) {
      results.push({slug, status: "too_old"});
    } else {
      try {
        results.push(await sendPost(env, item, slug));
      } catch {
        results.push({slug, status: "failed", error: "database unavailable"});
      }
    }
  }
  return json({ok: results.every((result) => result.status !== "failed"), results});
};

// Browsers dropped XSLT, so a browser opening a feed URL gets a page instead;
// feed readers, scripts and ?raw=1 still get the feed itself.
const wantsPage = (request, url) =>
  url.searchParams.get("raw") !== "1" &&
  (request.headers.get("sec-fetch-dest") === "document" || /^\s*text\/html/i.test(request.headers.get("accept") || ""));

const feedResponse = async (request, env, url) => {
  const page = wantsPage(request, url) ? (url.pathname === "/feed.json" ? "/json-feed" : "/subscribe") : "";
  const response = await env.ASSETS.fetch(page ? new Request(new URL(page, request.url), request) : request);
  const out = new Response(response.body, response);
  out.headers.append("vary", "Accept, Sec-Fetch-Dest");
  return out;
};

const methodNotAllowed = (allow) => json({ok: false, error: "method not allowed"}, {status: 405, headers: {allow}});

const notFound = (request, env) =>
  env.ASSETS.fetch(new Request(new URL("/404.html", request.url), {method: "GET"}))
    .then((page) => new Response(page.ok ? page.body : "Not Found", {
      status: 404,
      headers: {"content-type": page.ok ? "text/html; charset=utf-8" : "text/plain; charset=utf-8", "cache-control": "no-store"},
    }));

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/comments") {
      if (request.method === "HEAD") {
        return new Response(null, {
          status: 200,
          headers: {
            "cache-control": "no-store",
            "content-type": "application/json; charset=utf-8",
            "x-content-type-options": "nosniff",
          },
        });
      }
      if (request.method === "GET") return commentsGet(request, env);
      if (request.method === "POST") return commentsPost(request, env);
      return json({ok: false, error: "method not allowed"}, {status: 405, headers: {allow: "GET, HEAD, POST"}});
    }
    if (url.pathname === "/api/subscribe") {
      return request.method === "POST" ? subscribePost(request, env) : methodNotAllowed("POST");
    }
    if (url.pathname === "/api/newsletter/send") {
      return request.method === "POST" ? newsletterSend(request, env) : methodNotAllowed("POST");
    }
    if (url.pathname === "/subscribe/confirm" || url.pathname === "/unsubscribe") {
      if (!["GET", "HEAD", "POST"].includes(request.method)) return methodNotAllowed("GET, HEAD, POST");
      return url.pathname === "/unsubscribe" ? unsubscribe(request, env) : confirmSubscription(request, env);
    }
    if (PRIVATE_PATHS.some((pattern) => pattern.test(url.pathname))) return notFound(request, env);
    if (url.pathname === "/feed.json" || url.pathname === "/feed.xml") return feedResponse(request, env, url);
    if (url.pathname === "/posts") {
      const latest = new URL("/posts/", request.url);
      return env.ASSETS.fetch(new Request(latest, request));
    }
    return env.ASSETS.fetch(request);
  },
};
