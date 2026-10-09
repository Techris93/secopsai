const MAX_COMMENT_BYTES = 16384;
const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
};
// Repository files that are uploaded with the Pages output but are not part
// of the public site.  Without an explicit 404 they are served as-is.
const PRIVATE_PATHS = [/^\/README\.md$/i, /^\/_worker\.js$/, /^\/_headers$/, /^\/functions(\/|$)/, /^\/drafts(\/|$)/, /^\/migrations(\/|$)/, /^\/data\/news-cache\.json$/];

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
    if (PRIVATE_PATHS.some((pattern) => pattern.test(url.pathname))) return notFound(request, env);
    if (url.pathname === "/feed.json" && url.searchParams.get("raw") !== "1" && request.headers.get("accept")?.includes("text/html")) {
      const landing = new URL("/json-feed", request.url);
      return env.ASSETS.fetch(new Request(landing, request));
    }
    if (url.pathname === "/posts") {
      const latest = new URL("/posts/", request.url);
      return env.ASSETS.fetch(new Request(latest, request));
    }
    return env.ASSETS.fetch(request);
  },
};
