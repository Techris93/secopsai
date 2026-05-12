const json = (payload, init = {}) =>
  new Response(JSON.stringify(payload), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...(init.headers || {}),
    },
  });

const clean = (value, max) => String(value || "").replace(/\s+/g, " ").trim().slice(0, max);
const validSlug = (value) => /^[a-z0-9][a-z0-9-]{1,158}[a-z0-9]$/.test(value);
const configured = (env) => Boolean(env.SUPABASE_URL && env.SUPABASE_SERVICE_ROLE_KEY);

const sha256 = async (value) => {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
};

const supabaseRequest = async (env, path, init = {}) => {
  const url = `${env.SUPABASE_URL}/rest/v1/${path}`;
  const key = env.SUPABASE_SERVICE_ROLE_KEY;
  if (!env.SUPABASE_URL || !key) {
    throw new Error("comments backend is not configured");
  }
  return fetch(url, {
    ...init,
    headers: {
      apikey: key,
      authorization: `Bearer ${key}`,
      "content-type": "application/json",
      prefer: "return=representation",
      ...(init.headers || {}),
    },
  });
};

export async function onRequestGet({request, env}) {
  const url = new URL(request.url);
  if (url.searchParams.get("health") === "1") {
    return json({
      ok: true,
      configured: configured(env),
      required_missing: [
        ...(!env.SUPABASE_URL ? ["SUPABASE_URL"] : []),
        ...(!env.SUPABASE_SERVICE_ROLE_KEY ? ["SUPABASE_SERVICE_ROLE_KEY"] : []),
      ],
      optional_missing: [
        ...(!env.BLOG_COMMENTS_TABLE ? ["BLOG_COMMENTS_TABLE"] : []),
        ...(!env.BLOG_COMMENT_IP_SALT ? ["BLOG_COMMENT_IP_SALT"] : []),
      ],
    });
  }
  const slug = clean(url.searchParams.get("slug"), 160);
  if (!slug || !validSlug(slug)) return json({ok: false, error: "invalid slug"}, {status: 400});
  try {
    const table = env.BLOG_COMMENTS_TABLE || "blog_comments";
    const response = await supabaseRequest(
      env,
      `${table}?select=id,slug,name,body,created_at&slug=eq.${encodeURIComponent(slug)}&status=eq.approved&order=created_at.desc&limit=50`,
      {method: "GET"}
    );
    if (!response.ok) throw new Error(await response.text());
    return json({ok: true, comments: await response.json()});
  } catch {
    return json({ok: false, error: "comments backend unavailable"}, {status: 503});
  }
}

export async function onRequestPost({request, env}) {
  let payload;
  try {
    payload = await request.json();
  } catch {
    return json({ok: false, error: "invalid JSON"}, {status: 400});
  }

  if (clean(payload.website, 200)) {
    return json({ok: true, moderated: true});
  }

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

  try {
    const table = env.BLOG_COMMENTS_TABLE || "blog_comments";
    const ip = clean(request.headers.get("cf-connecting-ip"), 80);
    const ipHash = ip ? await sha256(`${env.BLOG_COMMENT_IP_SALT || "secopsai-blog"}:${ip}`) : "";
    const response = await supabaseRequest(env, table, {
      method: "POST",
      body: JSON.stringify([{
        slug,
        name,
        email,
        body,
        status: "pending",
        user_agent: clean(request.headers.get("user-agent"), 240),
        ip_hash_hint: ipHash,
      }]),
    });
    if (!response.ok) throw new Error(await response.text());
    return json({ok: true, moderated: true});
  } catch {
    return json({ok: false, error: "comments backend unavailable"}, {status: 503});
  }
}
