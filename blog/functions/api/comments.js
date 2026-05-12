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

const sha256 = async (value) => {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
};

const supabaseRequest = async (env, path, init = {}) => {
  const url = `${env.SUPABASE_URL}/rest/v1/${path}`;
  const key = env.SUPABASE_SERVICE_ROLE_KEY || env.SUPABASE_ANON_KEY;
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
  const slug = clean(url.searchParams.get("slug"), 160);
  if (!slug) return json({ok: false, error: "missing slug"}, {status: 400});
  try {
    const table = env.BLOG_COMMENTS_TABLE || "blog_comments";
    const response = await supabaseRequest(
      env,
      `${table}?select=id,slug,name,body,created_at&slug=eq.${encodeURIComponent(slug)}&status=eq.approved&order=created_at.desc&limit=50`,
      {method: "GET"}
    );
    if (!response.ok) throw new Error(await response.text());
    return json({ok: true, comments: await response.json()});
  } catch (error) {
    return json({ok: false, error: error.message}, {status: 503});
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
  if (!slug || !name || !email || body.length < 8) {
    return json({ok: false, error: "missing required fields"}, {status: 400});
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
  } catch (error) {
    return json({ok: false, error: error.message}, {status: 503});
  }
}
