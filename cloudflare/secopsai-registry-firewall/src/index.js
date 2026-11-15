// SecOpsAI install firewall (frontier phase 5).
//
// Point npm or pip at this Worker instead of the public registry. It serves the
// registry's own responses with every known-malicious version removed, and
// refuses known-malicious tarballs. The blocklist (ossf/malicious-packages plus
// SecOpsAI verdicts) is built hourly into 4,096 shards per ecosystem in R2.
//
//   npm config set registry https://<worker>/npm/
//   npm config set //<worker>/npm/:_authToken <FIREWALL_TOKEN>
//   pip install --index-url https://x:<FIREWALL_TOKEN>@<worker>/pypi/simple/ <package>

const NPM_UPSTREAM = "https://registry.npmjs.org/";
const PYPI_UPSTREAM = "https://pypi.org/simple/";
const SHARD_TTL_MS = 5 * 60 * 1000;
const shardCache = new Map();

export function timingSafeEqual(left, right) {
  const a = new TextEncoder().encode(String(left));
  const b = new TextEncoder().encode(String(right));
  if (a.byteLength !== b.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < a.byteLength; index += 1) difference |= a[index] ^ b[index];
  return difference === 0;
}

export function presentedToken(request) {
  const header = request.headers.get("authorization") || "";
  if (header.startsWith("Bearer ")) return header.slice(7);
  if (header.startsWith("Basic ")) {
    try { return atob(header.slice(6)).split(":").slice(1).join(":"); } catch { return ""; }
  }
  return "";
}

export function normalize(ecosystem, name) {
  return ecosystem === "pypi" ? String(name).toLowerCase().replace(/[-_.]+/g, "-") : String(name).trim().toLowerCase();
}

async function shardOf(ecosystem, name) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(normalize(ecosystem, name)));
  return [...new Uint8Array(digest).slice(0, 2)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 3);
}

async function shardKey(ecosystem, name) {
  return `firewall/${ecosystem}/${await shardOf(ecosystem, name)}.json`;
}

async function loadShard(env, key, now = Date.now()) {
  let cached = shardCache.get(key);
  if (!cached || now - cached.at > SHARD_TTL_MS) {
    const object = await env.LEDGER.get(key);
    cached = { at: now, data: object ? JSON.parse(await object.text()) : {} };
    shardCache.set(key, cached);
  }
  return cached.data;
}

export async function entryFor(env, ecosystem, name, now = Date.now()) {
  const data = await loadShard(env, await shardKey(ecosystem, name), now);
  return data[normalize(ecosystem, name)] || null;
}

export function isBlocked(entry, version) {
  return Boolean(entry) && (entry.all || (entry.versions || []).includes(String(version)));
}

function refused(reason, entry) {
  return new Response(JSON.stringify({ error: "blocked by SecOpsAI install firewall", reason, advisories: entry?.ids || [] }),
    { status: 403, headers: { "content-type": "application/json", "x-secopsai-firewall": "blocked" } });
}

// npm --------------------------------------------------------------------------

export function filterPackument(doc, entry) {
  const removed = [];
  for (const version of Object.keys(doc.versions || {})) {
    if (isBlocked(entry, version)) {
      delete doc.versions[version];
      if (doc.time) delete doc.time[version];
      removed.push(version);
    }
  }
  const remaining = Object.keys(doc.versions || {});
  for (const [tag, version] of Object.entries(doc["dist-tags"] || {})) {
    if (removed.includes(version)) {
      // Point the tag at the newest remaining version, or drop it.
      // Newest by publish time; abbreviated documents have no times, so keep publish order.
      const fallback = doc.time ? [...remaining].sort((a, b) => Date.parse(doc.time[b] || 0) - Date.parse(doc.time[a] || 0))[0]
        : remaining[remaining.length - 1];
      if (fallback) doc["dist-tags"][tag] = fallback; else delete doc["dist-tags"][tag];
    }
  }
  return removed;
}

function npmPackageName(path) {
  // /@scope/name, /@scope%2fname, /name ; tarballs: /<name>/-/<file>.tgz
  const decoded = decodeURIComponent(path.replace(/^\/+/, ""));
  const tarball = decoded.indexOf("/-/");
  const name = tarball >= 0 ? decoded.slice(0, tarball) : decoded;
  return { name, file: tarball >= 0 ? decoded.slice(tarball + 3) : "" };
}

export function npmTarballVersion(name, file) {
  const base = name.split("/").pop();
  const match = file.match(new RegExp(`^${base.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}-(.+)\\.tgz$`));
  return match ? match[1] : "";
}

async function npm(request, env, path, origin) {
  const { name, file } = npmPackageName(path);
  if (!name || name.startsWith("-/")) return fetch(NPM_UPSTREAM + path.replace(/^\/+/, ""), { headers: forwardHeaders(request) });
  const entry = await entryFor(env, "npm", name);
  if (file) {
    const version = npmTarballVersion(name, file);
    if (isBlocked(entry, version)) return refused(`${name}@${version} is a known-malicious release`, entry);
    return fetch(`${NPM_UPSTREAM}${name}/-/${file}`, { headers: forwardHeaders(request) });
  }
  if (entry?.all) return refused(`every version of ${name} is known-malicious`, entry);
  const upstream = await fetch(NPM_UPSTREAM + encodeURIComponent(name).replace("%40", "@"), { headers: forwardHeaders(request) });
  if (!upstream.ok || !entry) return rewriteTarballs(upstream, origin);
  const doc = await upstream.json();
  const removed = filterPackument(doc, entry);
  return jsonResponse(rewriteDoc(doc, origin), { "x-secopsai-firewall": `removed ${removed.length}` });
}

function rewriteDoc(doc, origin) {
  // Tarballs come back through the firewall, so a lockfile's pinned version is checked too.
  for (const version of Object.values(doc.versions || {})) {
    if (version?.dist?.tarball) version.dist.tarball = version.dist.tarball.replace(NPM_UPSTREAM, `${origin}/npm/`);
  }
  return doc;
}

async function rewriteTarballs(upstream, origin) {
  if (!upstream.ok || !(upstream.headers.get("content-type") || "").includes("json")) return upstream;
  return jsonResponse(rewriteDoc(await upstream.json(), origin), { "x-secopsai-firewall": "removed 0" });
}

// PyPI -------------------------------------------------------------------------

export function pypiFileVersion(filename) {
  const name = String(filename);
  if (name.endsWith(".whl")) return name.split("-")[1] || "";
  const stem = name.replace(/\.(tar\.gz|tar\.bz2|tgz|zip|egg)$/, "");
  const index = stem.lastIndexOf("-");
  return index > 0 ? stem.slice(index + 1) : "";
}

async function pypi(request, env, path) {
  const project = decodeURIComponent(path.replace(/^\/+/, "").replace(/\/+$/, ""));
  if (!project) return fetch(PYPI_UPSTREAM, { headers: forwardHeaders(request) });
  const entry = await entryFor(env, "pypi", project);
  if (entry?.all) return refused(`every version of ${project} is known-malicious`, entry);
  const upstream = await fetch(`${PYPI_UPSTREAM}${project}/`, { headers: forwardHeaders(request) });
  if (!upstream.ok || !entry) return upstream;
  const type = upstream.headers.get("content-type") || "";
  if (type.includes("json")) {
    const doc = await upstream.json();
    const before = (doc.files || []).length;
    doc.files = (doc.files || []).filter((file) => !isBlocked(entry, pypiFileVersion(file.filename)));
    doc.versions = (doc.versions || []).filter((version) => !isBlocked(entry, version));
    return jsonResponse(doc, { "content-type": type, "x-secopsai-firewall": `removed ${before - doc.files.length}` });
  }
  const html = await upstream.text();
  let removed = 0;
  const filtered = html.replace(/<a\b[^>]*>([^<]+)<\/a>\s*(<br\s*\/?>)?/gi, (anchor, filename) => {
    if (isBlocked(entry, pypiFileVersion(filename.trim()))) { removed += 1; return ""; }
    return anchor;
  });
  return new Response(filtered, { status: 200, headers: { "content-type": type || "text/html", "x-secopsai-firewall": `removed ${removed}` } });
}

// shared -----------------------------------------------------------------------

function forwardHeaders(request) {
  const headers = { "user-agent": "secopsai-registry-firewall" };
  const accept = request.headers.get("accept");
  if (accept) headers.accept = accept;
  return headers;
}

// Lockfile check: POST /check {"packages": [{"ecosystem": "npm"|"pypi", "name", "version"}]} (up to 500).
export const MAX_CHECK = 500;

async function check(request, env) {
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: "invalid JSON" }, {}, 400); }
  const packages = Array.isArray(body?.packages) ? body.packages : null;
  if (!packages || packages.length > MAX_CHECK) return jsonResponse({ error: `packages must be a list of at most ${MAX_CHECK}` }, {}, 400);
  for (const item of packages) {
    if (!["npm", "pypi"].includes(item?.ecosystem) || typeof item.name !== "string" || typeof item.version !== "string") {
      return jsonResponse({ error: "each package needs ecosystem (npm or pypi), name and version" }, {}, 400);
    }
  }
  // Each distinct shard is read once, all in parallel; lookups one by one outlast client timeouts.
  const keys = [...new Set(await Promise.all(packages.map((item) => shardKey(item.ecosystem, item.name))))];
  await Promise.all(keys.map((key) => loadShard(env, key)));
  const blocked = [];
  for (const item of packages) {
    const entry = await entryFor(env, item.ecosystem, item.name);
    if (isBlocked(entry, item.version)) blocked.push({ ...item, advisories: entry.ids || [] });
  }
  return jsonResponse({ checked: packages.length, blocked });
}

function jsonResponse(value, headers = {}, status = 200) {
  return new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json", ...headers } });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") return jsonResponse({ status: "ok", service: "secopsai-registry-firewall" });
    if (!env.FIREWALL_TOKEN || !timingSafeEqual(presentedToken(request), env.FIREWALL_TOKEN)) {
      return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "content-type": "application/json", "www-authenticate": "Basic realm=\"secopsai\"" } });
    }
    if (url.pathname === "/check" && request.method === "POST") return check(request, env);
    if (!["GET", "HEAD"].includes(request.method)) return new Response("method not allowed", { status: 405 });
    const started = Date.now();
    let response;
    if (url.pathname.startsWith("/npm/")) response = await npm(request, env, url.pathname.slice(4), url.origin);
    else if (url.pathname.startsWith("/pypi/simple/")) response = await pypi(request, env, url.pathname.slice("/pypi/simple".length));
    else return new Response("not found", { status: 404 });
    const out = new Response(response.body, response);
    out.headers.set("x-secopsai-firewall-ms", String(Date.now() - started));
    return out;
  },
};
