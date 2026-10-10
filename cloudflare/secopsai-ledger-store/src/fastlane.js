// Fast lane: every minute, find new releases of high-impact packages and
// start the GitHub Actions "Fast Lane" diff-and-scan for them, so a
// compromise of a popular package is analysed within minutes of publishing.
//
// State and watchlists live in R2 under fastlane/.  Watchlists are uploaded
// by the "Fast Lane Watchlists" workflow (scripts/build_watchlists.py).

const UA = { "user-agent": "secopsai-fastlane/1.0" };
const STATE_KEY = "fastlane/state.json";
const NPM_REPLICATE = "https://replicate.npmjs.com/";
const PYPI_RSS = "https://pypi.org/rss/updates.xml";
const MAX_NPM_PAGES = 3;
const NPM_PAGE = 1000;
const MAX_TARGETS_PER_TICK = 20;
const DISPATCH_MEMORY_MS = 6 * 3600 * 1000;
const WATCHLIST_TTL_MS = 10 * 60 * 1000;
// A tick that pages the npm feed can outlast the one-minute cadence; the
// lease stops an overlapping tick from re-reading unsaved state and
// dispatching the same releases again.  It expires if a tick dies.
const LEASE_MS = 5 * 60 * 1000;

let watchlistCache = { at: 0, npm: new Set(), pypi: new Set() };

export function normalizePypi(name) {
  return String(name || "").toLowerCase().replace(/[-_.]+/g, "-");
}

async function readJson(bucket, key, fallback) {
  const object = await bucket.get(key);
  if (!object) return fallback;
  try { return JSON.parse(await object.text()); } catch { return fallback; }
}

async function watchlists(bucket, now) {
  if (now - watchlistCache.at < WATCHLIST_TTL_MS && (watchlistCache.npm.size || watchlistCache.pypi.size)) return watchlistCache;
  const [npm, pypi] = await Promise.all([
    readJson(bucket, "fastlane/watchlist/npm.json", { names: [] }),
    readJson(bucket, "fastlane/watchlist/pypi.json", { names: [] }),
  ]);
  watchlistCache = { at: now, npm: new Set(npm.names || []), pypi: new Set((pypi.names || []).map(normalizePypi)) };
  return watchlistCache;
}

export function parsePypiRss(xml) {
  const items = [];
  for (const match of String(xml).matchAll(/<item>[\s\S]*?<title>([^<]+)<\/title>[\s\S]*?<\/item>/g)) {
    const parts = match[1].trim().split(/\s+/);
    if (parts.length >= 2) items.push({ package: parts[0], version: parts[parts.length - 1] });
  }
  return items;
}

async function npmLatest(name, fetcher) {
  const response = await fetcher(`https://registry.npmjs.org/${name.replace("/", "%2F")}/latest`, { headers: UA });
  if (!response.ok) return "";
  const doc = await response.json();
  return String(doc.version || "");
}

export async function fastlaneTick(env, { fetcher = fetch, now = Date.now(), dispatch } = {}) {
  const bucket = env.LEDGER;
  const stored = await bucket.get(STATE_KEY);
  let state = { npm_seq: null, pypi_seen: [], dispatched: {} };
  if (stored) { try { state = JSON.parse(await stored.text()); } catch { /* start fresh */ } }
  if (state.lease_until && now < state.lease_until) {
    return { component: "fastlane", skipped: "previous tick still running" };
  }
  // Conditional put: only one of several concurrent ticks wins the lease.
  const leased = await bucket.put(STATE_KEY, JSON.stringify({ ...state, lease_until: now + LEASE_MS }), stored ? { onlyIf: { etagMatches: stored.etag } } : undefined);
  if (!leased) return { component: "fastlane", skipped: "another tick holds the lease" };
  delete state.lease_until;
  const lists = await watchlists(bucket, now);
  const dispatched = Object.fromEntries(Object.entries(state.dispatched || {}).filter(([, at]) => now - at < DISPATCH_MEMORY_MS));
  const targets = [];
  const summary = { npm_changes: 0, npm_hits: 0, pypi_items: 0, pypi_hits: 0 };

  // npm: resume the CouchDB changes feed from the stored sequence.
  if (lists.npm.size) {
    if (state.npm_seq == null) {
      const root = await (await fetcher(NPM_REPLICATE, { headers: UA })).json();
      state.npm_seq = root.update_seq;
    } else {
      const names = new Set();
      for (let page = 0; page < MAX_NPM_PAGES; page += 1) {
        const response = await fetcher(`${NPM_REPLICATE}_changes?since=${encodeURIComponent(state.npm_seq)}&limit=${NPM_PAGE}`, { headers: UA });
        if (!response.ok) break;
        const feed = await response.json();
        for (const change of feed.results || []) {
          summary.npm_changes += 1;
          if (!change.deleted && lists.npm.has(change.id)) names.add(change.id);
        }
        if (feed.last_seq != null) state.npm_seq = feed.last_seq;
        if ((feed.results || []).length < NPM_PAGE) break;
      }
      summary.npm_hits = names.size;
      for (const name of names) {
        const version = await npmLatest(name, fetcher);
        if (version) targets.push({ ecosystem: "npm", package: name, version });
      }
    }
  }

  // PyPI: the updates feed lists the latest 100 releases.
  if (lists.pypi.size) {
    const response = await fetcher(PYPI_RSS, { headers: UA });
    if (response.ok) {
      const seen = new Set(state.pypi_seen || []);
      const items = parsePypiRss(await response.text());
      summary.pypi_items = items.length;
      for (const item of items) {
        const key = `${normalizePypi(item.package)}@${item.version}`;
        if (seen.has(key)) continue;
        if (lists.pypi.has(normalizePypi(item.package))) {
          // Marked seen only once dispatched, so a failed dispatch retries.
          summary.pypi_hits += 1;
          targets.push({ ecosystem: "pypi", package: item.package, version: item.version, seen_key: key });
        } else {
          seen.add(key);
        }
      }
      state.pypi_seen = [...seen].slice(-400);
    }
  }

  const fresh = [];
  for (const target of targets) {
    const key = `${target.ecosystem}:${target.package}@${target.version}`;
    if (dispatched[key]) continue;
    dispatched[key] = now;
    const { seen_key: _seenKey, ...clean } = target;
    fresh.push({ ...clean, seen_at: new Date(now).toISOString() });
  }
  state.dispatched = dispatched;
  let dispatchResult = { status: "none" };
  if (fresh.length) {
    dispatchResult = await dispatch("fast-lane.yml", { targets: JSON.stringify(fresh.slice(0, MAX_TARGETS_PER_TICK)), trigger: "cloudflare-cron" });
    if (dispatchResult.status !== "dispatched") {
      // Forget the keys so the next tick retries them.
      for (const target of fresh) delete dispatched[`${target.ecosystem}:${target.package}@${target.version}`];
    }
  }
  if (!fresh.length || dispatchResult.status === "dispatched") {
    const seen = new Set(state.pypi_seen || []);
    for (const target of targets) if (target.seen_key) seen.add(target.seen_key);
    state.pypi_seen = [...seen].slice(-400);
  }
  await bucket.put(STATE_KEY, JSON.stringify(state));
  const result = { component: "fastlane", ...summary, targets: fresh.length, dispatch: dispatchResult.status };
  console.log(JSON.stringify(result));
  return { ...result, fresh };
}
