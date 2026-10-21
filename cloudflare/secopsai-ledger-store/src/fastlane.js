// Fast lane: every minute, find new releases of high-impact packages and
// start the GitHub Actions "Fast Lane" diff-and-scan for them, so a
// compromise of a popular package is analysed within minutes of publishing.
//
// State and watchlists live in R2 under fastlane/.  Watchlists are uploaded
// by the "Fast Lane Watchlists" workflow (scripts/build_watchlists.py).

const UA = { "user-agent": "secopsai-fastlane/1.0" };
const STATE_KEY = "fastlane/state.json";
const TARGET_PREFIX = "fastlane/targets/";
const QUEUE_PREFIX = "fastlane/queue/";
const NPM_REPLICATE = "https://replicate.npmjs.com/";
const PYPI_RSS = "https://pypi.org/rss/updates.xml";
const MAX_NPM_PAGES = 3;
const NPM_PAGE = 1000;
const MAX_TARGETS_PER_TICK = 20;
const MAX_DISPATCH_ATTEMPTS = 6;
const DISPATCH_MEMORY_MS = 6 * 3600 * 1000;
const WATCHLIST_TTL_MS = 10 * 60 * 1000;
// A tick that pages the npm feed can outlast the one-minute cadence; the
// lease stops an overlapping tick from re-reading unsaved state and
// dispatching the same releases again.  It expires if a tick dies.
const LEASE_MS = 5 * 60 * 1000;
const DISPATCH_LEASE_MS = 90 * 60 * 1000;

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
  if (!response.ok) throw Object.assign(new Error(`npm registry HTTP ${response.status}`), {status: response.status});
  const doc = await response.json();
  return String(doc.version || "");
}

async function targetId(target) {
  const identity = `${target.ecosystem}\0${target.package.toLowerCase()}\0${target.version}`;
  const bytes = new TextEncoder().encode(identity);
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), (b) => b.toString(16).padStart(2, "0")).join("");
}

function timeKey(value) {
  return String(Math.max(0, Date.parse(value) || 0)).padStart(16, "0");
}

function queueIndex(state, item) {
  return `${QUEUE_PREFIX}${state}/${timeKey(item.created_at)}_${item.queue_id}.json`;
}

async function persistTarget(bucket, target, now) {
  const id = await targetId(target);
  const key = `${TARGET_PREFIX}${id}.json`;
  const existing = await bucket.get(key);
  let item;
  if (existing) {
    item = JSON.parse(await existing.text());
  } else {
    item = {queue_id: id, target: {...target}, state: "queued", attempt: 0,
      created_at: new Date(now).toISOString(), retry_at: now, dispatch_lease_until: null, last_outcome: null};
    await bucket.put(key, JSON.stringify(item));
  }
  if (["queued", "dispatched", "incomplete", "failed", "completed"].includes(item.state)) {
    await bucket.put(queueIndex(item.state, item), JSON.stringify({queue_id: id}));
  }
  return id;
}

async function readQueued(bucket, now, limit) {
  const listing = await bucket.list({prefix: `${QUEUE_PREFIX}queued/`, limit: 1000});
  const picked = [];
  for (const entry of listing.objects || []) {
    if (picked.length >= limit) break;
    const index = await bucket.get(entry.key);
    if (!index) continue;
    const {queue_id: id} = JSON.parse(await index.text());
    const object = await bucket.get(`${TARGET_PREFIX}${id}.json`);
    if (!object) continue;
    const item = JSON.parse(await object.text());
    if (item.state === "queued" && Number(item.retry_at || 0) <= now) picked.push(item);
  }
  return picked;
}

async function recoverExpiredDispatches(bucket, now, limit = 100) {
  const listing = await bucket.list({prefix: `${QUEUE_PREFIX}dispatched/`, limit: 1000});
  let recovered = 0;
  for (const entry of listing.objects || []) {
    if (recovered >= limit) break;
    const index = await bucket.get(entry.key);
    if (!index) continue;
    const {queue_id: id} = JSON.parse(await index.text());
    const key = `${TARGET_PREFIX}${id}.json`;
    const object = await bucket.get(key);
    if (!object) continue;
    const item = JSON.parse(await object.text());
    if (item.state !== "dispatched" || Number(item.dispatch_lease_until || 0) > now) continue;
    await bucket.delete(entry.key);
    item.state = "queued";
    item.retry_at = now;
    item.dispatch_lease_until = null;
    item.last_outcome = {status: "missing_completion_receipt", at: new Date(now).toISOString()};
    await bucket.put(key, JSON.stringify(item));
    await bucket.put(queueIndex("queued", item), JSON.stringify({queue_id: id}));
    recovered += 1;
  }
  return recovered;
}

async function dispatchQueued(bucket, dispatch, now) {
  const recovered = await recoverExpiredDispatches(bucket, now);
  const items = await readQueued(bucket, now, MAX_TARGETS_PER_TICK);
  if (!items.length) return {status: "none", targets: [], recovered};
  const targets = items.map((item) => ({...item.target, _queue_id: item.queue_id, seen_at: item.created_at}));
  const result = await dispatch("fast-lane.yml", {targets: JSON.stringify(targets), trigger: "cloudflare-cron"});
  if (result.status === "dispatched") {
    for (const item of items) {
      await bucket.delete(queueIndex("queued", item));
      item.state = "dispatched";
      item.attempt = Number(item.attempt || 0) + 1;
      item.last_dispatched_at = new Date(now).toISOString();
      item.dispatch_lease_until = now + DISPATCH_LEASE_MS;
      await bucket.put(`${TARGET_PREFIX}${item.queue_id}.json`, JSON.stringify(item));
      await bucket.put(queueIndex("dispatched", item), JSON.stringify({queue_id: item.queue_id}));
    }
  }
  return {status: result.status, targets, recovered};
}

export async function completeFastlaneTargets(bucket, results, {now = Date.now(), runId = ""} = {}) {
  if (!Array.isArray(results) || results.length > MAX_TARGETS_PER_TICK) throw new Error("invalid fast-lane completion batch");
  const accepted = new Set(["analyzed", "incomplete", "retryable_failure", "error", "skipped: not a fresh release"]);
  let completed = 0, retried = 0, unresolved = 0;
  for (const result of results) {
    if (!result || typeof result.queue_id !== "string" || !/^[a-f0-9]{64}$/.test(result.queue_id) || !accepted.has(result.status)) {
      throw new Error("invalid fast-lane target completion");
    }
    const key = `${TARGET_PREFIX}${result.queue_id}.json`;
    const object = await bucket.get(key);
    if (!object) throw new Error("unknown fast-lane target");
    const item = JSON.parse(await object.text());
    const outcome = {status: result.status, failure_category: String(result.failure_category || "").slice(0, 100),
      http_status: Number.isInteger(result.http_status) ? result.http_status : null,
      reasons: String(result.reasons || "").slice(0, 300), run_id: String(runId).slice(0, 80),
      completed_at: new Date(now).toISOString()};
    if (item.last_outcome?.status === outcome.status && item.last_outcome?.run_id === outcome.run_id && item.state !== "dispatched") {
      completed += 1;
      continue;
    }
    if (item.state !== "dispatched") throw new Error("fast-lane target is not awaiting a dispatch receipt");
    await bucket.delete(queueIndex("dispatched", item));
    item.last_outcome = outcome;
    item.dispatch_lease_until = null;
    if (result.status === "retryable_failure") {
      if (Number(item.attempt || 0) >= MAX_DISPATCH_ATTEMPTS) {
        item.state = "incomplete";
        item.last_outcome.retry_exhausted = true;
        await bucket.put(queueIndex("incomplete", item), JSON.stringify({queue_id: item.queue_id}));
        unresolved += 1;
      } else {
        item.state = "queued";
        item.retry_at = now + Math.min(60 * 60 * 1000, 30_000 * (2 ** Math.min(item.attempt, 6)));
        await bucket.put(queueIndex("queued", item), JSON.stringify({queue_id: item.queue_id}));
        retried += 1;
      }
    } else if (result.status === "analyzed" || result.status === "skipped: not a fresh release") {
      item.state = "completed";
      completed += 1;
      await bucket.put(queueIndex("completed", item), JSON.stringify({queue_id: item.queue_id}));
    } else {
      item.state = result.status === "incomplete" ? "incomplete" : "failed";
      unresolved += 1;
      await bucket.put(queueIndex(item.state, item), JSON.stringify({queue_id: item.queue_id}));
    }
    await bucket.put(key, JSON.stringify(item));
  }
  return {status: "stored", completed, retried, unresolved};
}

export async function fastlaneQueueStatus(bucket) {
  const result = {};
  for (const state of ["queued", "dispatched", "incomplete", "failed", "completed"]) {
    const listing = await bucket.list({prefix: `${QUEUE_PREFIX}${state}/`, limit: 1000});
    result[state] = (listing.objects || []).length;
    if (listing.truncated) result[state + "_more"] = true;
  }
  return result;
}

export async function fastlaneTick(env, { fetcher = fetch, now = Date.now(), dispatch } = {}) {
  const bucket = env.LEDGER;
  const stored = await bucket.get(STATE_KEY);
  let state = { npm_seq: null, pypi_seen: [] };
  if (stored) { try { state = JSON.parse(await stored.text()); } catch { /* start fresh */ } }
  if (state.lease_until && now < state.lease_until) {
    return { component: "fastlane", skipped: "previous tick still running" };
  }
  // Conditional put: only one of several concurrent ticks wins the lease.
  const leased = await bucket.put(STATE_KEY, JSON.stringify({ ...state, lease_until: now + LEASE_MS }), stored ? { onlyIf: { etagMatches: stored.etag } } : undefined);
  if (!leased) return { component: "fastlane", skipped: "another tick holds the lease" };
  const committedState = {...state};
  delete state.lease_until;
  let committed = false;
  try {
  const lists = await watchlists(bucket, now);
  const targets = [];
  const summary = { npm_changes: 0, npm_hits: 0, pypi_items: 0, pypi_hits: 0 };

  // npm: resume the CouchDB changes feed from the stored sequence.
  if (lists.npm.size) {
    if (state.npm_seq == null) {
      const rootResponse = await fetcher(NPM_REPLICATE, { headers: UA });
      if (!rootResponse.ok) throw Object.assign(new Error(`npm changes feed HTTP ${rootResponse.status}`), {status: rootResponse.status});
      const root = await rootResponse.json();
      state.npm_seq = root.update_seq;
    } else {
      const names = new Set();
      for (let page = 0; page < MAX_NPM_PAGES; page += 1) {
        const response = await fetcher(`${NPM_REPLICATE}_changes?since=${encodeURIComponent(state.npm_seq)}&limit=${NPM_PAGE}`, { headers: UA });
        if (!response.ok) throw Object.assign(new Error(`npm changes page HTTP ${response.status}`), {status: response.status});
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
        if (!version) throw new Error("npm latest version is missing; changes cursor was not advanced");
        targets.push({ ecosystem: "npm", package: name, version });
      }
    }
  }

  // PyPI: the updates feed lists the latest 100 releases.
  if (lists.pypi.size) {
    const response = await fetcher(PYPI_RSS, { headers: UA });
    if (!response.ok) throw Object.assign(new Error(`PyPI updates feed HTTP ${response.status}`), {status: response.status});
    {
      const seen = new Set(state.pypi_seen || []);
      const items = parsePypiRss(await response.text());
      summary.pypi_items = items.length;
      for (const item of items) {
        const key = `${normalizePypi(item.package)}@${item.version}`;
        if (seen.has(key)) continue;
        if (lists.pypi.has(normalizePypi(item.package))) {
          summary.pypi_hits += 1;
          targets.push({ ecosystem: "pypi", package: item.package, version: item.version, seen_key: key });
        } else {
          seen.add(key);
        }
      }
      state.pypi_seen = [...seen].slice(-400);
    }
  }

  const queued = [];
  for (const target of targets) {
    const {seen_key, ...clean} = target;
    const id = await persistTarget(bucket, clean, now);
    queued.push({queue_id: id, seen_key});
  }
  const seen = new Set(state.pypi_seen || []);
  for (const target of queued) if (target.seen_key) seen.add(target.seen_key);
  state.pypi_seen = [...seen].slice(-400);
  const dispatchResult = await dispatchQueued(bucket, dispatch, now);
  await bucket.put(STATE_KEY, JSON.stringify(state));
  committed = true;
  const result = { component: "fastlane", ...summary, queued: queued.length,
    targets: dispatchResult.status === "dispatched" ? dispatchResult.targets.length : 0,
    dispatch: dispatchResult.status, expired_dispatches_recovered: dispatchResult.recovered };
  console.log(JSON.stringify(result));
  return { ...result, dispatched: dispatchResult.targets };
  } finally {
    if (!committed) {
      delete committedState.lease_until;
      await bucket.put(STATE_KEY, JSON.stringify(committedState));
    }
  }
}
