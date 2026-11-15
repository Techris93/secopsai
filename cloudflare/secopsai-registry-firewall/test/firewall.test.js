import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import worker, { filterPackument, normalize, npmTarballVersion, pypiFileVersion, rewriteTarballText } from "../src/index.js";

const shard = (eco, name) => createHash("sha256").update(normalize(eco, name)).digest("hex").slice(0, 3);

function env(blocks) {
  const store = new Map();
  for (const [eco, entries] of Object.entries(blocks)) {
    for (const [name, entry] of Object.entries(entries)) {
      const key = `firewall/${eco}/${shard(eco, name)}.json`;
      store.set(key, { ...(store.get(key) || {}), [normalize(eco, name)]: entry });
    }
  }
  return { FIREWALL_TOKEN: "tok", LEDGER: { get: async (key) => store.has(key) ? { text: async () => JSON.stringify(store.get(key)) } : null } };
}

function upstream(routes) {
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    const route = routes[String(url)];
    if (!route) return new Response("missing", { status: 404 });
    return new Response(typeof route.body === "string" ? route.body : JSON.stringify(route.body), { status: 200, headers: { "content-type": route.type || "application/json" } });
  };
  return calls;
}

const get = (path, e, token = "tok", basic = false) => worker.fetch(new Request(`https://fw.example${path}`, {
  headers: { authorization: basic ? `Basic ${btoa(`x:${token}`)}` : `Bearer ${token}` } }), e);

test("npm documents lose blocked versions and tags move to a safe version", async () => {
  const e = env({ npm: { "@scope/lib": { all: false, versions: ["1.0.1"], ids: ["MAL-1"] } } });
  upstream({ "https://registry.npmjs.org/@scope%2Flib": { body: {
    name: "@scope/lib", "dist-tags": { latest: "1.0.1" },
    time: { "1.0.0": "2026-01-01T00:00:00Z", "1.0.1": "2026-02-01T00:00:00Z" },
    versions: { "1.0.0": { dist: { tarball: "https://registry.npmjs.org/@scope/lib/-/lib-1.0.0.tgz" } },
                "1.0.1": { dist: { tarball: "https://registry.npmjs.org/@scope/lib/-/lib-1.0.1.tgz" } } } } } });
  const response = await get("/npm/@scope%2flib", e);
  const doc = await response.json();
  assert.deepEqual(Object.keys(doc.versions), ["1.0.0"]);
  assert.equal(doc["dist-tags"].latest, "1.0.0");
  assert.equal(doc.versions["1.0.0"].dist.tarball, "https://fw.example/npm/@scope/lib/-/lib-1.0.0.tgz", "tarballs come back through the firewall");
  assert.equal(response.headers.get("x-secopsai-firewall"), "removed 1");
});

test("a blocked npm tarball is refused even when pinned by a lockfile", async () => {
  const e = env({ npm: { "left-pad": { all: false, versions: ["9.9.9"], ids: ["MAL-2"] } } });
  const calls = upstream({ "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz": { body: "tgz", type: "application/octet-stream" } });
  const blocked = await get("/npm/left-pad/-/left-pad-9.9.9.tgz", e);
  assert.equal(blocked.status, 403);
  assert.deepEqual((await blocked.json()).advisories, ["MAL-2"]);
  assert.equal((await get("/npm/left-pad/-/left-pad-1.3.0.tgz", e)).status, 200);
  assert.ok(!calls.some((url) => url.includes("9.9.9")), "a blocked tarball is never fetched");
});

test("a package that is malicious at every version is refused outright", async () => {
  const e = env({ npm: { evilpkg: { all: true, versions: [] } }, pypi: { "evil-pkg": { all: true, versions: [] } } });
  upstream({});
  assert.equal((await get("/npm/evilpkg", e)).status, 403);
  assert.equal((await get("/pypi/simple/Evil_Pkg/", e, "tok", true)).status, 403, "PyPI names are normalized");
});

test("PyPI JSON and HTML indexes lose blocked files", async () => {
  const e = env({ pypi: { requests: { all: false, versions: ["9.0.0"] } } });
  upstream({ "https://pypi.org/simple/requests/": { type: "application/vnd.pypi.simple.v1+json", body: {
    name: "requests", versions: ["2.32.3", "9.0.0"],
    files: [{ filename: "requests-2.32.3-py3-none-any.whl" }, { filename: "requests-9.0.0.tar.gz" }, { filename: "requests-9.0.0-py3-none-any.whl" }] } } });
  const doc = await (await get("/pypi/simple/requests/", e, "tok", true)).json();
  assert.deepEqual(doc.files.map((file) => file.filename), ["requests-2.32.3-py3-none-any.whl"]);
  assert.deepEqual(doc.versions, ["2.32.3"]);
  upstream({ "https://pypi.org/simple/requests/": { type: "text/html", body:
    '<a href="https://files/requests-2.32.3.tar.gz">requests-2.32.3.tar.gz</a><br/><a href="https://files/requests-9.0.0.tar.gz">requests-9.0.0.tar.gz</a><br/>' } });
  const html = await (await get("/pypi/simple/requests/", e, "tok", true)).text();
  assert.ok(html.includes("2.32.3") && !html.includes("9.0.0"));
});

test("the firewall needs its token, by bearer or basic auth", async () => {
  const e = env({});
  upstream({ "https://registry.npmjs.org/left-pad": { body: { versions: {} } } });
  assert.equal((await get("/npm/left-pad", e, "wrong")).status, 401);
  assert.equal((await get("/npm/left-pad", e, "tok", true)).status, 200);
  assert.equal((await worker.fetch(new Request("https://fw.example/npm/left-pad"), { ...e, FIREWALL_TOKEN: "" })).status, 401, "fails closed without a configured token");
});

test("file names map to versions", () => {
  assert.equal(pypiFileVersion("requests-2.32.3-py3-none-any.whl"), "2.32.3");
  assert.equal(pypiFileVersion("my-pkg-1.0.0rc1.tar.gz"), "1.0.0rc1");
  assert.equal(npmTarballVersion("@scope/lib", "lib-1.0.1-beta.2.tgz"), "1.0.1-beta.2");
  const doc = { "dist-tags": { latest: "2.0.0" }, versions: { "1.0.0": {}, "2.0.0": {} } };
  filterPackument(doc, { all: false, versions: ["2.0.0"] });
  assert.equal(doc["dist-tags"].latest, "1.0.0", "abbreviated documents fall back to publish order");
});

test("lockfile check reports blocked entries with their advisories", async () => {
  // Names unused by other tests: shards are cached per isolate for five minutes.
  const e = env({ npm: { "left-pad": { all: false, versions: ["9.9.9"], ids: ["MAL-2"] } }, pypi: { "bad-lib": { all: true, versions: [], ids: ["MAL-3"] } } });
  const post = (body, token = "tok") => worker.fetch(new Request("https://fw.example/check", { method: "POST", body: JSON.stringify(body),
    headers: { authorization: `Bearer ${token}` } }), e);
  const result = await (await post({ packages: [
    { ecosystem: "npm", name: "left-pad", version: "9.9.9" }, { ecosystem: "npm", name: "left-pad", version: "1.3.0" },
    { ecosystem: "pypi", name: "Bad_Lib", version: "1.0" }] })).json();
  assert.equal(result.checked, 3);
  assert.deepEqual(result.blocked.map((item) => [item.name, item.advisories[0]]), [["left-pad", "MAL-2"], ["Bad_Lib", "MAL-3"]]);
  assert.equal((await post({ packages: [{ ecosystem: "cargo", name: "x", version: "1" }] })).status, 400);
  assert.equal((await post({ packages: [] }, "wrong")).status, 401);
});

test("a lockfile check reads each shard once, in parallel", async () => {
  const e = env({ npm: { "par-a": { all: true, versions: [], ids: ["MAL-9"] } } });
  let inFlight = 0, peak = 0, reads = 0;
  const get = e.LEDGER.get;
  e.LEDGER.get = async (key) => { reads += 1; inFlight += 1; peak = Math.max(peak, inFlight); await new Promise((r) => setTimeout(r, 5)); inFlight -= 1; return get(key); };
  const packages = Array.from({ length: 40 }, (_, i) => ({ ecosystem: "npm", name: `par-${i === 0 ? "a" : `x${i}`}`, version: "1.0.0" }));
  packages.push({ ecosystem: "npm", name: "par-a", version: "2.0.0" });
  const response = await worker.fetch(new Request("https://fw.example/check", { method: "POST", body: JSON.stringify({ packages }),
    headers: { authorization: "Bearer tok" } }), e);
  const result = await response.json();
  assert.equal(result.blocked.length, 2);
  assert.ok(peak > 1, "shards are read in parallel");
  const distinct = new Set(packages.map((item) => shard("npm", item.name))).size;
  assert.ok(reads <= distinct, `each shard read at most once (${reads} reads, ${distinct} shards)`);
});

test("an unlisted package keeps its document and only tarball URLs change", async () => {
  const e = env({});
  const body = '{"name":"clean-pkg","homepage":"https://registry.npmjs.org/x","versions":{"1.0.0":{"dist":{"tarball":"https://registry.npmjs.org/clean-pkg/-/clean-pkg-1.0.0.tgz"}}}}';
  upstream({ "https://registry.npmjs.org/clean-pkg": { body, type: "application/vnd.npm.install-v1+json" } });
  const response = await get("/npm/clean-pkg", e);
  assert.equal(response.headers.get("content-type"), "application/vnd.npm.install-v1+json");
  const text = await response.text();
  assert.equal(text, body.replace('"tarball":"https://registry.npmjs.org/', '"tarball":"https://fw.example/npm/'));
  assert.ok(text.includes('"homepage":"https://registry.npmjs.org/x"'), "only tarball fields are rewritten");
  assert.equal(rewriteTarballText('"tarball":"https://registry.npmjs.org/a"', "https://o"), '"tarball":"https://o/npm/a"');
});
