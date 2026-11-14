import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import worker, { filterPackument, normalize, npmTarballVersion, pypiFileVersion } from "../src/index.js";

const shard = (eco, name) => createHash("sha256").update(normalize(eco, name)).digest("hex").slice(0, 2);

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
