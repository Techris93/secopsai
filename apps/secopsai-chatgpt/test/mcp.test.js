import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { protectedResourceMetadata, tokenScopes } from "../src/auth.js";
import { loadConfig } from "../src/config.js";
import { CoreClient } from "../src/core-client.js";
import { createHttpServer } from "../src/server.js";

function testConfig(overrides = {}) {
  return {
    environment: "test",
    port: 0,
    resource: "http://127.0.0.1:8787",
    authorizationServer: "https://auth.example.test",
    issuer: "https://auth.example.test/",
    audience: "https://mcp.example.test",
    jwksUrl: "https://auth.example.test/.well-known/jwks.json",
    coreApiUrl: "https://core.example.test",
    coreReadToken: "core-read-token-that-is-never-sent-to-chatgpt",
    documentationUrl: "https://docs.secopsai.dev",
    allowedOrigins: ["https://chatgpt.com"],
    allowedHosts: [],
    scopes: [
      "secopsai.workspace.read",
      "secopsai.findings.read",
      "secopsai.assets.read",
      "secopsai.research.read",
    ],
    maxRequestBytes: 1024 * 1024,
    coreTimeoutMs: 1000,
    ...overrides,
  };
}

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

test("production configuration fails closed without OAuth and explicit hosts", () => {
  assert.throws(
    () => loadConfig({
      SECOPSAI_MCP_ENVIRONMENT: "production",
      SECOPSAI_MCP_RESOURCE: "https://mcp.secopsai.dev",
      SECOPSAI_CORE_API_URL: "https://core.secopsai.dev",
      SECOPSAI_CORE_READ_TOKEN: "short",
    }),
    /AUTHORIZATION_SERVER/,
  );
});

test("protected resource metadata advertises the exact resource and scopes", () => {
  const metadata = protectedResourceMetadata(testConfig());
  assert.equal(metadata.resource, "http://127.0.0.1:8787");
  assert.deepEqual(metadata.authorization_servers, ["https://auth.example.test"]);
  assert.ok(metadata.scopes_supported.includes("secopsai.research.read"));
  assert.deepEqual([...tokenScopes({ scope: "one two", scp: ["three"] })], ["one", "two", "three"]);
});

test("HTTP surface publishes metadata and rejects unauthenticated MCP calls", async (t) => {
  const config = testConfig();
  const server = createHttpServer({ config, verifier: async () => ({ subject: "operator", scopes: new Set(config.scopes) }), coreClient: { query: async () => ({}) } });
  t.after(() => server.close());
  const base = await listen(server);

  const metadata = await fetch(`${base}/.well-known/oauth-protected-resource`);
  assert.equal(metadata.status, 200);
  assert.equal((await metadata.json()).authorization_servers[0], "https://auth.example.test");

  const denied = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } } }),
  });
  assert.equal(denied.status, 401);
  assert.match(denied.headers.get("www-authenticate"), /oauth-protected-resource/);
});

test("MCP exposes only read-only tools and forwards normalized Core queries", async (t) => {
  const config = testConfig();
  const calls = [];
  const coreClient = {
    async query(action, inputs) {
      calls.push({ action, inputs });
      return {
        schema_version: "secopsai.intelligence.v1",
        action,
        read_only: true,
        data: action === "list_findings" ? { findings: [], count: 0 } : {},
      };
    },
  };
  const verifier = async (token) => {
    assert.equal(token, "test-access-token");
    return { subject: "operator-1", organizationId: "org-1", scopes: new Set(config.scopes) };
  };
  const server = createHttpServer({ config, verifier, coreClient });
  t.after(() => server.close());
  const base = await listen(server);
  const client = new Client({ name: "secopsai-test", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
    requestInit: { headers: { authorization: "Bearer test-access-token" } },
  });
  t.after(async () => client.close());
  await client.connect(transport);

  const tools = await client.listTools();
  assert.equal(tools.tools.length, 9);
  for (const tool of tools.tools) {
    assert.equal(tool.annotations.readOnlyHint, true);
    assert.equal(tool.annotations.destructiveHint, false);
    assert.equal(tool.annotations.openWorldHint, false);
    assert.equal(tool._meta.securitySchemes[0].type, "oauth2");
  }

  const result = await client.callTool({ name: "secopsai_list_findings", arguments: { severity: "high", limit: 10 } });
  assert.equal(result.isError, undefined);
  assert.equal(result.structuredContent.result.read_only, true);
  assert.deepEqual(calls, [{ action: "list_findings", inputs: { severity: "high", limit: 10 } }]);
});

test("MCP returns an OAuth challenge when a tool scope is missing", async (t) => {
  const config = testConfig();
  const server = createHttpServer({
    config,
    verifier: async () => ({ subject: "operator", scopes: new Set(["secopsai.findings.read"]) }),
    coreClient: { query: async () => { throw new Error("must not be called"); } },
  });
  t.after(() => server.close());
  const base = await listen(server);
  const client = new Client({ name: "scope-test", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), {
    requestInit: { headers: { authorization: "Bearer test-access-token" } },
  });
  t.after(async () => client.close());
  await client.connect(transport);
  const result = await client.callTool({ name: "secopsai_workspace_summary", arguments: {} });
  assert.equal(result.isError, true);
  assert.match(result._meta["mcp/www_authenticate"][0], /insufficient_scope/);
});

test("Core client keeps its credential server-side and rejects unsupported responses", async () => {
  const requests = [];
  const fetchImpl = async (url, options) => {
    requests.push({ url, options });
    return new Response(JSON.stringify({ schema_version: "wrong" }), { status: 200, headers: { "content-type": "application/json" } });
  };
  const client = new CoreClient(testConfig(), fetchImpl);
  await assert.rejects(() => client.query("workspace_summary", {}), /unsupported intelligence contract/);
  assert.equal(requests[0].options.headers.authorization, "Bearer core-read-token-that-is-never-sent-to-chatgpt");
  assert.doesNotMatch(JSON.stringify(requests[0].options.body), /core-read-token/);
});
