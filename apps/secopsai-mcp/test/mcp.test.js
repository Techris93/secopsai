import assert from "node:assert/strict";
import { once } from "node:events";
import test from "node:test";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

import { identityFromClaims, protectedResourceMetadata, tokenScopes } from "../src/auth.js";
import { publicGatewayMetadata } from "../src/client-profiles.js";
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
    organizationId: "org-1",
    workspaceId: "workspace-1",
    allowedOrigins: ["https://chatgpt.com", "https://vscode.dev"],
    allowedHosts: [],
    allowedClientIds: ["chatgpt-client", "vscode-client"],
    clientProfiles: [{ id: "chatgpt-client", profile: "chatgpt", name: "ChatGPT" }],
    auditRequired: true,
    stdioEnabled: false,
    stdioClientId: "local-test",
    stdioScopes: ["secopsai.workspace.read"],
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

test("local configuration has no implicit browser origin", () => {
  const config = loadConfig({});
  assert.deepEqual(config.allowedOrigins, []);
  assert.equal(config.stdioEnabled, false);
});

test("production requires audited origins, registered clients, and remote transport", () => {
  const base = {
    SECOPSAI_MCP_ENVIRONMENT: "production",
    SECOPSAI_MCP_RESOURCE: "https://mcp.secopsai.dev",
    SECOPSAI_MCP_AUTHORIZATION_SERVER: "https://auth.secopsai.dev",
    SECOPSAI_MCP_ISSUER: "https://auth.secopsai.dev",
    SECOPSAI_MCP_AUDIENCE: "https://mcp.secopsai.dev",
    SECOPSAI_MCP_JWKS_URL: "https://auth.secopsai.dev/.well-known/jwks.json",
    SECOPSAI_MCP_ORGANIZATION_ID: "secopsai",
    SECOPSAI_MCP_WORKSPACE_ID: "pilot",
    SECOPSAI_CORE_API_URL: "https://core.secopsai.dev",
    SECOPSAI_CORE_READ_TOKEN: "x".repeat(32),
    SECOPSAI_MCP_ALLOWED_HOSTS: "mcp.secopsai.dev",
  };
  assert.throws(() => loadConfig(base), /audited browser origins/);
  assert.throws(
    () => loadConfig({ ...base, SECOPSAI_MCP_ALLOWED_ORIGINS: "https://vscode.dev" }),
    /approved OAuth clients/,
  );
  assert.throws(
    () => loadConfig({
      ...base,
      SECOPSAI_MCP_ALLOWED_ORIGINS: "https://vscode.dev",
      SECOPSAI_MCP_ALLOWED_CLIENT_IDS: "vscode-client",
      SECOPSAI_MCP_STDIO_ENABLED: "true",
    }),
    /stdio bridge cannot run/,
  );
});

test("protected resource metadata advertises the exact resource and scopes", () => {
  const metadata = protectedResourceMetadata(testConfig());
  assert.equal(metadata.resource, "http://127.0.0.1:8787");
  assert.deepEqual(metadata.authorization_servers, ["https://auth.example.test"]);
  assert.ok(metadata.scopes_supported.includes("secopsai.research.read"));
  assert.deepEqual([...tokenScopes({ scope: "one two", scp: ["three"] })], ["one", "two", "three"]);
});

test("provider-neutral discovery advertises one gateway and compatibility profiles", () => {
  const metadata = publicGatewayMetadata(testConfig());
  assert.equal(metadata.service, "secopsai-mcp-gateway");
  assert.equal(metadata.endpoint, "http://127.0.0.1:8787/mcp");
  assert.equal(metadata.safety.provider_tokens_accepted, false);
  assert.ok(metadata.client_profiles.some((item) => item.id === "chatgpt" && item.configured));
  assert.ok(metadata.client_profiles.some((item) => item.id === "vscode"));
});

test("OAuth claims are tenant-bound, client-allowlisted, and pseudonymized", () => {
  const config = testConfig();
  const identity = identityFromClaims(
    { sub: "operator@example.test", org_id: "org-1", workspace_id: "workspace-1", azp: "chatgpt-client", jti: "token-1", scope: config.scopes.join(" ") },
    { alg: "ES256" },
    config,
  );
  assert.equal(identity.clientId, "chatgpt-client");
  assert.equal(identity.organizationId, "org-1");
  assert.equal(identity.workspaceId, "workspace-1");
  assert.equal(identity.subjectId.length, 64);
  assert.equal(identity.sessionId.length, 64);
  assert.doesNotMatch(JSON.stringify(identity), /operator@example\.test|token-1/);
  assert.throws(
    () => identityFromClaims({ sub: "operator", org_id: "org-other", workspace_id: "workspace-1", azp: "chatgpt-client" }, { alg: "ES256" }, config),
    /organization/,
  );
  assert.throws(
    () => identityFromClaims({ sub: "operator", org_id: "org-1", workspace_id: "workspace-1", azp: "unapproved-client" }, { alg: "ES256" }, config),
    /not approved/,
  );
  assert.throws(
    () => identityFromClaims({ sub: "operator", org_id: "org-1", workspace_id: "workspace-other", azp: "chatgpt-client" }, { alg: "ES256" }, config),
    /workspace/,
  );
});

function auditedCoreClient(query = async () => ({}), status = "unknown") {
  const activity = [];
  return {
    activity,
    query,
    async sessionStatus() { return { session: { status } }; },
    async recordActivity(identity, eventType, details, toolName = "") { activity.push({ identity, eventType, details, toolName }); return { recorded: true }; },
  };
}

test("HTTP surface publishes metadata and rejects unauthenticated MCP calls", async (t) => {
  const config = testConfig();
  const server = createHttpServer({
    config,
    verifier: async () => ({ subjectId: "a".repeat(64), sessionId: "b".repeat(64), clientId: "chatgpt-client", clientName: "ChatGPT", organizationId: "org-1", workspaceId: "workspace-1", transport: "streamable-http", scopes: new Set(config.scopes) }),
    coreClient: auditedCoreClient(),
  });
  t.after(() => server.close());
  const base = await listen(server);

  const metadata = await fetch(`${base}/.well-known/oauth-protected-resource`);
  assert.equal(metadata.status, 200);
  assert.equal(metadata.headers.get("access-control-allow-origin"), "*");
  assert.equal((await metadata.json()).authorization_servers[0], "https://auth.example.test");

  const denied = await fetch(`${base}/mcp`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: "https://chatgpt.com" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } } }),
  });
  assert.equal(denied.status, 401);
  assert.equal(denied.headers.get("access-control-allow-origin"), "https://chatgpt.com");
  assert.match(denied.headers.get("www-authenticate"), /oauth-protected-resource/);
});

test("browser origins are explicit and malformed MCP messages fail safely", async (t) => {
  const config = testConfig();
  const coreClient = auditedCoreClient();
  const identity = { subjectId: "a".repeat(64), sessionId: "b".repeat(64), clientId: "vscode-client", clientName: "VS Code", organizationId: "org-1", workspaceId: "workspace-1", transport: "streamable-http", scopes: new Set(config.scopes) };
  const server = createHttpServer({ config, verifier: async () => identity, coreClient });
  t.after(() => server.close());
  const base = await listen(server);
  const rejected = await fetch(`${base}/mcp`, { method: "POST", headers: { authorization: "Bearer token", origin: "https://evil.example", "content-type": "application/json" }, body: "{}" });
  assert.equal(rejected.status, 403);
  const unsupportedHeaders = await fetch(`${base}/mcp`, { method: "POST", headers: { authorization: "Bearer token", origin: "https://vscode.dev", "content-type": "application/json" }, body: JSON.stringify({ nope: true }) });
  assert.equal(unsupportedHeaders.status, 406);
  const malformed = await fetch(`${base}/mcp`, { method: "POST", headers: { authorization: "Bearer token", origin: "https://vscode.dev", accept: "application/json, text/event-stream", "content-type": "application/json" }, body: JSON.stringify({ nope: true }) });
  assert.equal(malformed.status, 400);
  const invalidJson = await fetch(`${base}/mcp`, { method: "POST", headers: { authorization: "Bearer token", origin: "https://vscode.dev", accept: "application/json, text/event-stream", "content-type": "application/json" }, body: "{" });
  assert.equal(invalidJson.status, 400);
  assert.equal(coreClient.activity.length, 3);
});

test("chunked MCP request bodies cannot bypass the configured size limit", async (t) => {
  const config = testConfig({ maxRequestBytes: 64 });
  const identity = { subjectId: "a".repeat(64), sessionId: "b".repeat(64), clientId: "vscode-client", clientName: "VS Code", organizationId: "org-1", workspaceId: "workspace-1", transport: "streamable-http", scopes: new Set(config.scopes) };
  const server = createHttpServer({ config, verifier: async () => identity, coreClient: auditedCoreClient() });
  t.after(() => server.close());
  const base = await listen(server);
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(JSON.stringify({ payload: "x".repeat(128) })));
      controller.close();
    },
  });
  const response = await fetch(`${base}/mcp`, {
    method: "POST",
    duplex: "half",
    headers: { authorization: "Bearer token", origin: "https://vscode.dev", accept: "application/json, text/event-stream", "content-type": "application/json" },
    body,
  });
  assert.equal(response.status, 413);
  assert.equal((await response.json()).error, "request_too_large");
});

test("revoked sessions are rejected before MCP initialization", async (t) => {
  const config = testConfig();
  const identity = { subjectId: "a".repeat(64), sessionId: "b".repeat(64), clientId: "chatgpt-client", clientName: "ChatGPT", organizationId: "org-1", workspaceId: "workspace-1", transport: "streamable-http", scopes: new Set(config.scopes) };
  const server = createHttpServer({ config, verifier: async () => identity, coreClient: auditedCoreClient(async () => ({}), "revoked") });
  t.after(() => server.close());
  const base = await listen(server);
  const response = await fetch(`${base}/mcp`, { method: "POST", headers: { authorization: "Bearer token", "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "1" } } }) });
  assert.equal(response.status, 401);
  assert.match(response.headers.get("www-authenticate"), /invalid_token/);
});

test("MCP exposes only read-only tools and forwards normalized Core queries", async (t) => {
  const config = testConfig();
  const calls = [];
  const coreClient = auditedCoreClient(async (action, inputs, context) => {
    assert.equal(context.identity.clientId, "chatgpt-client");
    assert.equal(context.toolName, "secopsai_list_findings");
    calls.push({ action, inputs });
    return {
      schema_version: "secopsai.intelligence.v1",
      action,
      read_only: true,
      data: action === "list_findings" ? { findings: [], count: 0 } : {},
    };
  });
  const verifier = async (token) => {
    assert.equal(token, "test-access-token");
    return { subjectId: "a".repeat(64), sessionId: "b".repeat(64), clientId: "chatgpt-client", clientName: "ChatGPT", organizationId: "org-1", workspaceId: "workspace-1", transport: "streamable-http", scopes: new Set(config.scopes) };
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
  const coreClient = auditedCoreClient(async () => { throw new Error("must not be called"); });
  const server = createHttpServer({
    config,
    verifier: async () => ({ subjectId: "a".repeat(64), sessionId: "b".repeat(64), clientId: "chatgpt-client", clientName: "ChatGPT", organizationId: "org-1", workspaceId: "workspace-1", transport: "streamable-http", scopes: new Set(["secopsai.findings.read"]) }),
    coreClient,
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
  assert.equal(coreClient.activity.at(-1).toolName, "secopsai_workspace_summary");
  assert.equal(coreClient.activity.at(-1).details.result, "failed");
});

test("stateless MCP clients can initialize and disconnect cleanly", async (t) => {
  const config = testConfig();
  const identity = { subjectId: "a".repeat(64), sessionId: "b".repeat(64), clientId: "chatgpt-client", clientName: "ChatGPT", organizationId: "org-1", workspaceId: "workspace-1", transport: "streamable-http", scopes: new Set(config.scopes) };
  const server = createHttpServer({ config, verifier: async () => identity, coreClient: auditedCoreClient() });
  t.after(() => server.close());
  const base = await listen(server);
  const client = new Client({ name: "disconnect-test", version: "1.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(`${base}/mcp`), { requestInit: { headers: { authorization: "Bearer test-access-token" } } });
  await client.connect(transport);
  await client.close();
  const ready = await fetch(`${base}/readyz`);
  assert.equal(ready.status, 200);
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
