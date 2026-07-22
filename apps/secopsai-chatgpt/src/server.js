import { randomUUID } from "node:crypto";
import { createServer } from "node:http";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { AuthenticationError, authenticationChallenge, protectedResourceMetadata, verifyRequest } from "./auth.js";
import { loadConfig } from "./config.js";
import { CoreClient } from "./core-client.js";
import { createSecOpsMcpServer } from "./tools.js";

const MCP_PATH = "/mcp";
const MCP_METHODS = new Set(["POST", "GET", "DELETE"]);

export function createHttpServer({ config = loadConfig(), verifier, coreClient = new CoreClient(config) } = {}) {
  return createServer(async (request, response) => {
    const requestId = request.headers["x-request-id"]?.toString().slice(0, 128) || randomUUID();
    setSecurityHeaders(response, requestId);
    try {
      if (!request.url) return json(response, 400, { error: "missing_url", request_id: requestId });
      if (!allowedHost(request, config)) return json(response, 421, { error: "misdirected_request", request_id: requestId });
      const url = new URL(request.url, config.resource);

      if (request.method === "GET" && url.pathname === "/") {
        return json(response, 200, { status: "ok", service: "secopsai-chatgpt-app", mcp: MCP_PATH });
      }
      if (request.method === "GET" && url.pathname === "/readyz") {
        return json(response, 200, { status: "ready", oauth: Boolean(config.authorizationServer && config.jwksUrl), core_configured: Boolean(config.coreReadToken) });
      }
      if (request.method === "GET" && oauthMetadataPath(url.pathname)) {
        return json(response, 200, protectedResourceMetadata(config));
      }
      if (request.method === "OPTIONS" && url.pathname.startsWith(MCP_PATH)) {
        setCorsHeaders(request, response, config);
        response.writeHead(204).end();
        return;
      }
      if (url.pathname === MCP_PATH && request.method && MCP_METHODS.has(request.method)) {
        const length = Number(request.headers["content-length"] || 0);
        if (length > config.maxRequestBytes) return json(response, 413, { error: "request_too_large", request_id: requestId });
        let identity;
        try {
          identity = await verifyRequest(request, config, verifier);
        } catch (error) {
          const authError = error instanceof AuthenticationError ? error : new AuthenticationError("Access token verification failed");
          response.setHeader("WWW-Authenticate", authenticationChallenge(config, authError));
          return json(response, 401, { error: authError.code, error_description: authError.message, request_id: requestId });
        }
        setCorsHeaders(request, response, config);
        const mcp = createSecOpsMcpServer({ identity, coreClient, config });
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
        response.on("close", () => {
          transport.close();
          mcp.close();
        });
        await mcp.connect(transport);
        await transport.handleRequest(request, response);
        return;
      }
      return json(response, 404, { error: "not_found", request_id: requestId });
    } catch (error) {
      console.error(JSON.stringify({ level: "error", event: "mcp.request_failed", request_id: requestId, error: safeMessage(error) }));
      if (!response.headersSent) return json(response, 500, { error: "internal_error", request_id: requestId });
      response.end();
    }
  });
}

function oauthMetadataPath(pathname) {
  return pathname === "/.well-known/oauth-protected-resource" || pathname === "/.well-known/oauth-protected-resource/mcp";
}

function allowedHost(request, config) {
  if (!config.allowedHosts.length) return true;
  const host = String(request.headers.host || "").split(":")[0].toLowerCase();
  return config.allowedHosts.map((item) => item.toLowerCase()).includes(host);
}

function setCorsHeaders(request, response, config) {
  const origin = String(request.headers.origin || "");
  if (origin && config.allowedOrigins.includes(origin)) response.setHeader("Access-Control-Allow-Origin", origin);
  response.setHeader("Vary", "Origin");
  response.setHeader("Access-Control-Allow-Methods", "POST, GET, DELETE, OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "authorization, content-type, mcp-session-id, x-request-id");
  response.setHeader("Access-Control-Expose-Headers", "Mcp-Session-Id, X-Request-ID, WWW-Authenticate");
}

function setSecurityHeaders(response, requestId) {
  response.setHeader("X-Request-ID", requestId);
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  response.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
}

function json(response, status, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "content-length": Buffer.byteLength(body) });
  response.end(body);
}

function safeMessage(error) {
  return String(error?.message || "request failed").replace(/[\r\n]/g, " ").slice(0, 500);
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  const config = loadConfig();
  createHttpServer({ config }).listen(config.port, "0.0.0.0", () => {
    console.log(JSON.stringify({ level: "info", event: "mcp.started", port: config.port, path: MCP_PATH }));
  });
}
