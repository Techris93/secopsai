import { randomUUID } from "node:crypto";
import { createServer } from "node:http";

import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";

import { AuthenticationError, authenticationChallenge, protectedResourceMetadata, verifyRequest } from "./auth.js";
import { loadConfig } from "./config.js";
import { CoreClient } from "./core-client.js";
import { createSecOpsMcpServer } from "./tools.js";
import { publicGatewayMetadata } from "./client-profiles.js";

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
        return json(response, 200, { status: "ok", service: "secopsai-mcp-gateway", mcp: MCP_PATH });
      }
      if (request.method === "GET" && url.pathname === "/readyz") {
        return json(response, 200, { status: "ready", oauth: Boolean(config.authorizationServer && config.jwksUrl), core_configured: Boolean(config.coreReadToken) });
      }
      if (request.method === "GET" && oauthMetadataPath(url.pathname)) {
        response.setHeader("Access-Control-Allow-Origin", "*");
        return json(response, 200, protectedResourceMetadata(config));
      }
      if (request.method === "GET" && url.pathname === "/.well-known/secopsai-mcp") {
        response.setHeader("Access-Control-Allow-Origin", "*");
        return json(response, 200, publicGatewayMetadata(config));
      }
      if (request.method === "OPTIONS" && url.pathname.startsWith(MCP_PATH)) {
        if (!allowedOrigin(request, config)) return json(response, 403, { error: "origin_not_allowed", request_id: requestId });
        setCorsHeaders(request, response, config);
        response.writeHead(204).end();
        return;
      }
      if (url.pathname === MCP_PATH && request.method && MCP_METHODS.has(request.method)) {
        if (!allowedOrigin(request, config)) return json(response, 403, { error: "origin_not_allowed", request_id: requestId });
        setCorsHeaders(request, response, config);
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
        try {
          const status = await coreClient.sessionStatus(identity.sessionId);
          if (status?.session?.status === "revoked") {
            const revoked = new AuthenticationError("This SecOpsAI MCP session has been revoked", "invalid_token");
            response.setHeader("WWW-Authenticate", authenticationChallenge(config, revoked));
            return json(response, 401, { error: revoked.code, error_description: revoked.message, request_id: requestId });
          }
          await coreClient.recordActivity(identity, "authenticated_request", { method: request.method, request_id: requestId });
        } catch (error) {
          if (config.auditRequired) return json(response, 503, { error: "audit_unavailable", request_id: requestId });
          console.error(JSON.stringify({ level: "warn", event: "mcp.audit_unavailable", request_id: requestId, error: safeMessage(error) }));
        }
        const mcp = createSecOpsMcpServer({ identity, coreClient, config });
        const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
        response.on("close", () => {
          transport.close();
          mcp.close();
        });
        await mcp.connect(transport);
        let parsedBody;
        if (request.method === "POST") {
          try {
            parsedBody = await readBoundedJson(request, config.maxRequestBytes);
          } catch (error) {
            const status = error instanceof RequestBodyError ? error.status : 400;
            return json(response, status, { error: status === 413 ? "request_too_large" : "invalid_json", request_id: requestId });
          }
        }
        await transport.handleRequest(request, response, parsedBody);
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

class RequestBodyError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

async function readBoundedJson(request, maximumBytes) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > maximumBytes) throw new RequestBodyError("MCP request body is too large", 413);
    chunks.push(chunk);
  }
  if (!chunks.length) throw new RequestBodyError("MCP request body is required", 400);
  try {
    return JSON.parse(Buffer.concat(chunks, size).toString("utf8"));
  } catch {
    throw new RequestBodyError("MCP request body must be valid JSON", 400);
  }
}

function oauthMetadataPath(pathname) {
  return pathname === "/.well-known/oauth-protected-resource" || pathname === "/.well-known/oauth-protected-resource/mcp";
}

function allowedHost(request, config) {
  if (!config.allowedHosts.length) return true;
  const host = String(request.headers.host || "").split(":")[0].toLowerCase();
  return config.allowedHosts.map((item) => item.toLowerCase()).includes(host);
}

function allowedOrigin(request, config) {
  const origin = String(request.headers.origin || "").trim();
  return !origin || config.allowedOrigins.includes(origin);
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
