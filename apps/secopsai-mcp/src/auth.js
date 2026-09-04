import { createRemoteJWKSet, jwtVerify } from "jose";
import { createHash } from "node:crypto";

import { clientDisplayName } from "./client-profiles.js";

const jwksCache = new Map();

export class AuthenticationError extends Error {
  constructor(message, code = "invalid_token", requiredScope = "") {
    super(message);
    this.name = "AuthenticationError";
    this.code = code;
    this.requiredScope = requiredScope;
  }
}

export async function verifyRequest(request, config, verifier = verifyJwt) {
  const authorization = String(request.headers.authorization || "");
  const [scheme, token, extra] = authorization.split(/\s+/);
  if (scheme?.toLowerCase() !== "bearer" || !token || extra) {
    throw new AuthenticationError("A bearer access token is required", "invalid_token");
  }
  return verifier(token, config);
}

export async function verifyJwt(token, config) {
  if (!config.jwksUrl || !config.issuer || !config.audience) {
    throw new AuthenticationError("OAuth token verification is not configured", "server_error");
  }
  let jwks = jwksCache.get(config.jwksUrl);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(config.jwksUrl), { timeoutDuration: 5000, cooldownDuration: 30000 });
    jwksCache.set(config.jwksUrl, jwks);
  }
  try {
    const { payload, protectedHeader } = await jwtVerify(token, jwks, {
      issuer: config.issuer,
      audience: config.audience,
      algorithms: ["RS256", "ES256", "EdDSA"],
      clockTolerance: 5,
    });
    return identityFromClaims(payload, protectedHeader, config);
  } catch (error) {
    throw new AuthenticationError(`Access token verification failed: ${safeMessage(error)}`, "invalid_token");
  }
}

export function identityFromClaims(payload, protectedHeader, config) {
  const scopes = tokenScopes(payload);
  if (!payload.sub) throw new Error("subject claim is required");
  const clientId = String(payload.azp || payload.client_id || "").trim();
  if (!clientId) throw new Error("authorized client claim is required");
  if (config.allowedClientIds.length && !config.allowedClientIds.includes(clientId)) {
    throw new Error("OAuth client is not approved for this SecOpsAI gateway");
  }
  const organizationId = String(payload.org_id || payload.organization_id || "").trim();
  if (config.organizationId && organizationId !== config.organizationId) {
    throw new Error("access token is not bound to the configured SecOpsAI organization");
  }
  const workspaceId = String(payload.workspace_id || "").trim();
  if (config.workspaceId && workspaceId !== config.workspaceId) {
    throw new Error("access token is not bound to the configured SecOpsAI workspace");
  }
  const tokenMarker = String(payload.jti || payload.iat || payload.exp || "token");
  return Object.freeze({
    subjectId: digest(`${config.issuer}\0${payload.sub}`),
    organizationId,
    workspaceId,
    clientId,
    clientName: clientDisplayName(config, clientId),
    sessionId: digest(`${config.issuer}\0${payload.sub}\0${clientId}\0${tokenMarker}`),
    scopes,
    algorithm: String(protectedHeader.alg || ""),
    transport: "streamable-http",
  });
}

export function localStdioIdentity(config) {
  if (!config.stdioEnabled) throw new AuthenticationError("The local stdio adapter is not enabled", "access_denied");
  return Object.freeze({
    subjectId: digest(`local\0${process.env.USER || "operator"}`),
    organizationId: config.organizationId || "local",
    workspaceId: config.workspaceId || "local",
    clientId: config.stdioClientId,
    clientName: clientDisplayName(config, config.stdioClientId),
    sessionId: digest(`stdio\0${config.stdioClientId}\0${process.pid}`),
    scopes: new Set(config.stdioScopes),
    algorithm: "local-process-boundary",
    transport: "stdio",
  });
}

export function requireScope(identity, scope) {
  if (!identity?.scopes?.has(scope)) {
    throw new AuthenticationError(`The '${scope}' scope is required`, "insufficient_scope", scope);
  }
}

export function protectedResourceMetadata(config) {
  return {
    resource: config.resource,
    authorization_servers: [config.authorizationServer],
    scopes_supported: config.scopes,
    resource_documentation: config.documentationUrl,
    bearer_methods_supported: ["header"],
  };
}

export function authenticationChallenge(config, error = null) {
  const metadata = new URL("/.well-known/oauth-protected-resource", config.resource).toString();
  const scope = error?.requiredScope ? `, scope="${escapeHeader(error.requiredScope)}"` : "";
  const code = error?.code ? `, error="${escapeHeader(error.code)}"` : "";
  const description = error?.message ? `, error_description="${escapeHeader(error.message)}"` : "";
  return `Bearer resource_metadata="${escapeHeader(metadata)}"${scope}${code}${description}`;
}

export function tokenScopes(payload) {
  const values = [];
  if (typeof payload.scope === "string") values.push(...payload.scope.split(/\s+/));
  if (Array.isArray(payload.scp)) values.push(...payload.scp);
  return new Set(values.map((item) => String(item).trim()).filter(Boolean));
}

function escapeHeader(value) {
  return String(value).replace(/["\\\r\n]/g, "");
}

function safeMessage(error) {
  return String(error?.message || "invalid token").replace(/[\r\n]/g, " ").slice(0, 300);
}

function digest(value) {
  return createHash("sha256").update(String(value)).digest("hex");
}
