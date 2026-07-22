import { createRemoteJWKSet, jwtVerify } from "jose";

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
    const scopes = tokenScopes(payload);
    if (!payload.sub) throw new Error("subject claim is required");
    return Object.freeze({
      subject: String(payload.sub),
      organizationId: String(payload.org_id || payload.organization_id || ""),
      scopes,
      tokenId: String(payload.jti || ""),
      algorithm: String(protectedHeader.alg || ""),
    });
  } catch (error) {
    throw new AuthenticationError(`Access token verification failed: ${safeMessage(error)}`, "invalid_token");
  }
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
