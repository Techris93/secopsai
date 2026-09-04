const PROTECTED_ENVIRONMENTS = new Set(["pilot", "production"]);

export const SUPPORTED_SCOPES = Object.freeze([
  "secopsai.workspace.read",
  "secopsai.findings.read",
  "secopsai.assets.read",
  "secopsai.research.read",
]);

export function loadConfig(environment = process.env) {
  const clientProfiles = parseClientProfiles(environment.SECOPSAI_MCP_CLIENTS_JSON);
  const config = {
    environment: clean(environment.SECOPSAI_MCP_ENVIRONMENT || "local").toLowerCase(),
    port: boundedInt(environment.PORT, 8787, 1, 65535),
    resource: clean(environment.SECOPSAI_MCP_RESOURCE || "http://127.0.0.1:8787"),
    authorizationServer: clean(environment.SECOPSAI_MCP_AUTHORIZATION_SERVER),
    issuer: clean(environment.SECOPSAI_MCP_ISSUER),
    audience: clean(environment.SECOPSAI_MCP_AUDIENCE),
    jwksUrl: clean(environment.SECOPSAI_MCP_JWKS_URL),
    coreApiUrl: clean(environment.SECOPSAI_CORE_API_URL || "http://127.0.0.1:8001"),
    coreReadToken: clean(environment.SECOPSAI_CORE_READ_TOKEN),
    documentationUrl: clean(environment.SECOPSAI_MCP_DOCUMENTATION_URL || "https://docs.secopsai.dev"),
    organizationId: clean(environment.SECOPSAI_MCP_ORGANIZATION_ID),
    workspaceId: clean(environment.SECOPSAI_MCP_WORKSPACE_ID),
    allowedOrigins: csv(environment.SECOPSAI_MCP_ALLOWED_ORIGINS),
    allowedHosts: csv(environment.SECOPSAI_MCP_ALLOWED_HOSTS),
    allowedClientIds: csv(environment.SECOPSAI_MCP_ALLOWED_CLIENT_IDS),
    clientProfiles,
    auditRequired: booleanSetting(environment.SECOPSAI_MCP_AUDIT_REQUIRED, true),
    stdioEnabled: booleanSetting(environment.SECOPSAI_MCP_STDIO_ENABLED, false),
    stdioClientId: clean(environment.SECOPSAI_MCP_STDIO_CLIENT_ID || "local-mcp-client"),
    stdioScopes: csv(environment.SECOPSAI_MCP_STDIO_SCOPES || SUPPORTED_SCOPES.join(",")),
    scopes: [...SUPPORTED_SCOPES],
    maxRequestBytes: boundedInt(environment.SECOPSAI_MCP_MAX_REQUEST_BYTES, 1024 * 1024, 16 * 1024, 4 * 1024 * 1024),
    coreTimeoutMs: boundedInt(environment.SECOPSAI_MCP_CORE_TIMEOUT_MS, 15000, 1000, 60000),
  };
  validateConfig(config);
  return Object.freeze(config);
}

export function validateConfig(config) {
  if (!new Set(["local", "test", "pilot", "production"]).has(config.environment)) {
    throw new Error("SECOPSAI_MCP_ENVIRONMENT must be local, test, pilot, or production");
  }
  for (const [label, value] of [["resource", config.resource], ["core API", config.coreApiUrl]]) {
    let url;
    try {
      url = new URL(value);
    } catch {
      throw new Error(`SecOpsAI MCP ${label} must be an absolute URL`);
    }
    if (PROTECTED_ENVIRONMENTS.has(config.environment) && url.protocol !== "https:") {
      throw new Error(`SecOpsAI MCP ${label} must use HTTPS in ${config.environment}`);
    }
  }
  if (PROTECTED_ENVIRONMENTS.has(config.environment)) {
    for (const [name, value] of [
      ["SECOPSAI_MCP_AUTHORIZATION_SERVER", config.authorizationServer],
      ["SECOPSAI_MCP_ISSUER", config.issuer],
      ["SECOPSAI_MCP_AUDIENCE", config.audience],
      ["SECOPSAI_MCP_JWKS_URL", config.jwksUrl],
    ]) {
      if (!value) throw new Error(`${name} is required in ${config.environment}`);
      if (new URL(value).protocol !== "https:") throw new Error(`${name} must use HTTPS`);
    }
    if (!config.organizationId) {
      throw new Error(`SECOPSAI_MCP_ORGANIZATION_ID is required in ${config.environment}`);
    }
    if (!/^[A-Za-z0-9._:/-]{1,240}$/.test(config.organizationId)) {
      throw new Error("SECOPSAI_MCP_ORGANIZATION_ID must be a safe tenant identifier");
    }
    if (!config.workspaceId) {
      throw new Error(`SECOPSAI_MCP_WORKSPACE_ID is required in ${config.environment}`);
    }
    if (!/^[A-Za-z0-9._:/-]{1,240}$/.test(config.workspaceId)) {
      throw new Error("SECOPSAI_MCP_WORKSPACE_ID must be a safe workspace identifier");
    }
    if (config.coreReadToken.length < 32) {
      throw new Error("SECOPSAI_CORE_READ_TOKEN must contain at least 32 characters");
    }
    if (!config.allowedHosts.length || config.allowedHosts.includes("*")) {
      throw new Error("SECOPSAI_MCP_ALLOWED_HOSTS must be explicit in pilot/production");
    }
    if (!config.allowedOrigins.length || config.allowedOrigins.includes("*")) {
      throw new Error("SECOPSAI_MCP_ALLOWED_ORIGINS must explicitly identify audited browser origins in pilot/production");
    }
    if (!config.allowedClientIds.length || config.allowedClientIds.includes("*")) {
      throw new Error("SECOPSAI_MCP_ALLOWED_CLIENT_IDS must explicitly identify approved OAuth clients in pilot/production");
    }
    if (!config.auditRequired) {
      throw new Error("SECOPSAI_MCP_AUDIT_REQUIRED cannot be disabled in pilot/production");
    }
  }
  const unsupportedScopes = config.stdioScopes.filter((scope) => !SUPPORTED_SCOPES.includes(scope));
  if (unsupportedScopes.length) throw new Error(`Unsupported stdio scopes: ${unsupportedScopes.join(", ")}`);
  const unapprovedProfiles = config.clientProfiles.filter((profile) => !config.allowedClientIds.includes(profile.id));
  if (unapprovedProfiles.length) {
    throw new Error("Every SECOPSAI_MCP_CLIENTS_JSON id must also be in SECOPSAI_MCP_ALLOWED_CLIENT_IDS");
  }
  if (PROTECTED_ENVIRONMENTS.has(config.environment) && config.stdioEnabled) {
    throw new Error("The local stdio bridge cannot run in pilot/production mode");
  }
  return config;
}

function clean(value) {
  return String(value || "").trim();
}

function csv(value) {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function booleanSetting(value, fallback) {
  const normalized = clean(value).toLowerCase();
  if (!normalized) return fallback;
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  throw new Error(`Invalid boolean setting: ${value}`);
}

function parseClientProfiles(value) {
  if (!clean(value)) return [];
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error("SECOPSAI_MCP_CLIENTS_JSON must be valid JSON");
  }
  if (!Array.isArray(parsed) || parsed.length > 50) {
    throw new Error("SECOPSAI_MCP_CLIENTS_JSON must be an array with at most 50 entries");
  }
  return parsed.map((item) => {
    if (!item || typeof item !== "object") throw new Error("Every MCP client profile must be an object");
    const id = clean(item.id);
    const profile = clean(item.profile || "generic");
    const name = clean(item.name || id);
    if (!/^[A-Za-z0-9._:/-]{1,240}$/.test(id)) throw new Error("Every MCP client profile requires a safe id");
    if (!/^[a-z0-9-]{1,64}$/.test(profile)) throw new Error("Every MCP client profile requires a safe profile name");
    return Object.freeze({ id, profile, name: name.slice(0, 120) });
  });
}

function boundedInt(value, fallback, minimum, maximum) {
  const parsed = Number.parseInt(String(value || ""), 10);
  return Math.max(minimum, Math.min(Number.isFinite(parsed) ? parsed : fallback, maximum));
}
