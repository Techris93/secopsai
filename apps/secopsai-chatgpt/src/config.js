const PROTECTED_ENVIRONMENTS = new Set(["pilot", "production"]);

export const SUPPORTED_SCOPES = Object.freeze([
  "secopsai.workspace.read",
  "secopsai.findings.read",
  "secopsai.assets.read",
  "secopsai.research.read",
]);

export function loadConfig(environment = process.env) {
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
    allowedOrigins: csv(environment.SECOPSAI_MCP_ALLOWED_ORIGINS || "https://chatgpt.com"),
    allowedHosts: csv(environment.SECOPSAI_MCP_ALLOWED_HOSTS),
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
    if (config.coreReadToken.length < 32) {
      throw new Error("SECOPSAI_CORE_READ_TOKEN must contain at least 32 characters");
    }
    if (!config.allowedHosts.length || config.allowedHosts.includes("*")) {
      throw new Error("SECOPSAI_MCP_ALLOWED_HOSTS must be explicit in pilot/production");
    }
    if (config.allowedOrigins.includes("*")) {
      throw new Error("SECOPSAI_MCP_ALLOWED_ORIGINS cannot contain a wildcard in pilot/production");
    }
  }
  return config;
}

function clean(value) {
  return String(value || "").trim();
}

function csv(value) {
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function boundedInt(value, fallback, minimum, maximum) {
  const parsed = Number.parseInt(String(value || ""), 10);
  return Math.max(minimum, Math.min(Number.isFinite(parsed) ? parsed : fallback, maximum));
}
