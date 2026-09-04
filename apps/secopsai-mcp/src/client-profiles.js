const CLIENT_PROFILES = Object.freeze([
  Object.freeze({
    id: "chatgpt",
    name: "ChatGPT",
    transport: "streamable-http",
    authentication: "oauth-2.1",
    setup: "Register the canonical HTTPS /mcp endpoint as a remote MCP app and complete OAuth authorization.",
  }),
  Object.freeze({
    id: "codex",
    name: "Codex",
    transport: "streamable-http-or-stdio",
    authentication: "oauth-2.1-or-local-process",
    setup: "Use the hosted endpoint with OAuth or the explicit local stdio command.",
  }),
  Object.freeze({
    id: "claude",
    name: "Claude-compatible clients",
    transport: "streamable-http-or-stdio",
    authentication: "oauth-2.1-or-local-process",
    setup: "Use remote OAuth when supported by the client; otherwise use the local stdio adapter.",
  }),
  Object.freeze({
    id: "vscode",
    name: "Visual Studio Code",
    transport: "streamable-http-or-stdio",
    authentication: "oauth-2.1-or-local-process",
    setup: "Register the remote endpoint in MCP configuration or launch the local stdio adapter.",
  }),
  Object.freeze({
    id: "cursor",
    name: "Cursor-compatible clients",
    transport: "streamable-http-or-stdio",
    authentication: "client-dependent",
    setup: "Use the strongest transport and authorization mode supported by the installed client version.",
  }),
  Object.freeze({
    id: "generic",
    name: "Other MCP clients",
    transport: "streamable-http-or-stdio",
    authentication: "oauth-2.1-or-local-process",
    setup: "Use MCP Streamable HTTP with OAuth 2.1, or the opt-in local stdio compatibility adapter.",
  }),
]);

export function publicGatewayMetadata(config) {
  const configured = new Map(config.clientProfiles.map((item) => [item.profile, item]));
  return {
    service: "secopsai-mcp-gateway",
    protocol: "model-context-protocol",
    endpoint: new URL("/mcp", config.resource).toString(),
    transports: ["streamable-http", ...(config.stdioEnabled ? ["stdio-local"] : [])],
    authorization: "oauth-2.1",
    scopes: [...config.scopes],
    client_profiles: CLIENT_PROFILES.map((profile) => ({
      ...profile,
      configured: profile.id === "generic" || configured.has(profile.id),
    })),
    safety: {
      default_access: "read-only",
      provider_tokens_accepted: false,
      protected_actions_exposed: false,
    },
  };
}

export function clientDisplayName(config, clientId) {
  const match = config.clientProfiles.find((item) => item.id === clientId);
  return match?.name || clientId || "unidentified-mcp-client";
}
