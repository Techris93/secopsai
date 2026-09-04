const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export class CoreClient {
  constructor(config, fetchImpl = globalThis.fetch) {
    this.baseUrl = config.coreApiUrl.replace(/\/+$/, "");
    this.token = config.coreReadToken;
    this.timeoutMs = config.coreTimeoutMs;
    this.fetch = fetchImpl;
  }

  async query(action, inputs = {}, context = {}) {
    if (!this.token) throw new Error("SecOpsAI Core read access is not configured");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetch(`${this.baseUrl}/api/v1/intelligence/query`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.token}`,
          "content-type": "application/json",
          accept: "application/json",
          "user-agent": "secopsai-mcp-gateway/0.2.0",
        },
        body: JSON.stringify({ action, inputs, mcp_context: mcpContext(context.identity, context.toolName) }),
        redirect: "error",
        signal: controller.signal,
      });
      const declared = Number(response.headers.get("content-length") || 0);
      if (declared > MAX_RESPONSE_BYTES) throw new Error("SecOpsAI Core response exceeds the MCP limit");
      const raw = new Uint8Array(await response.arrayBuffer());
      if (raw.byteLength > MAX_RESPONSE_BYTES) throw new Error("SecOpsAI Core response exceeds the MCP limit");
      let payload;
      try {
        payload = JSON.parse(new TextDecoder().decode(raw));
      } catch {
        throw new Error("SecOpsAI Core returned invalid JSON");
      }
      if (!response.ok) {
        throw new Error(`SecOpsAI Core request failed (${response.status}): ${String(payload?.detail || "request rejected").slice(0, 500)}`);
      }
      if (!payload || payload.schema_version !== "secopsai.intelligence.v1") {
        throw new Error("SecOpsAI Core returned an unsupported intelligence contract");
      }
      return payload;
    } finally {
      clearTimeout(timer);
    }
  }


  async recordActivity(identity, eventType, details = {}, toolName = "") {
    return this.request("/api/v1/mcp/activity", {
      method: "POST",
      body: { ...mcpContext(identity, toolName), event_type: eventType, details },
    });
  }

  async sessionStatus(sessionId) {
    return this.request(`/api/v1/mcp/sessions/${encodeURIComponent(sessionId)}/status`, { method: "GET" });
  }

  async request(path, { method, body }) {
    if (!this.token) throw new Error("SecOpsAI Core read access is not configured");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetch(`${this.baseUrl}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${this.token}`,
          accept: "application/json",
          ...(body ? { "content-type": "application/json" } : {}),
          "user-agent": "secopsai-mcp-gateway/0.2.0",
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
        redirect: "error",
        signal: controller.signal,
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(`SecOpsAI Core MCP audit request failed (${response.status})`);
      return payload;
    } finally {
      clearTimeout(timer);
    }
  }
}

function mcpContext(identity, toolName = "") {
  if (!identity) return {};
  return {
    session_id: String(identity.sessionId || ""),
    client_id: String(identity.clientId || ""),
    client_name: String(identity.clientName || ""),
    subject_id: String(identity.subjectId || ""),
    organization_id: String(identity.organizationId || ""),
    workspace_id: String(identity.workspaceId || ""),
    transport: String(identity.transport || ""),
    scopes: [...(identity.scopes || [])],
    tool_name: String(toolName || ""),
  };
}
