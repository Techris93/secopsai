const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

export class CoreClient {
  constructor(config, fetchImpl = globalThis.fetch) {
    this.baseUrl = config.coreApiUrl.replace(/\/+$/, "");
    this.token = config.coreReadToken;
    this.timeoutMs = config.coreTimeoutMs;
    this.fetch = fetchImpl;
  }

  async query(action, inputs = {}) {
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
          "user-agent": "secopsai-chatgpt-app/0.1.0",
        },
        body: JSON.stringify({ action, inputs }),
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
}
