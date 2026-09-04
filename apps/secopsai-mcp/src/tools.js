import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

import { AuthenticationError, authenticationChallenge, requireScope } from "./auth.js";

const limit = z.number().int().min(1).max(100).optional().describe("Maximum records to return; defaults to 50.");
const optionalText = z.string().max(240).optional();

const TOOLS = [
  {
    name: "secopsai_workspace_summary",
    title: "SecOpsAI workspace summary",
    description: "Read a compact summary of current findings, discovered assets, research cases, and local intelligence queue health.",
    scope: "secopsai.workspace.read",
    action: "workspace_summary",
    inputSchema: {},
  },
  {
    name: "secopsai_list_findings",
    title: "List SecOpsAI findings",
    description: "List normalized security findings. Use filters to keep the response relevant; raw telemetry is never returned.",
    scope: "secopsai.findings.read",
    action: "list_findings",
    inputSchema: { severity: optionalText, status: optionalText, source: optionalText, limit },
  },
  {
    name: "secopsai_get_finding",
    title: "Get a SecOpsAI finding",
    description: "Read minimized evidence and workflow state for one exact finding ID.",
    scope: "secopsai.findings.read",
    action: "get_finding",
    inputSchema: { finding_id: z.string().min(1).max(240) },
  },
  {
    name: "secopsai_list_assets",
    title: "List SecOpsAI Edge assets",
    description: "List normalized assets discovered by SecOpsAI Edge without exposing MAC addresses or raw scans.",
    scope: "secopsai.assets.read",
    action: "list_assets",
    inputSchema: { limit },
  },
  {
    name: "secopsai_asset_changes",
    title: "Review SecOpsAI asset changes",
    description: "Read recent asset graph changes, optionally focused on one asset or graph node.",
    scope: "secopsai.assets.read",
    action: "asset_changes",
    inputSchema: { target_id: optionalText, limit },
  },
  {
    name: "secopsai_list_research_cases",
    title: "List SecOpsAI research cases",
    description: "List durable defensive research cases with workflow state and evidence counts.",
    scope: "secopsai.research.read",
    action: "list_research_cases",
    inputSchema: { status: optionalText, case_type: optionalText, limit },
  },
  {
    name: "secopsai_get_research_case",
    title: "Get a SecOpsAI research case",
    description: "Read normalized subjects, evidence, verdicts, and publication readiness for one research case.",
    scope: "secopsai.research.read",
    action: "get_research_case",
    inputSchema: { case_id: z.string().min(1).max(240) },
  },
  {
    name: "secopsai_research_evidence_matrix",
    title: "Build a SecOpsAI evidence matrix",
    description: "Build a read-only claim-to-evidence matrix for a research case. This does not persist, approve, disclose, or publish anything.",
    scope: "secopsai.research.read",
    action: "research_evidence_matrix",
    inputSchema: { case_id: z.string().min(1).max(240) },
  },
  {
    name: "secopsai_publication_readiness",
    title: "Check SecOpsAI publication readiness",
    description: "Read publication blockers and human approval state for a research case without changing or publishing it.",
    scope: "secopsai.research.read",
    action: "publication_readiness",
    inputSchema: { case_id: z.string().min(1).max(240) },
  },
];

export function createSecOpsMcpServer({ identity, coreClient, config }) {
  const server = new McpServer({ name: "secopsai", version: "0.2.0" });
  for (const tool of TOOLS) {
    server.registerTool(
      tool.name,
      {
        title: tool.title,
        description: tool.description,
        inputSchema: tool.inputSchema,
        securitySchemes: [{ type: "oauth2", scopes: [tool.scope] }],
        _meta: { securitySchemes: [{ type: "oauth2", scopes: [tool.scope] }] },
        annotations: {
          readOnlyHint: true,
          destructiveHint: false,
          idempotentHint: true,
          openWorldHint: false,
        },
      },
      async (args) => {
        try {
          requireScope(identity, tool.scope);
          const result = await coreClient.query(tool.action, args || {}, { identity, toolName: tool.name });
          return {
            content: [{ type: "text", text: summaryText(tool, result) }],
            structuredContent: { result },
          };
        } catch (error) {
          try {
            await coreClient.recordActivity(
              identity,
              "tool_call",
              { result: "failed", error_type: error instanceof AuthenticationError ? error.code : "tool_error" },
              tool.name,
            );
          } catch (auditError) {
            if (config.auditRequired) {
              return {
                content: [{ type: "text", text: "SecOpsAI denied the request because the required audit record could not be written." }],
                isError: true,
              };
            }
          }
          if (error instanceof AuthenticationError) {
            return {
              content: [{ type: "text", text: error.message }],
              _meta: { "mcp/www_authenticate": [authenticationChallenge(config, error)] },
              isError: true,
            };
          }
          return {
            content: [{ type: "text", text: `SecOpsAI could not complete this read-only request: ${safeMessage(error)}` }],
            isError: true,
          };
        }
      },
    );
  }
  return server;
}

export function toolDefinitions() {
  return TOOLS.map(({ inputSchema, ...tool }) => ({ ...tool, readOnly: true }));
}

function summaryText(tool, result) {
  const data = result?.data || {};
  const count = data.count ?? data.findings?.total ?? data.assets?.total ?? data.research_cases?.total;
  return count === undefined ? `${tool.title} completed.` : `${tool.title} returned ${count} record(s).`;
}

function safeMessage(error) {
  return String(error?.message || "request failed").replace(/[\r\n]/g, " ").slice(0, 500);
}
