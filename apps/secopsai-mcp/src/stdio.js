import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { localStdioIdentity } from "./auth.js";
import { loadConfig } from "./config.js";
import { CoreClient } from "./core-client.js";
import { createSecOpsMcpServer } from "./tools.js";

const config = loadConfig();
const identity = localStdioIdentity(config);
const coreClient = new CoreClient(config);

const status = await coreClient.sessionStatus(identity.sessionId);
if (status?.session?.status === "revoked") throw new Error("This local SecOpsAI MCP session has been revoked");
await coreClient.recordActivity(identity, "stdio_started", { process_id: process.pid });

const server = createSecOpsMcpServer({ identity, coreClient, config });
const transport = new StdioServerTransport();
await server.connect(transport);
