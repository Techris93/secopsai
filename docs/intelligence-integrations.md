# Intelligence integrations

SecOpsAI supports two separate model-assisted operating modes. Both use the same versioned, read-only intelligence contract and both keep raw scanner output, packet data, package artifacts, credentials, and private keys outside model context.

## Choose the correct mode

| Mode | Where the model runs | Authentication | Best use |
|---|---|---|---|
| Local Codex bridge | Codex CLI on the operator's Mac or Linux sensor | Existing local ChatGPT sign-in | Private local analysis and Mission Control actions |
| ChatGPT app | ChatGPT calls the hosted SecOpsAI MCP server | SecOpsAI OAuth plus the user's ChatGPT account | Conversational access to authorized findings, assets, and research cases |

ChatGPT authentication pays for and identifies the model session. SecOpsAI OAuth separately decides which SecOpsAI data that person may read. One never replaces the other.

## Local Codex bridge

The bridge accepts only named SecOpsAI actions. It does not expose an arbitrary prompt or shell endpoint. Core builds a minimized context, the bridge runs Codex in an ephemeral read-only sandbox, and the structured result returns to the durable job record for human review.

Check the local installation and ChatGPT sign-in:

```bash
cd /Users/chrixchange/secopsai
.venv/bin/python -m secopsai.cli intelligence bridge doctor
```

List the approved actions:

```bash
.venv/bin/python -m secopsai.cli intelligence actions
```

Queue an explanation for one finding:

```bash
.venv/bin/python -m secopsai.cli intelligence enqueue \
  --action explain_finding \
  --target-id FND-EXAMPLE
```

Process one queued request:

```bash
.venv/bin/python -m secopsai.cli intelligence bridge run --once
```

Install the bridge as a user-level background service:

```bash
.venv/bin/python -m secopsai.cli intelligence bridge service install
.venv/bin/python -m secopsai.cli intelligence bridge service status
.venv/bin/python -m secopsai.cli intelligence bridge service logs
```

The installer creates `~/Library/LaunchAgents/ai.secopsai.codex-bridge.plist` on macOS or `~/.config/systemd/user/secopsai-codex-bridge.service` on Linux. It does not copy or persist a ChatGPT credential. Codex continues to own its local authentication state.

## ChatGPT app MCP server

The app exposes nine read-only tools:

- workspace summary
- list and get findings
- list assets and recent asset changes
- list and get research cases
- build a non-persisting evidence matrix
- check publication readiness

The MCP server never runs Codex. ChatGPT provides the reasoning and calls the tools. The server verifies the SecOpsAI OAuth access token, checks issuer, audience, expiry, signature, and per-tool scope, then calls the Core intelligence API with a server-side read credential.

### Local protocol test

```bash
cd /Users/chrixchange/secopsai/apps/secopsai-chatgpt
npm ci --ignore-scripts
npm test
npm audit --audit-level=moderate
```

### Production OAuth requirements

Use an established OAuth 2.1 provider such as Auth0, Okta, Cognito, or Stytch. Configure authorization-code flow with PKCE `S256`, a token audience equal to `SECOPSAI_MCP_RESOURCE`, short-lived signed access tokens, the four SecOpsAI read scopes, and a JWKS endpoint. Do not build a custom password or token issuer inside the MCP server.

Required scopes:

- `secopsai.workspace.read`
- `secopsai.findings.read`
- `secopsai.assets.read`
- `secopsai.research.read`

Required Render values:

| Variable | Purpose |
|---|---|
| `SECOPSAI_MCP_AUTHORIZATION_SERVER` | OAuth issuer base URL advertised to ChatGPT |
| `SECOPSAI_MCP_ISSUER` | Exact expected JWT `iss` value |
| `SECOPSAI_MCP_JWKS_URL` | Provider signing-key endpoint |
| `SECOPSAI_CORE_READ_TOKEN` | Same server-side read credential configured on Core |

The Blueprint fixes the production MCP resource and audience to `https://secopsai-chatgpt-app.onrender.com`. Change both together if a custom domain is introduced.

After deployment, verify:

```bash
curl -sS https://secopsai-chatgpt-app.onrender.com/readyz
curl -sS https://secopsai-chatgpt-app.onrender.com/.well-known/oauth-protected-resource
```

Then enable ChatGPT developer mode, create a developer app using `https://secopsai-chatgpt-app.onrender.com/mcp`, complete the OAuth link, and test `secopsai_workspace_summary` before enabling any wider pilot group.

The current hosted Core is a single-tenant pilot deployment. Limit OAuth access to the same invited SecOpsAI organization. Do not use this deployment for multiple unrelated customers until Core enforces organization membership on every query.

## Security boundary

- Every MCP tool is read-only and declares its exact OAuth scope.
- Core read, ingest, and intelligence credentials are different.
- The local bridge runs only allowlisted actions and structured output.
- Raw telemetry and artifact contents are removed before context construction.
- Package metadata and finding text are treated as untrusted data, not model instructions.
- Model output is advisory. It cannot resolve a finding, approve disclosure, submit a sandbox artifact, or publish research.
