# Universal MCP Gateway

SecOpsAI exposes one provider-neutral Model Context Protocol gateway. ChatGPT,
Codex, Claude-compatible clients, Visual Studio Code, Cursor-compatible clients,
and other compatible MCP hosts use the same tool names, scopes, evidence
contract, and audit boundary. Client profiles contain onboarding metadata only;
they never fork tool behavior.

## Architecture

```text
MCP host
  -> HTTPS /mcp (Streamable HTTP) + SecOpsAI OAuth 2.1
  -> SecOpsAI MCP Gateway
  -> tenant, workspace, audience, approved-client, scope, and revocation checks
  -> SecOpsAI Core read API
  -> minimized findings, assets, and research records

Local MCP host
  -> explicit stdio process
  -> the same tool registry and Core client
```

The remote gateway is the canonical interface. The stdio adapter exists only
for a local client that cannot complete remote Streamable HTTP and OAuth. It is
opt-in, refuses to run in `pilot` or `production` mode, and never weakens the
remote authorization policy.

## Security properties

- All nine tools are read-only and declare the exact required OAuth scope.
- Access tokens must be signed by the configured issuer and bound to the exact
  gateway audience.
- Protected deployments require exact SecOpsAI organization and workspace
  claims plus an explicit OAuth client allowlist.
- Browser requests with an `Origin` header are rejected unless that exact
  origin is configured. There is no permissive default or wildcard.
- Provider API keys and model-provider tokens are not accepted or forwarded.
- Core receives a separate server-side read credential.
- Subjects and sessions are stored as one-way SHA-256 identifiers. Access
  tokens, raw subject claims, cookies, and provider credentials are not stored.
- Every authenticated request and tool call updates the Core activity ledger.
- A revoked session is denied before MCP initialization and cannot reactivate
  itself by sending more traffic.
- Verdicts, containment, sandbox submission, disclosure, publication, and
  deployment are not exposed by this gateway.

## Remote deployment

Use `https://mcp.secopsai.dev` as the canonical resource origin and
`https://mcp.secopsai.dev/mcp` as the MCP endpoint. The authorization server
must support OAuth authorization code with PKCE `S256`, metadata discovery,
resource indicators, and short-lived audience-bound access tokens.

Required settings:

| Setting | Purpose |
|---|---|
| `SECOPSAI_MCP_ENVIRONMENT=production` | Enables fail-closed production validation |
| `SECOPSAI_MCP_RESOURCE=https://mcp.secopsai.dev` | Canonical protected resource |
| `SECOPSAI_MCP_AUTHORIZATION_SERVER` | OAuth authorization-server issuer |
| `SECOPSAI_MCP_ISSUER` | Exact accepted JWT issuer |
| `SECOPSAI_MCP_AUDIENCE=https://mcp.secopsai.dev` | Exact accepted token audience |
| `SECOPSAI_MCP_JWKS_URL` | HTTPS signing-key endpoint |
| `SECOPSAI_MCP_ORGANIZATION_ID` | Exact permitted SecOpsAI organization |
| `SECOPSAI_MCP_WORKSPACE_ID` | Exact permitted SecOpsAI workspace |
| `SECOPSAI_MCP_ALLOWED_CLIENT_IDS` | Comma-separated approved OAuth client IDs |
| `SECOPSAI_MCP_ALLOWED_HOSTS=mcp.secopsai.dev` | Exact HTTP host allowlist |
| `SECOPSAI_MCP_ALLOWED_ORIGINS` | Explicit audited browser origins; at least one is required in pilot/production |
| `SECOPSAI_MCP_CLIENTS_JSON` | Optional audited client names and profiles |
| `SECOPSAI_CORE_API_URL` | Core API origin |
| `SECOPSAI_CORE_READ_TOKEN` | Dedicated Core read credential, at least 32 characters |

Core must use the same workspace boundary through
`SECOPSAI_CORE_WORKSPACE_ID`. Existing single-workspace Core deployments
temporarily default that value to `SECOPSAI_CORE_ORGANIZATION_ID`; set it
explicitly before onboarding a second workspace.

Example non-secret client metadata:

```json
[
  {"id":"chatgpt-production-client","profile":"chatgpt","name":"ChatGPT production"},
  {"id":"vscode-security-team","profile":"vscode","name":"Security team VS Code"}
]
```

The IDs in that JSON must also be present in
`SECOPSAI_MCP_ALLOWED_CLIENT_IDS`. Do not put client secrets in the JSON.

Verify after deployment:

```bash
curl -fsS https://mcp.secopsai.dev/readyz
curl -fsS https://mcp.secopsai.dev/.well-known/oauth-protected-resource
curl -fsS https://mcp.secopsai.dev/.well-known/secopsai-mcp
```

## Client profiles

Register a separate OAuth client for every product or managed client group. Give
each client only the scopes its operators need. ChatGPT is one profile and uses
the same endpoint as every other remote client.

| Profile | Preferred mode | Compatibility mode |
|---|---|---|
| ChatGPT | Remote Streamable HTTP and OAuth | None |
| Codex | Remote Streamable HTTP and OAuth | Local stdio |
| Claude-compatible | Remote OAuth when supported | Local stdio |
| Visual Studio Code | Remote Streamable HTTP and OAuth | Local stdio |
| Cursor-compatible | Strongest mode supported by the installed version | Local stdio |
| Generic MCP | Remote Streamable HTTP and OAuth | Local stdio |

Client capabilities change independently. Confirm the installed client's
current transport and OAuth support before onboarding it. Do not enable an
unapproved client ID merely because its product name appears in this table.

## Local stdio compatibility

Use stdio only on a trusted workstation. Export the Core URL and read token from
the operator's protected environment, not from a committed client file:

```bash
cd /Users/chrixchange/secopsai/apps/secopsai-mcp
export SECOPSAI_MCP_ENVIRONMENT=local
export SECOPSAI_MCP_STDIO_ENABLED=true
export SECOPSAI_MCP_STDIO_CLIENT_ID=local-security-client
export SECOPSAI_MCP_ORGANIZATION_ID=local
export SECOPSAI_MCP_WORKSPACE_ID=local
export SECOPSAI_CORE_API_URL=http://127.0.0.1:8001
export SECOPSAI_CORE_READ_TOKEN='use-the-existing-protected-core-read-token'
npm run start:stdio
```

The process communicates over stdin/stdout and uses the same nine tool
definitions as the remote gateway. Restrict local scopes with
`SECOPSAI_MCP_STDIO_SCOPES` when the client does not need the complete read-only
surface.

## Mission Control and revocation

Open **Administration -> Automation -> Models -> MCP integrations**. The card
shows the configured endpoint, compatible client profiles, recent clients,
sessions active within the last 15 minutes, granted scopes, last activity, and
revoked sessions. "Connected" means recently active because the remote gateway
is stateless; it does not claim that a persistent socket is open.

Core provides protected operational endpoints:

- `GET /api/v1/mcp/sessions` uses the Core read credential.
- `GET /api/v1/mcp/sessions/{session_id}/status` uses the Core read credential.
- `POST /api/v1/mcp/sessions/{session_id}/revoke` uses the separate Core
  intelligence credential and requires an operator reason.

Revocation takes effect on the next MCP request. Also revoke the OAuth grant at
the authorization provider when terminating access permanently.

## Verification

```bash
cd /Users/chrixchange/secopsai/apps/secopsai-mcp
npm ci --ignore-scripts
npm run check
npm test
npm audit --audit-level=moderate

cd /Users/chrixchange/secopsai
.venv/bin/python -m pytest tests/test_mcp_gateway.py tests/test_core_api.py -q
python3 scripts/verify_docs_examples.py
git diff --check
```

## Standards references

- [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
  for protected-resource discovery, audience binding, OAuth 2.1, and PKCE.
- [VS Code full MCP specification support](https://code.visualstudio.com/blogs/2025/06/12/full-mcp-spec-support)
  for remote Streamable HTTP and OAuth client compatibility.
