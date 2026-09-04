# MCP Gateway Validation

## Acceptance evidence

| Requirement | Implementation evidence | Regression evidence |
|---|---|---|
| Provider-neutral service | `apps/secopsai-mcp`, package `@secopsai/mcp-gateway`, service `secopsai-mcp-gateway` | Node metadata and root-service tests |
| One canonical tool registry | All client profiles instantiate `createSecOpsMcpServer` | Nine-tool MCP conformance test |
| Remote standard transport | Streamable HTTP at `/mcp` | SDK client initialization, list, call, and close test |
| Local compatibility transport | Explicit `src/stdio.js` adapter using the same registry | Static check and fail-closed configuration tests |
| OAuth discovery | RFC 9728 protected-resource metadata and `WWW-Authenticate` challenge | Unauthenticated request test |
| Tenant/workspace/client binding | Exact organization, workspace, and OAuth client allowlists | Protected configuration, identity, and Core rejection tests |
| Explicit browser origins | Empty default, wildcard rejection, exact request-origin enforcement | Unapproved-origin test |
| Complete activity history | Core `mcp_client_sessions` and append-only `mcp_client_events` | Activity, tool-call, deduplication, and redaction tests |
| Revocation | Core revoke/status endpoints and gateway pre-initialization check | Durable revocation and denied-initialization tests |
| Mission Control visibility | MCP Integrations card with client, scope, activity, and revoked-session state | Dashboard static/runtime and hosted-worker tests |
| Existing ChatGPT support | ChatGPT remains a client profile and compatibility response alias | Profile discovery and dashboard worker tests |
| Provider-token isolation | Gateway accepts SecOpsAI OAuth only and Core token remains server-side | Core-client credential non-disclosure test |

## Boundaries

The conformance suite proves protocol behavior against the official MCP SDK. It
does not claim that every version of every third-party client implements remote
OAuth. Client compatibility must be verified during onboarding. The gateway
does not route SecOpsAI's internal OpenCodex model jobs and does not expose
protected security decisions or publication actions.

## Verification record

Verified locally on 2026-09-04:

- MCP SDK conformance and security suite: 14 passed.
- MCP package syntax checks: passed.
- MCP production dependency audit: 0 vulnerabilities.
- Core MCP/API/workflow/isolated-job regression set: 38 passed.
- Complete Core test suite: 726 passed and 4 subtests passed.
- Dashboard JavaScript contract suites: passed.
- Dashboard local-helper suite: 47 passed.
- Dashboard MCP user-interface suite: 17 passed.
- Documentation examples, blog integrity, strict MkDocs build, workflow graph,
  Python compilation, and both repositories' diff checks: passed.

The canonical hostname and configuration are implemented, but deployment is
intentionally not claimed by this report. Production activation still requires
the SecOpsAI OAuth issuer/JWKS, exact client registrations, audited browser
origins, matching organization/workspace settings, the dedicated Core read
credential, DNS, and TLS.
