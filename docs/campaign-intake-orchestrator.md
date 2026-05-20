# Campaign Intake Orchestrator

SecOpsAI Autonomous Discovery now runs a constrained, deterministic intake
orchestrator before a source report can become Campaign Research input. The
orchestrator is intentionally not an LLM-driven decision maker. It is a
rule-based router that classifies a candidate, validates extracted entities,
separates source references from attacker IOCs, and explains which actions are
safe.

## Why It Exists

Discovery feeds contain many legitimate security stories that are not package
supply-chain campaigns. A malware/APT report such as a Webworm backdoor story
can mention C2, Discord, Microsoft Graph API, and a trusted news URL without
naming any npm, PyPI, Open VSX, or other package artifact. Those reports should
be retained as threat-intel leads, but they should not create fake package rows
or package SOC findings.

The orchestrator prevents common extraction failures:

- CSS and markup tokens such as `byline-author`, `font-family`, and
  `docs-internal-guid-*`.
- Generic article words such as `overview`, `description`, `impact`, `known`,
  `push`, and `open-source`.
- Empty placeholders such as `@scope/pkg`, `group:artifact`, and `org/model`.
- Source domains such as `thehackernews.com`, `security.googleblog.com`, and
  `kb.cert.org` being treated as attacker infrastructure.
- Placeholder actors or publishers such as `known` and `unknown`.

## Candidate Routes

Each candidate receives an `orchestrator` object with:

- `campaign_type`: for example `supply_chain_package_campaign`,
  `malware_apt_c2`, `vulnerability_advisory`, `github_token_breach`, or
  `vscode_extension_compromise`.
- `recommended_route`: for example `campaign_research`,
  `threat_intel_review`, `vulnerability_tracking`,
  `github_security_review`, or `extension_security_review`.
- `validated_packages` and `rejected_package_candidates`.
- `validated_iocs` and `rejected_iocs`.
- `source_references`.
- `allowed_actions`, `blocked_actions`, `route_blockers`, and
  `recommended_next_action`.

Only candidates routed to `campaign_research` without route blockers are
eligible for package Campaign Research autopilot selection.

## Source References vs IOCs

Source references are reporting locations: article URLs, advisory pages, or
vendor blogs. They are useful references, but they are not attacker
infrastructure by themselves.

Validated IOCs are attacker-controlled or attacker-used indicators such as C2
domains, IPs, hashes, payload filenames, or repository descriptions. The
orchestrator removes known reporting domains and the candidate source host from
IOC fields unless the operator supplies stronger evidence separately.

## CLI Usage

Run discovery with orchestrator review:

```bash
python3 -m secopsai.cli supply-chain discover-campaigns --since 24h --limit 10 --orchestrate --json
```

Review one cached or exported candidate:

```bash
python3 -m secopsai.cli supply-chain orchestrate-candidate --input candidate.json --json
```

Run autopilot in read-only mode. Autopilot only researches orchestrator-approved
package campaign candidates:

```bash
python3 -m secopsai.cli supply-chain campaign-autopilot --since 24h --dry-run --orchestrate --json
```

## Operator Workflow

1. Run Discovery.
2. Open Orchestrator Review for each candidate.
3. Confirm candidate type, route, validated packages, rejected noise, validated
   IOCs, and missing evidence.
4. Promote only candidates routed to Campaign Research with validated
   package/extension artifacts.
5. Add only validated packages, publishers, malware names, extension IDs,
   GitHub repos, or attacker IOCs to the watchlist.
6. Persist findings or create review-only blog drafts only after the
   orchestrator and analyst evidence support the action.

## Dashboard Notes

Hosted `secopsai-dashboard` intentionally does not depend on
`SECOPSAI_HELPER_BASE_URL` in production. Helper-backed actions should be run in
local helper mode unless a live private helper URL is explicitly configured.

Local helper workflow:

```bash
cd /Users/chrixchange/Documents/Codex/2026-04-20-fix-issues-techris-apr-19-2026/secopsai-dashboard-repo/secopsai-dashboard
./start-local-dashboard-stack.sh
open http://127.0.0.1:45680
```

Local helper mode supports Triage Ops investigation, Campaign Research,
Autonomous Discovery, and Blog Ops draft/review actions. It does not deploy the
blog when deploy capability is false; use hosted Blog Ops or the GitHub
Actions/Cloudflare deployment workflow for deployment.
