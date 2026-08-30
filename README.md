# SecOpsAI

**SecOpsAI v1.0.0** is the current stable release.

**Evidence-first security operations for agent telemetry, software supply chains, and analyst-reviewed research.**

SecOpsAI brings host and AI-agent telemetry, package-registry surveillance,
findings triage, guarded automation, and security publishing into one
local-first workflow. Deterministic evidence stays authoritative; model review
is bounded, optional, and visible to the operator.

[Website](https://secopsai.dev) · [Documentation](https://docs.secopsai.dev) · [Install](docs/getting-started.md) · [Mission Control](https://github.com/Techris93/secopsai-dashboard) · [Security policy](SECURITY.md)

[![Release](https://img.shields.io/github/v/release/Techris93/secopsai?display_name=tag&color=276c5c)](https://github.com/Techris93/secopsai/releases/latest) [![npm](https://img.shields.io/npm/v/secopsai?color=276c5c)](https://www.npmjs.com/package/secopsai) [![GitHub Marketplace](https://img.shields.io/badge/GitHub%20Marketplace-SecOpsAI%20Guard-276c5c)](https://github.com/marketplace/actions/secopsai-supply-chain-guard) [![License](https://img.shields.io/github/license/Techris93/secopsai?color=276c5c)](LICENSE)

[![SecOpsAI Mission Control showing priorities, investigation queues, and service health](docs/assets/mission-control/overview.png)](docs/assets/mission-control/overview.png)

> The product tour uses representative sample data. It contains no live
> credentials, private telemetry, customer records, or local filesystem paths.

## Why SecOpsAI

Security evidence is usually split across host logs, agent activity, package
registries, issue queues, research notes, and deployment tools. SecOpsAI
normalizes those signals into a shared evidence model, helps operators decide
what deserves attention, and keeps consequential actions behind explicit
approval boundaries.

| Outcome | What SecOpsAI provides |
| --- | --- |
| See the operating picture | Unified OpenClaw, Hermes, macOS, Linux, Windows, Edge, CI, and registry evidence |
| Find risky software early | Multi-ecosystem registry monitoring, no-execution artifact analysis, advisories, and AI Dependency Guard |
| Investigate with context | Durable Research Cases, IOC extraction, correlations, evidence matrices, and bounded model review |
| Respond safely | Explainable triage, reversible low-risk automation, protected actions, and complete audit history |
| Route engineering work safely | Reviewed specialist profiles, persisted OpenCodex model routing, bounded contracts, isolated worktrees, and independent review |
| Publish defensible research | Evidence-linked drafts, media review, editorial approval, archive-safe staging, and separate deployment |

## Core Capabilities

| Area | Capability | Operator guide |
| --- | --- | --- |
| Detection | Cross-platform collection, normalization, correlation, adaptive scoring, and findings | [Platform overview](docs/index.md) |
| Supply chain | npm, PyPI, Packagist, Go, Maven, NuGet, RubyGems, Open VSX, crates, Hugging Face, and container evidence | [Supply-chain security](docs/supply-chain.md) |
| AI-built software | Hallucinated, missing, newly registered, lookalike, and source-mismatch dependency review | [AI Dependency Guard](docs/ai-dependency-guard.md) |
| Artifact analysis | Metadata indexing, quarantine, checksums, static/YARA rules, minimized triage, and analyst escalation | [Artifact Fleet](docs/artifact-fleet-operations.md) |
| Research | Durable cases, competing hypotheses, evidence plans, claim ledgers, blinded review, visual QA, disclosure, and sandbox gates | [Research reliability](docs/research-reliability.md) |
| Triage | Evidence bundles, dispositions, queued actions, mitigation, and auditable closure | [Findings triage](docs/findings-triage-guide.md) |
| Specialist work | Deterministic expertise routing, explicit OpenCodex model/fallback snapshots, guarded worktrees, and independent review | [Specialist Orchestrator](docs/specialist-orchestrator.md) |
| Publishing | Source-backed drafts, image review, feeds, archive-safe staging, and protected deployment | [Blog publishing](docs/blog-publishing.md) |
| Enterprise | Read-only cloud adapters, vulnerability context, Kubernetes posture, authorized DAST plans, and governance records | [Enterprise architecture](docs/enterprise-security-operations-architecture.md) |

## Quick Start

Install the complete local-first platform:

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
cd ~/secopsai
source .venv/bin/activate

secopsai status
secopsai refresh --platform macos,openclaw,hermes
secopsai triage summary
```

The installer checks out the current stable release and runs the documented
setup profile. Review the script before running it in a sensitive environment,
or use the manual path:

```bash
git clone https://github.com/Techris93/secopsai.git
cd secopsai
bash setup.sh --non-interactive --profile default
source .venv/bin/activate
```

The published npm package is the OpenClaw plugin distribution, not the complete
Python platform. Install it through OpenClaw:

```bash
openclaw plugins install secopsai
```

For repository scanning in CI, use the
[SecOpsAI Supply Chain Guard](https://github.com/marketplace/actions/secopsai-supply-chain-guard):

```yaml
- uses: Techris93/secopsai-action@v1.0.0
  with:
    mode: advisory-check
    ecosystem: npm
    package: node-ipc
    version: 12.0.1
    fail-on-severity: high
```

| Distribution | Use it for | Status |
| --- | --- | --- |
| Installer / source checkout | Complete SecOpsAI Core and CLI | Recommended |
| Python editable install | Local development and test contributions | Documented in [Contributing](CONTRIBUTING.md) |
| npm `secopsai@1.0.0` | Published OpenClaw plugin | Available |
| GitHub Packages `@techris93/secopsai` | Authenticated scoped package workflow | Published; access may require `read:packages` |
| Marketplace Action `v1.0.0` | Advisory, package, discovery, and triage checks in GitHub Actions | Available |

See [Getting Started](docs/getting-started.md) for platform-specific setup,
[GitHub Distribution](docs/github-distribution-plan.md) for the exact npm and
GitHub Packages boundaries, and [Deployment](docs/deployment-guide.md) for
long-running services.

### Open Mission Control

Mission Control is maintained separately so the static Cloudflare-compatible
console and local helper can evolve without coupling UI delivery to Core:

```bash
git clone https://github.com/Techris93/secopsai-dashboard.git
cd secopsai-dashboard/secopsai-dashboard
cp .env.example .env
./start-local-dashboard-stack.sh
```

Open `http://127.0.0.1:45680`. Local helper actions require the configured
action token; hosted mode fails safely when a helper-backed capability is not
configured.

In **Work**, Specialist Orchestrator can preview a deterministic route for each
item, save a recommendation, queue read-only analysis, or prepare an explicitly
approved isolated worktree. The specialist defines the expertise; the persisted
operator-selected OpenCodex model performs the work. OpenClaw and Hermes remain
separate optional telemetry and compatibility runtimes.

## Product Tour

Mission Control is the operator-facing companion to the SecOpsAI CLI. It keeps
the dark green navigation and restrained green action language of the product
concept while using a bright, high-contrast workspace for dense operational
data.

### Overview

The full-width overview above shows priorities, investigation queues, research
production, and service health without exposing internal implementation views
as competing products.

### Findings and triage

Work the latest evidence-backed detections first. Each row exposes severity,
confidence, environment impact, evidence state, ownership, and the next safe
action without turning scanner output into an automatic verdict.

[![Findings backlog ordered latest first with evidence and response state](docs/assets/mission-control/findings.png)](docs/assets/mission-control/findings.png)

### Model routing

Persist the model you chose, see its current health, and decide explicitly
whether an ordered fallback policy may be used. Primary-only mode leaves work
queued rather than silently consuming another provider.

[![Model routing with a selected primary model, health, and explicit fallback policy](docs/assets/mission-control/model-routing.png)](docs/assets/mission-control/model-routing.png)

### Research pipeline and Artifact Fleet

Index registry metadata, run deterministic static and YARA checks, minimize the
context sent to optional model triage, and escalate only suspicious or
inconclusive artifacts. **Source-First Artifact Research** is the single
adapter-driven workflow for npm, PyPI, crates.io, Packagist, Go, Maven, NuGet,
RubyGems, Open VSX, GitHub, Hugging Face, containers, and approved local
artifacts. Package code, lifecycle scripts, extensions, and binaries are never
executed. Use `secopsai research investigate --ecosystem <name> --package
<identifier> --json`; the existing `research rust-package` command remains a
compatibility alias.

Every artifact result is context-calibrated: structured manifests determine
lifecycle hooks, language-aware rules inspect executable call sites, source and
documentation URLs stay separate from attacker IOC candidates, and repeated
observations are deduplicated with an audit count. Mission Control shows a
decision card with priority, detection confidence, assessment, potential
impact, local exposure, evidence quality, contradictions, and next action.
See [Artifact Signal Calibration](docs/artifact-signal-calibration.md).

For material investigations, the Research Case reliability workspace adds
competing hypotheses, versioned evidence plans, scaffold/transition/full safe
gates, tamper-evident run bundles, claim-level support checks, specialist and
blinded independent review, adjudication, completeness/originality/visual
audits, and resource accounting. Unsupported claims are removed or qualified
with an auditable revision diff before a review-only draft can be created. See
[Execution-Grounded Research Architecture](docs/execution-grounded-research-architecture.md)
and [Research Reliability Operations](docs/research-reliability.md).

Use **Run Safe Automation** to advance every deterministic gate that the current
evidence supports. The same guarded coordinator runs during the enabled daily
workflow, queues at most one selected-model read-only review, and resumes
idempotently when evidence or review state changes. It stops for unsupported
claims, reviewer disagreement, real visual evidence, publication approval,
sandbox submission, disclosure, publishing, deployment, destructive response,
and any external communication.

[![Artifact Fleet funnel from metadata indexing to analyst review](docs/assets/mission-control/artifact-fleet.png)](docs/assets/mission-control/artifact-fleet.png)

### Research Cases

Turn a package lead into a durable case with quarantined artifact evidence,
checksums, rule hits, comparison results, IOCs, readiness gates, and a
review-only publication handoff.

[![Research Case workspace with evidence readiness and guarded next actions](docs/assets/mission-control/research-case.png)](docs/assets/mission-control/research-case.png)

### Publications

Review claims, references, and media; approve editorial content; stage approved
posts; and deploy the complete archive as a separate protected action. Older
published posts are preserved during rebuilds.

[![Publication operations with review state, approved media, staging, and deployment](docs/assets/mission-control/publications.png)](docs/assets/mission-control/publications.png)

### Enterprise integrations

See the difference between an available adapter, a configured connector, and a
source producing fresh evidence. Cloud ingestion is read-only by default,
Kubernetes assessment is non-mutating, and active DAST requires recorded
authorization.

[![Enterprise workspace with connector readiness, vulnerability priorities, DAST, and governance](docs/assets/mission-control/enterprise.png)](docs/assets/mission-control/enterprise.png)

## How It Works

```mermaid
flowchart LR
    A[Agent and host telemetry] --> C[Normalize and correlate]
    B[Registries and advisories] --> D[Static, policy, and YARA checks]
    C --> E[Findings and evidence]
    D --> E
    E --> F[Bounded model review]
    F --> G[Analyst decision]
    G --> H[Guarded response]
    G --> I[Review-only publication]
```

**Safety invariant:** untrusted artifacts are never executed by this workflow;
models receive bounded evidence, and response, disclosure, and publication stay
behind explicit operator approval.

1. **Collect:** adapters ingest supported host, agent, Edge, cloud, CI, and registry signals.
2. **Normalize:** SecOpsAI maps evidence into shared event, finding, asset, and research records.
3. **Detect:** deterministic rules, advisories, artifact checks, correlations, and policy gates produce explainable evidence.
4. **Investigate:** Research Cases preserve provenance while optional models receive only bounded, minimized context.
5. **Decide:** an analyst verifies evidence, disposition, mitigation, disclosure, and publication readiness.
6. **Act:** only allowlisted, approval-appropriate responses are applied and recorded.

## Integrations and Platform Coverage

Coverage labels are intentionally strict: **Complete** is production-usable in
the documented local workflow, **Partial** requires scoped configuration or
does not cover the full platform surface, **Experimental** is pilot-stage, and
**Planned** describes target architecture that is not presented as available.

| Source or surface | Support level | Notes |
| --- | --- | --- |
| OpenClaw | Complete | Audit telemetry, plugin workflow, detections, and response guidance |
| Hermes Agent | Complete | Read-only log and tool-call collection with persistent monitoring |
| macOS | Complete | Unified log, process, file, persistence, and network evidence |
| Linux | Partial (beta) | Auth, process, file, persistence, and network adapters |
| Windows | Partial (beta) | Event, process, PowerShell, persistence, and network adapters |
| SecOpsAI Edge | Experimental (pilot) | Normalized asset graph and findings import; raw scan logs remain at the sensor |
| Package registries | Complete | Registry metadata and safe artifact inspection across the documented ecosystems |
| AWS, GCP, Kubernetes | Partial (read-only) | Normalized connectors and non-mutating posture checks; no infrastructure changes |
| PostgreSQL data plane | Partial (optional) | Pooled adapter is available; SQLite remains the authoritative local default |
| Managed hosted control plane | Planned | Target architecture only; not presented as an available hosted service |

## Safety Boundaries

- Package artifacts are inspected without installing them, importing modules, running lifecycle scripts, activating extensions, or executing binaries.
- Browser actions call fixed helper routes; the browser cannot provide arbitrary shell commands.
- Model analysis receives minimized evidence and cannot independently publish, disclose, submit to a sandbox, or enable unverified rules.
- Active DAST, cloud mutations, Kubernetes changes, ticket creation, disclosure, and publication remain approval-gated.
- Source references are kept separate from attacker-controlled IOCs.
- Credentials stay server-side or in the operator's local runtime and must never be committed to the repository.

Read the [Security Policy](SECURITY.md), [Threat Model](docs/threat-model.md),
[Security and Data Handling](docs/security-and-data-handling.md), and
[Operator Runbook](docs/operator-runbook.md) before enabling protected actions.

## Documentation and Community

| Start with | When you need |
| --- | --- |
| [Documentation home](https://docs.secopsai.dev) | The complete operator documentation |
| [Getting Started](docs/getting-started.md) | Installation and first-run checks |
| [Intelligence integrations](docs/intelligence-integrations.md) | Local model bridge, model routing, and the read-only ChatGPT app |
| [Specialist Orchestrator](docs/specialist-orchestrator.md) | Work routing, reviewed profiles, automation tiers, approvals, recovery, and profile updates |
| [Research discovery](docs/research-discovery.md) | Watchlists, candidate intake, orchestration, and promotion |
| [Triage orchestrator](docs/triage-orchestrator.md) | Evidence collection, action queues, and closure |
| [Rules registry](docs/rules-registry.md) | Detection rule lifecycle and validation |
| [API reference](docs/api-reference.md) | Protected Core and integration contracts |
| [Security and data handling](docs/security-and-data-handling.md) | Local-first storage, credentials, models, artifacts, and approval boundaries |
| [Repository layout](docs/repository-layout.md) | Canonical folders, compatibility entry points, and duplication rules |
| [Background monitoring](docs/deployment-guide.md) | Long-running services and scheduled operation |
| [GitHub Action](https://github.com/Techris93/secopsai-action) | Versioned repository security checks |
| [Marketplace](https://github.com/marketplace/actions/secopsai-supply-chain-guard) | Install SecOpsAI Supply Chain Guard |
| [Issue tracker](https://github.com/Techris93/secopsai/issues) | Bugs, feature requests, and operator feedback |
| [Security reporting](SECURITY.md) | Private vulnerability reporting and response expectations |
| [Contributing](CONTRIBUTING.md) | Development setup, checks, and review expectations |
| [MIT License](LICENSE) | Open-source terms |
