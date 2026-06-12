# AI Dependency Guard

AI Dependency Guard scans AI-built code and optional local agent telemetry for
hallucinated, newly registered, or lookalike dependencies before they become a
supply-chain incident.

It is designed for slopsquatting risk: an LLM suggests a plausible package name,
the package does not exist or was recently registered, and a developer or CI
workflow installs it without source-backed review.

## What it checks

- Repository manifests and lockfiles: npm, PyPI, Packagist, Go, crates, Maven,
  NuGet, RubyGems, Open VSX, and Hugging Face style identifiers.
- Source imports from Python and JavaScript/TypeScript files.
- Dockerfiles and GitHub Actions workflow install commands.
- Optional local AI-agent telemetry from OpenClaw, Hermes Agent, and SecOpsAI
  session/job records.
- Registry metadata only. SecOpsAI never installs packages, imports generated
  code, runs lifecycle scripts, activates extensions, or executes artifacts.

## Run it locally

```bash
secopsai supply-chain ai-dependency-guard --path . --json
```

Include local agent/session logs when you want to check packages suggested by
AI tools before they landed in manifests:

```bash
secopsai supply-chain ai-dependency-guard \
  --path . \
  --include-agent-logs \
  --agent-source auto \
  --json
```

Limit to one ecosystem:

```bash
secopsai supply-chain ai-dependency-guard --path . --ecosystem npm --json
```

Write a report and persist high-confidence findings:

```bash
secopsai supply-chain ai-dependency-guard \
  --path . \
  --include-agent-logs \
  --persist-findings \
  --report-path reports/ai-dependency-guard.json \
  --json
```

## CI behavior

The guard warns by default. To block pull requests, opt into a threshold:

```bash
secopsai supply-chain ai-dependency-guard --path . --fail-on high --json
```

GitHub Action example:

```yaml
- uses: Techris93/secopsai-action@v1
  with:
    mode: ai-dependency-guard
    scan-path: .
    fail-on-severity: high
```

## Classifications

| Classification | Meaning |
| --- | --- |
| `verified_existing` | Registry metadata confirms the package exists. |
| `missing_or_hallucinated` | A referenced package was not found in registry metadata. |
| `newly_registered` | Registry metadata shows a recently created package. |
| `name_similarity_risk` | Package name resembles a common trusted package. |
| `advisory_matched` | Existing SecOpsAI advisory data matches the package. |
| `local_only_or_private` | Local policy allowlist marks the package as internal/private. |
| `needs_review` | Metadata lookup failed or evidence is inconclusive. |

## Reducing false positives

Use the existing supply-chain policy allowlist for private packages:

```bash
secopsai supply-chain allowlist add --ecosystem npm --package internal-ai-widget
```

Then rerun the guard. Allowlisted packages are reported as
`local_only_or_private` and do not create high-risk findings.

## Operator workflow

1. Run the guard before accepting AI-generated dependency changes.
2. Review packages classified as missing, newly registered, or similarity risk.
3. Check official project documentation before installing anything.
4. Persist findings only when the evidence is useful for triage ownership.
5. If a package came from AI output, ask the assistant for source-backed package
   names and compare against registry metadata before merging.
