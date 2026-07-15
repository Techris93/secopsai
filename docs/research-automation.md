# SecOpsAI Research Automation

SecOpsAI Research turns a watchlist lead into a defensible investigation without executing the investigated package. The dashboard buttons call the same typed Core workflow as the CLI; command-copy helpers are only a fallback.

## Operator workflow

1. Create or open a Research Case from Supply Chain Triage.
2. Select the ecosystem, package, and optional version.
3. Use **Collect Metadata Preview** to confirm the official registry target.
4. Use **Run Safe Package Intake**. The artifact is fetched into local quarantine, hashed, and inspected in memory. No package manager or build command runs.
5. Review the job result and indicators. Use **Attach Verified Evidence** only after reviewing the preview.
6. Use **Generate Evidence Matrix** and record a human verdict with rationale and evidence IDs.
7. Use **Run Publication Safety Check** before drafting public content.
8. Use **Prepare Disclosure** to create a reviewable maintainer/registry message. Approval and sending are separate actions.
9. Use **Request Sandbox Approval** only when static evidence leaves an important runtime question. The default provider is manual-result-import; Core never executes packages locally.
10. Approve the publication review, create the Blog Ops draft, edit it, and complete the existing Blog Ops approval/publish workflow.

## Supported intake ecosystems

The common adapter contract supports npm, PyPI, NuGet, Maven Central, RubyGems, Packagist, Go modules, and Open VSX. CI uses fixtures, not live registry calls. Adapters enforce their own official metadata and artifact host allowlists.

## CLI fallback

```bash
secopsai research intake preview --ecosystem npm --package chalk-tempalte
secopsai research intake run --case RSC-XXXXXXXXXXXX --ecosystem npm --package chalk-tempalte
secopsai research jobs list --case RSC-XXXXXXXXXXXX
secopsai research intake attach JOB-XXXXXXXXXXXX
secopsai research workflow evidence-matrix RSC-XXXXXXXXXXXX
secopsai research workflow publication-check RSC-XXXXXXXXXXXX
```

Human-gated actions are explicit:

```bash
secopsai research workflow verdict RSC-XXXXXXXXXXXX --verdict likely --confidence 70 --rationale "Explain the evidence and limitations." --evidence-id EVD-XXXXXXXXXXXX
secopsai research workflow prepare-disclosure RSC-XXXXXXXXXXXX --recipient security@example.org
secopsai research workflow request-sandbox RSC-XXXXXXXXXXXX --artifact-sha256 <sha256> --justification "Explain the unanswered runtime question."
secopsai research workflow publication-approve RSC-XXXXXXXXXXXX --review-id PUB-XXXXXXXXXXXX
```

## Security boundary

Artifacts are bounded by size, redirect, archive-entry, expanded-content, and inspected-text limits. Absolute paths, traversal, links, devices, archive bombs, private-address resolutions, credential-bearing URLs, and unapproved redirects are rejected. Static indicators are evidence leads, not proof of maliciousness. Raw artifacts and raw registry responses are not sent to AI.

Dynamic analysis is not enabled by pretending the Core host is a sandbox. Configure a dedicated isolated provider or import a sanitized result manually. Disclosure sending and publication approval remain auditable human decisions.
