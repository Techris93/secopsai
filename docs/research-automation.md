# SecOpsAI Research Automation

SecOpsAI Research turns a watchlist lead into a defensible investigation without executing the investigated package. The dashboard buttons call the same typed Core workflow as the CLI; command-copy helpers are only a fallback.

## Primary Mission Control workflow

The normal workflow no longer requires an evidence-bundle export, a file upload, or a copied prompt.

1. Open **Research**, select a case, and confirm that it has an active package or extension subject.
2. When you know the verified legitimate package, enter it under **Legitimate comparison package**. Leave it empty when ownership is not yet verified; SecOpsAI will not guess.
3. Click **Run Investigation Pipeline**.
4. Core collects official-registry metadata and the package artifact using bounded static-intake controls. It records hashes, inspects the archive without execution, and performs a deterministic comparison when a trusted reference was supplied.
5. Core queues three durable Intelligence jobs. The installed Local Codex Bridge reads only minimized case and static-analysis context and writes structured proposals back to the same pipeline record.
6. Mission Control refreshes the running pipeline automatically.
7. Review every proposed fact, inference, unsupported claim, contradiction, missing-evidence group, recommended-action group, disclosure draft, and publication-risk group. Related model list items are deduplicated and grouped into one editable review card so the queue remains usable. Click **Accept** or **Reject**.
8. Accepted static evidence is attached with its pipeline and review provenance. Accepted model text becomes an immutable analyst-reviewed case note. Rejected proposals remain auditable and do not change canonical evidence.
9. Record the human verdict, approve any sandbox request, send disclosure, and approve publication through their existing separate gates.

If the bridge or collection step fails, click **Retry from checkpoint**. A new pipeline revision is created, stale proposals are superseded, and the previous revision remains auditable. If comparison was incomplete, enter a verified reference and click **Add reference and rerun analysis**.

The pipeline cannot classify a package as malicious, execute it, submit it to a sandbox, send external communication, approve publication, or publish an article.

## Granular recovery controls

Use the individual actions only when diagnosing a step or deliberately running a narrower workflow:

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
