# SecOpsAI Research Automation

SecOpsAI Research turns a watchlist lead into a defensible investigation without executing the investigated package. The dashboard buttons call the same typed Core workflow as the CLI; command-copy helpers are only a fallback.

For Rust/crates.io investigations, use **Enterprise Security → Artifact Fleet → Run Rust Package Research** or:

```bash
secopsai research rust-package --package proc-macro1 --version 1.0.107 --compare-package proc-macro2 --compare-version 1.0.107 --json
```

This source-first workflow verifies crates.io metadata and checksum, stores the
exact crate in quarantine, runs Artifact Fleet static rules, records evidence
and validated IOCs, optionally reuses a Research Case, queues the selected
model with minimized context, and can prepare a review-only draft. Cargo,
`build.rs`, binaries, sandbox submission, disclosure, publication, and deploy
remain separate approval-gated actions.

## Automatic high-priority investigations

Eligible high and critical package findings are promoted automatically after initial model triage. Core creates or reuses the finding-linked Research Case, collects the exact registry artifact, verifies and catalogs the quarantine object, performs bounded static analysis, compares only a verified reference, extracts IOC candidates, correlates normalized evidence, and requests a complete model assessment.

Use **Administration → Automation → High-priority investigations** to inspect progress, retry a failed checkpoint, cancel active work, or open the linked case. A missing comparison reference, registry outage, analyzer limitation, or pending sandbox approval is displayed as an evidence gap rather than a verdict.

Investigation status responses include `recovery_available` and `recovery_reason`. A failed, evidence-gap, or canceled run is retriable while its attempt limit has not been reached, even if an older worker wrote a stale `retryable` flag. The console prioritizes these rows and exposes a visible **Retry** action. Runs at the attempt limit remain blocked and explain why they cannot be retried.

The unattended workflow cannot approve a sandbox submission, send external disclosure, or approve and publish an article. Those remain the final operator gates.

## Primary Mission Control workflow

The normal workflow no longer requires an evidence-bundle export, a file upload, or a copied prompt.

1. Open **Research**, select a case, and confirm that it has an active package or extension subject.
2. When you know the verified legitimate package, enter it under **Legitimate comparison package**. Leave it empty when ownership is not yet verified; SecOpsAI will not guess.
3. Click **Run Investigation Pipeline**.
4. Core collects official-registry metadata and the package artifact using bounded static-intake controls. It records hashes, inspects the archive without execution, and performs a deterministic comparison when a trusted reference was supplied.
5. Core queues three durable Intelligence jobs. The installed Local Codex Bridge reads only minimized case and static-analysis context and writes structured proposals back to the same pipeline record.
6. Mission Control refreshes the running pipeline automatically.
7. In **agent review** mode, SecOpsAI accepts the bounded evidence proposals, records an evidence-linked agent verdict, and reruns publication safety automatically. The verdict is constrained by deterministic guardrails: local absence cannot prove benignness, `credible` requires advisory-backed or sandbox evidence, and low-confidence work remains `inconclusive`.
8. In **supervised** mode, review each proposal manually with **Accept** or **Reject**, then record the verdict yourself.
9. Review the resulting case. External sandbox submission, external disclosure delivery, and final publication approval remain separate human gates.

If the bridge or collection step fails, click **Retry from checkpoint**. A new pipeline revision is created, stale proposals are superseded, and the previous revision remains auditable. If comparison was incomplete, enter a verified reference and click **Add reference and rerun analysis**.

If an exact package version is later removed from its registry, the pipeline may reuse a previously collected local quarantine artifact only when its ecosystem, package, version, byte size, and SHA-256 all match. The reuse reason and failed registry retrieval are recorded in the step result. SecOpsAI never substitutes another version or trusts an unverified local file.

The pipeline never executes package code, submits an artifact to an external sandbox, sends external communication, approves publication, or publishes an article. In agent-review mode it may record a bounded case verdict, but only against accepted, pipeline-specific evidence and with all guardrail decisions retained in the audit trail.

## Agent-review mode

Agent-review mode is the recommended high-automation setting for a local research workstation. It delegates the repeatable evidence review, verdict recommendation, analyst brief, and publication preflight to the selected Local Codex/OpenCodex model. Models remain fallible; SecOpsAI therefore validates their schema, evidence links, confidence, contradictions, and local-exposure reasoning before writing a verdict.

Install or update the background bridge in agent-review mode:

```bash
secopsai intelligence bridge service install \
  --autonomy-mode agent_review \
  --model google-antigravity/gemini-3.6-flash
```

Complete an already-waiting pipeline from the CLI:

```bash
secopsai research pipeline agent-complete RPL-XXXXXXXXXXXXXXXX
```

Mission Control exposes the same operation as **Complete Agent Review**. The action:

- accepts bounded static evidence and model proposals;
- records a verdict with confidence, rationale, evidence identifiers, model provider, and pipeline revision;
- blocks benign or not-substantiated conclusions based only on missing local exposure;
- downgrades unsupported or contradictory claims;
- reruns publication safety;
- does not upload an artifact, contact a third party, or publish content.

The model identifier is stored in the user service definition, not only in the browser session. Provider credentials remain owned by OpenCodex or Codex and are never copied into the service file.

When every deterministic closure gate passes, the research resolution policy can close the case as `not_substantiated` or `benign`, retract active case rules that would otherwise create unsupported alerts, and place the complete reversible decision in **Research → Resolved by agents**. A `not_substantiated` decision means the available evidence did not prove the allegation; it is not a benign classification. `benign` additionally requires independently reviewed sandbox evidence. Likely or credible threats remain open and escalated.

Configure this policy in Mission Control or use:

```bash
secopsai research resolution configure --mode guarded --min-confidence 90 --min-evidence-refs 4
secopsai research resolution status
secopsai research resolution review ARR-XXXXXXXXXXXXXXXX --decision reopen
```

Accepting a resolution records the operator review. Reopening restores the previous case fields and any validation-passed rules that the resolution retracted. Neither action publishes or contacts an external party.

Use supervised mode when policy requires proposal-by-proposal human acceptance:

```bash
secopsai intelligence bridge service install --autonomy-mode supervised
```

## Granular recovery controls

Use the individual actions only when diagnosing a step or deliberately running a narrower workflow:

1. Create or open a Research Case from Supply Chain Triage.
2. Select the ecosystem, package, and optional version.
3. Use **Collect Metadata Preview** to confirm the official registry target.
4. Use **Run Safe Package Intake**. The artifact is fetched into local quarantine, hashed, and inspected in memory. No package manager or build command runs.
5. Review the job result and indicators. Use **Attach Verified Evidence** only after reviewing the preview.
6. Use **Generate Evidence Matrix** and either click **Complete Agent Review** or record a human verdict with rationale and evidence IDs.
7. Use **Run Publication Safety Check** before drafting public content.
8. Use **Prepare Disclosure** to create a reviewable maintainer/registry message. Approval and sending are separate actions.
9. Use **Request Sandbox Approval** only when static evidence leaves an important runtime question. The default provider is manual-result-import; Core never executes packages locally.
10. When the server-side `TRIAGE_API_TOKEN` is configured, approve the public submission and select **Submit to Tria.ge**. The local helper verifies the approved SHA-256 before upload. Public Tria.ge submissions are visible publicly and cannot be deleted by public-cloud users. Select **Refresh Tria.ge result** after the analysis completes; SecOpsAI stores only the sanitized report metadata.
11. If API access is not configured, use the manual fallback: approve the public handoff, select **Download exact sample**, upload that hash-verified file through the Tria.ge web interface, and then record only the public report URL, score, and reviewed behavior summary through **Record manual Tria.ge result**.
12. Approve the publication review, create the Blog Ops draft, edit it, and complete the existing Blog Ops approval/publish workflow.

## Manual Tria.ge handoff fallback

Use this path only for an artifact already collected and attached to the case when API submission is unavailable or intentionally not authorized.

1. Confirm the artifact row shows the exact package/version and SHA-256 you intend to analyze.
2. Create a sandbox request with the unanswered runtime question in the justification.
3. Approve the public handoff. This acknowledges that public Tria.ge submissions are visible publicly and cannot be deleted by public-cloud users.
4. Select **Download exact sample**. Core re-hashes the owner-only quarantine file and serves it through a one-time, no-store response. A mismatch blocks the download.
5. In Tria.ge, submit the downloaded file interactively. Review the static report before selecting an execution profile. For package archives, select only the relevant executable or script extracted by Tria.ge.
6. Use a network-disabled profile when network access is not required to answer the research question. Enable controlled network access only when the expected behavior requires it.
7. Wait for the report to complete. Review process, filesystem, persistence, network, and memory evidence. A sandbox score alone is not a verdict.
8. In Mission Control, open **Record manual Tria.ge result**, enter the public report URL and score, and write a concise behavior summary that separates observed behavior from inference.
9. Select **Attach sanitized result**. Then regenerate the evidence matrix and rerun model analysis before changing the verdict.

Never submit customer files, credentials, tokens, private source code, internal documents, or any artifact whose authorization and public-disclosure status is unclear.

See the official [Tria.ge sample submission guide](https://tria.ge/docs/cloud-api/submit/), [analysis process](https://tria.ge/docs/data-model/), and [public-cloud FAQ](https://tria.ge/docs/faq/) before submitting a sample.

## Supported intake ecosystems

The common adapter contract supports npm, PyPI, crates.io, NuGet, Maven Central, RubyGems, Packagist, Go modules, and Open VSX. CI uses fixtures, not live registry calls. Adapters enforce their own official metadata and artifact host allowlists.

## CLI fallback

```bash
secopsai research intake preview --ecosystem npm --package chalk-tempalte
secopsai research intake run --case RSC-XXXXXXXXXXXX --ecosystem npm --package chalk-tempalte
secopsai research jobs list --case RSC-XXXXXXXXXXXX
secopsai research intake attach JOB-XXXXXXXXXXXX
secopsai research workflow evidence-matrix RSC-XXXXXXXXXXXX
secopsai research workflow publication-check RSC-XXXXXXXXXXXX
```

Human-gated external actions are explicit:

```bash
secopsai research workflow verdict RSC-XXXXXXXXXXXX --verdict likely --confidence 70 --rationale "Explain the evidence and limitations." --evidence-id EVD-XXXXXXXXXXXX
secopsai research workflow prepare-disclosure RSC-XXXXXXXXXXXX --recipient security@example.org
secopsai research workflow request-sandbox RSC-XXXXXXXXXXXX --artifact-sha256 <sha256> --justification "Explain the unanswered runtime question."
secopsai research workflow publication-approve RSC-XXXXXXXXXXXX --review-id PUB-XXXXXXXXXXXX
```

## Security boundary

Artifacts are bounded by size, redirect, archive-entry, expanded-content, and inspected-text limits. Absolute paths, traversal, links, devices, archive bombs, private-address resolutions, credential-bearing URLs, and unapproved redirects are rejected. Static indicators are evidence leads, not proof of maliciousness. Raw artifacts and raw registry responses are not sent to AI.

Dynamic analysis is not enabled by pretending the Core host is a sandbox. Configure a dedicated isolated provider or import a sanitized result manually. External sandbox submission, disclosure sending, and publication approval remain auditable human decisions. A model may prepare the justification or draft, but it cannot perform the external action.
