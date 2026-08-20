# Rust Package Research Automation

SecOpsAI can now run a source-first Rust package investigation from crates.io
metadata through a quarantined static scan, comparison, Research Case, selected
model review, and review-only Blog Ops draft.

## CLI

Preview official metadata without downloading the crate:

```bash
secopsai research rust-package \
  --package proc-macro1 \
  --version 1.0.107 \
  --compare-package proc-macro2 \
  --compare-version 1.0.107 \
  --dry-run --json
```

Run the safe workflow:

```bash
secopsai research rust-package \
  --package proc-macro1 \
  --version 1.0.107 \
  --compare-package proc-macro2 \
  --compare-version 1.0.107 \
  --source-reference https://example.org/research/report \
  --persist-findings --json
```

The command uses the crates.io metadata API and the official
`static.crates.io` artifact host. It verifies the exact package/version,
metadata checksum, downloaded SHA-256, source repository, and archive format.
The artifact is stored under the owner-only research quarantine. No Cargo
command, build script, import, binary, or payload runs.

## Dashboard

Open **Enterprise Security → Artifact Fleet → Run Rust Package Research**.
Enter the Automation action token under **Native Triage → Intelligence** and
provide the crate name, exact version, and optional verified comparison crate.

- **Preview metadata** performs a metadata-only check.
- **Run safe research** downloads into quarantine, scans, compares, and routes evidence.
- **Persist high-confidence finding** creates a SOC finding only for strong deterministic behavior.
- **Create review-only draft** never bypasses publication readiness or editorial approval.

The browser sends typed JSON only. The local helper builds an allowlisted CLI
argument array. Hosted mode returns clear `not_configured` guidance when no
Core/helper endpoint is configured.

## Evidence and routing

The workflow records:

- crates.io metadata, source repository, version, timestamps, and checksum;
- quarantined artifact SHA-256 and bounded archive metadata;
- Artifact Fleet rule IDs, severity, confidence, safe contexts, and mitigations;
- verified comparison metadata and static differences;
- validated external URLs, domains, IPs, and SHA-256 values;
- Research Case, evidence, IOC, finding, model-job, and draft identifiers.

Generic build hooks and ordinary Rust process/environment code remain review
signals. A Research Case, finding, or model job is created automatically only
when strong behavior rules corroborate the package risk. Comparison artifacts
are never sent to model triage solely because they contain normal build code.

Source domains and documentation URLs are references, not attacker IOCs. IOC
values are retained only when they pass URL, public-IP, domain, or SHA-256
validation.

## Model and human gates

Model triage receives minimized rule-hit context, never raw artifacts. The
persisted operator-selected model is used; other providers are not probed or
consumed unless explicit fallback configuration exists. Suspicious and
inconclusive results remain in analyst review.

The following actions remain human-controlled:

- public sandbox submission;
- vendor or registry disclosure;
- final verdict when evidence is incomplete;
- Blog Ops approval;
- publication and Cloudflare deployment.

Static evidence must be described as static evidence. Claims about runtime
execution, credential theft, persistence, or VirusTotal detection rates require
independent, timestamped evidence from an approved isolated source.

## Research-to-publication flow

1. Review the Artifact Fleet output and open the generated Research Case.
2. Run the evidence matrix and resolve publication blockers.
3. Add or review IOCs and detection-rule proposals.
4. Set disclosure to `not_required`, `disclosed`, or `closed` only when justified.
5. Set the case to `ready_to_publish` after human review.
6. Create the review-only Blog Ops draft.
7. Edit and approve the draft in Blog Ops.
8. Run **Publish approved** to stage the post.
9. Deploy through hosted Blog Ops or the Cloudflare/GitHub workflow.

Publishing never copies third-party article text. Reports should distinguish
SecOpsAI evidence, sandbox observations, and external corroboration.
