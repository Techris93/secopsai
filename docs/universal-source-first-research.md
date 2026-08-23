# Universal Source-First Security Research

SecOpsAI now uses one adapter-driven research pipeline for package, artifact,
repository, extension, advisory, and campaign investigations. The crates.io
workflow remains supported as a compatibility path, but it is no longer a
separate product surface.

## Start an investigation

Use the canonical command for an exact package or artifact:

```bash
secopsai research investigate \
  --ecosystem npm \
  --research-type package_compromise \
  --package suspicious-package \
  --version 1.2.3 \
  --source-reference https://vendor.example/advisory \
  --json
```

The same command accepts `pypi`, `crates`, `packagist`, `go`, `maven`,
`nuget`, `rubygems`, `open-vsx`, `huggingface`, `github`, `container`, and
`chrome-web-store`. Use `--artifact` for an approved local archive when the
source is metadata-only or a registry cannot safely provide a download.

`research rust-package` remains a compatibility alias for existing operators.
`research package` is also a universal compatibility entry point; use
`--legacy-report` only when an older source-backed report file is required.
New dashboard actions use `research investigate` so all ecosystems share the
same validation, evidence, model-routing, and publication gates.

Focused aliases use the same implementation: `research advisory` for
vulnerability records, `research extension` for Open VSX/Chrome extension
artifacts, `research github-incident` for repository/token incidents, and
`research source` for a general source-backed lead. They do not create a
second scanner or a separate evidence model.

For a bounded local exposure check, add `--search-root` or `--lockfile`. The
result reports matching manifest/lockfile lines without importing or installing
the dependency. A local path is accepted only by the CLI; browser routes use
typed server-side inputs and never execute a path supplied by the page.

## Shared safety boundary

Adapters use official allowlisted HTTPS metadata and artifact hosts. Archives
are hash-identified and inspected in quarantine with path, size, entry-count,
redirect, and expanded-content limits. SecOpsAI never installs a dependency,
runs a lifecycle/build/import hook, activates an extension, starts a binary,
or submits a sample to a sandbox automatically. Model jobs receive minimized
rule-hit context, never raw artifact content.

Sources are recorded separately from attacker IOCs. Registry URLs, vendor
reports, GitHub repository links, and documentation domains are references;
only validated infrastructure, hashes, and behavior-derived indicators become
IOC candidates.

## Evidence and publication

An investigation can create or update a Research Case, attach registry and
artifact evidence, build an evidence matrix, queue the explicitly selected
OpenCodex model, and create a review-only Blog Ops draft. Model output is a
bounded review proposal, not proof. Dynamic sandbox submission, disclosure,
publication, and deployment remain approval-gated and separate.

Each result reports the normalized research type, ecosystem, package/artifact,
version or revision, source references, static findings, validated IOCs,
local usage status, missing evidence, route, allowed/blocked actions,
confidence, and the explicit `execution_performed: false` safety state.

## Dashboard workflow

Open **Administration → Automation → Research pipeline** and use **Source-First
Artifact Research**. Select the research type and ecosystem, enter the package
or artifact and version, optionally add a comparison subject and source, then:

1. Preview metadata.
2. Run safe research.
3. Build the evidence matrix.
4. Queue the selected model.
5. Open the Research Case and review limitations.
6. Create a review-only draft when publication blockers are cleared.

The Artifact Fleet controls in the same workspace operate the staged metadata →
static scan → minimized triage → analyst queue funnel. There are no parallel
Rust/npm/PyPI panels.

## Capability notes

Registry adapters are active for npm, PyPI, crates.io, Packagist, Go, Maven,
NuGet, RubyGems, Open VSX, GitHub repository metadata, and Hugging Face
metadata. GitHub and Hugging Face return an explicit metadata-only result unless
the operator supplies a reviewed archive. Containers and Chrome extensions can
be analyzed from an approved local artifact. Unsupported or unconfigured
sources return a visible `metadata_only`/`not_configured` result instead of
silently falling back to another ecosystem.

## Research writing

Use the case evidence and matrix to write reports that distinguish:

- SecOpsAI deterministic static observations.
- Registry and repository provenance.
- External-source corroboration.
- Imported sandbox observations, if an analyst approved them.
- Analyst inference and unknowns.

Do not state that a payload executed, credentials were stolen, or a campaign is
attributed unless that fact is supported by the corresponding evidence type.
