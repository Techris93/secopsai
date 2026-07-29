# Research Cases

SecOpsAI Research Cases turn discovery leads, package analysis, SOC findings,
and public-source evidence into a durable investigation record. Cases are
local-first and stored in the Core SQLite SOC database.

## Ownership Boundary

- Supply-chain discovery and scanners produce leads and technical evidence.
- Research Cases own analyst workflow, provenance, disclosure, and publication
  readiness.
- Core findings can be linked to a case without changing their triage state.
- Blog Ops receives review-only drafts. It never publishes directly from a
  research case.

## Case Lifecycle

Statuses are:

`draft` → `investigating` → `validation` → `disclosure_pending` →
`ready_to_publish` → `published` or `closed`.

Disclosure is tracked separately as `not_started`, `not_required`,
`preparing`, `reported`, `coordinating`, `disclosed`, or `closed`.

Every mutation appends an immutable case event. Subjects, evidence, IOCs, and
finding links remain structured instead of being hidden in a prose report.

Incorrect structured records are retracted, not deleted:

```bash
secopsai research case retract RSC-... \
  --item-type evidence \
  --item-id EVD-... \
  --reason "Registry record belonged to a different namespace"
```

Retractions require a reason, remain visible in the case history, and are
excluded from readiness, exports, and publication. An active IOC linked to
retracted evidence blocks publication until its provenance is corrected.

## Detection Rules

Research cases can carry defensive YARA, Sigma, and Semgrep artifacts. Rules
are stored as text with their purpose, source evidence, structural validation
result, and case timeline event. SecOpsAI never executes a submitted rule.
Sigma and Semgrep documents are parsed with safe YAML loading; YARA receives a
bounded structural preflight (declaration, braces, and condition) rather than
claiming compiler-level validation.

The recommended path is the guarded proposal workflow:

```bash
secopsai research rule propose RSC-...
secopsai research rule list RSC-...
secopsai research rule review RSC-... RRP-... --decision accepted
```

Proposal generation is deterministic and evidence-bound. It can create:

- exact-artifact YARA rules from reviewed suspect package hashes;
- Sigma network rules from high-confidence domain or IP IOCs;
- Semgrep source indicators from high-confidence domains or URLs.

Legitimate comparison artifacts, low-confidence indicators, unlinked model
claims, and raw package content are excluded. Generation never activates a
rule. A proposal must pass structural and policy validation and then receive an
explicit accept decision. Rejected and failed proposals remain in the audit
history. The model may explain limitations, but it is not evidence and does not
control activation.

Attach a rule from inline content or a local UTF-8 file:

```bash
secopsai research case add-rule RSC-... \
  --rule-type sigma \
  --name suspicious-package-execution \
  --file ./rules/suspicious-package.yml \
  --purpose "Detect process execution associated with package installation." \
  --source-evidence-id EVD-...
```

Each active rule must pass structural validation before a case can become
publication-ready. Failed rules remain visible for analyst review and can be
replaced idempotently by repeating the same case, type, and name. Retract a
replaced rule without deleting its history:

```bash
secopsai research case retract RSC-... \
  --item-type rule \
  --item-id RUL-... \
  --reason "Replaced with the reviewed production rule"
```

Case JSON and Markdown exports include active rule content and validation
status, making published detections reproducible alongside the research
evidence. Rules are optional for publication; when present, every active rule
must pass the structural gate.

## Create And Build A Case

For a fast, safe package-research start, use the guided command. It records a
package subject and optional analyst-supplied source URL. It does not fetch a
registry or execute anything. With `--artifact`, it reads the local regular
file only to calculate a SHA-256 hash; it does not unpack or retain the file.

```bash
secopsai research case start-package \
  --ecosystem nuget \
  --package Braintree.Payments.SDK \
  --version 4.2.1 \
  --source-url https://example.com/package \
  --artifact ./fixtures/package.nupkg \
  --owner "SecOpsAI Research"
```

The resulting case starts in `draft` with explicit validation language. Add
evidence, IOCs, findings, and disclosure updates as the investigation earns
them. To attach a local artifact to an existing case:

```bash
secopsai research case add-artifact RSC-... \
  --artifact ./fixtures/package.nupkg \
  --notes "Hash-only collection from the isolated evidence directory"
```

### Promote A Watchlist Lead

The first automated watchlist workflow is intentionally narrow: it supports
explicitly selected npm package leads from the local campaign watchlist. The
default is a read-only preview. It does not query a registry, download an
artifact, unpack a package, or execute package code.

Preview one lead:

```bash
secopsai research case from-watchlist \
  --ecosystem npm \
  --package npm:chalk-tempalte \
  --watchlist-path data/supply_chain/campaign_discovery/watchlist.json
```

Create the case only after reviewing the preview:

```bash
secopsai research case from-watchlist \
  --ecosystem npm \
  --package npm:chalk-tempalte \
  --owner "SecOpsAI Research" \
  --create
```

Promotion is idempotent for an active npm package subject, records local
watchlist provenance, and leaves the case in `draft` with validation open.
Use `--all --create` only after reviewing the complete npm watchlist. Other
ecosystems are rejected by this first workflow rather than being silently
treated as npm packages. Add public source URLs later with the evidence
workflow; the promotion command never fetches them.

```bash
secopsai research case create \
  --title "NuGet payment SDK typosquat investigation" \
  --type typosquatting \
  --severity critical \
  --confidence 80 \
  --owner "SecOpsAI Research" \
  --summary "A suspicious package copied legitimate branding and introduced attacker-controlled checkout telemetry."

secopsai research case add-subject RSC-... \
  --subject-type package \
  --ecosystem nuget \
  --name Braintree.Payments.SDK \
  --version 4.2.1

secopsai research case add-evidence RSC-... \
  --evidence-type source \
  --title "Public registry package record" \
  --locator https://example.com/package \
  --provenance "public package registry"

secopsai research case add-ioc RSC-... \
  --ioc-type domain \
  --value checkout-telemetry.example \
  --confidence 90

secopsai research case link-finding RSC-... SCM-... --relationship derived_from
```

Use `secopsai research case list` and `secopsai research case show RSC-...`
to inspect the queue and full timeline.

## Publication Readiness

A case cannot create a blog draft until all deterministic gates pass:

- clear title and substantial executive summary
- at least one structured subject
- at least two evidence records
- at least one public source or registry record with a locator
- confidence of 60 or greater
- disclosure completed or explicitly marked not required
- case status set to `ready_to_publish`
- every attached active detection rule passes structural validation

Missing IOCs or linked findings are warnings, not automatic blockers, because a
valid investigation may produce no attacker infrastructure or local exposure.

```bash
secopsai research case update RSC-... \
  --status ready_to_publish \
  --disclosure-status disclosed \
  --confidence 90

secopsai research case export RSC-...
secopsai research case draft-blog RSC-...
```

Exports are deterministic JSON and Markdown under `reports/research/cases/`.
Each export also includes a `.manifest.json` with byte counts and SHA-256
checksums for the JSON and Markdown files. The export schema is
`secopsai.research.case.v1`; the manifest schema is
`secopsai.research.export-manifest.v1`. Re-exporting an unchanged case produces
the same report bytes, which makes review, archival, and publication checks
reproducible. Draft handoff produces an **Original Research** Blog Ops item
with `review_status=needs_review`; editorial approval and deployment remain
separate actions.

## Dashboard

Open **Research** in the canonical SecOpsAI dashboard to:

- review the case queue and publication blockers
- manage status, severity, confidence, owner, and disclosure
- add subjects, evidence, IOCs, notes, and finding links
- generate evidence-linked rule proposals, review their validation limits, and
  activate or reject them
- review active case-linked detection rules and their validation status
- download a Markdown case report
- create a review-only blog draft when readiness passes

Reads do not require a write token. Protected actions use the same
`TRIAGE_OPS_ADMIN_TOKEN` boundary as Triage Ops. The token stays in browser
session storage and is forwarded only to the authenticated helper.

## Safety And Ethics

- Collect public metadata and artifacts or data you are authorized to inspect.
- Prefer static analysis in isolated directories.
- Run dynamic analysis only in disposable, network-controlled sandboxes.
- Never execute untrusted packages on the operator workstation.
- Record provenance, hashes, timestamps, and limitations.
- Coordinate with affected vendors, registries, and maintainers before public
  disclosure when publication could increase harm.
- Do not include live credentials, private victim data, or unnecessary personal
  information in evidence or reports.

Structured cryptographic hash IOCs are preserved in public drafts. Unstructured
secret-like values remain redacted.
