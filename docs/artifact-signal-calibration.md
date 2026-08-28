# Artifact Signal Calibration

## Why This Exists

Artifact inspection is a prioritization aid, not a maliciousness verdict. Older
analysis treated words and strings as if they were executable behavior. A benign
package could therefore be promoted to a critical-looking lead when a README,
generated bundle, or ordinary identifier contained words such as `cron`,
`socket`, or `function`.

The calibrated pipeline now uses four separate decisions:

- **Priority**: how quickly an analyst should look at the item.
- **Detection confidence**: confidence that a specific behavior was observed.
- **Assessment**: the current maliciousness assessment (`unconfirmed`, a
  human verdict, or `unconfirmed_static_lead`).
- **Potential impact**: the plausible consequence if the behavior is confirmed;
  it is not proof that the behavior occurred locally.

Local exposure is reported independently. `not_observed` means the dependency
was not found in the searched workspace; it does not mean the artifact is safe.

## Analysis Contract

Every static observation contains:

- `rule_id`, category, severity, and bounded confidence;
- archive path, file type, context classification, and source line;
- analysis method (`json_manifest_parser`, `javascript_token_context`, `python_ast`, or
  a deliberately non-scoring `textual_heuristic` fallback);
- reachability status, a safe snippet, and a recommended verification step;
- a stable fingerprint and `occurrence_count`.

The analyzer classifies paths before applying rules. README and other
documentation, tests, examples, generated bundles, source maps, manifests,
lockfiles, and static theme data are not treated like production source. A
package lifecycle finding is emitted only when the relevant manifest declares
the hook. `package.json` and `composer.json` are parsed structurally; README
prose never creates a lifecycle finding.

JavaScript and Python rules require language-aware call sites. They recognize
direct calls to dynamic evaluation, process execution, network APIs, and
credential reads rather than matching a case-insensitive word. Unsupported
languages use a low-confidence, non-scoring fallback that asks for manual
verification.

## URL and IOC Provenance

URLs are not IOCs by default. Registry, repository, vendor-report, badge, and
documentation hosts are `source_reference` values. URLs in prose are
`documentation_url`; shared services such as Discord or Microsoft are
`shared_legitimate_service` until artifact behavior links them to an attacker.
An `ioc_candidate` requires an executable-source network call or equivalent
corroboration. Rejected candidates remain in the case for auditability and
include a deterministic reason.

## Evidence Deduplication

Evidence fingerprints combine the case, evidence type, locator, checksum,
analysis tool/version, and artifact checksum. Reobserving the same evidence
updates `occurrence_count` and emits an `evidence_reobserved` event instead of
creating another row. Observation fingerprints deduplicate repeated rule hits
while retaining the repeat count. This keeps metrics and model context honest
without deleting history.

## Subject State Reconciliation

The artifact catalog is authoritative for attached artifact state. A normal
case read reports the current catalog state without changing the case. An
explicit reconciliation updates a stale subject from `missing` to `collected`
(or another catalog state) and records `subject_state_reconciled`. Use the
guarded command when repairing older cases:

```bash
secopsai research case reconcile RSC-603DF0DC28E5 \
  --actor artifact-signal-calibrator --json
```

This also reclassifies legacy URL candidates. It never deletes a candidate or
changes an analyst-owned accepted/rejected decision. The dashboard exposes the
same operation as **Reconcile legacy indicators** when a case still contains
unclassified candidates.

## Decision Card

Mission Control leads with a compact decision card containing assessment,
detection confidence, priority, potential impact, local exposure, evidence
quality, unique/repeated observations, confirmed facts, contradictions, and
the next action. Full model output remains available under **Open full
analysis**. Intelligence jobs are grouped by research case so the three stages
(analysis, analyst brief, and publication safety) appear as one pipeline row;
the individual jobs remain available for audit and recovery.

## Safe Operator Workflow

1. Refresh the case and confirm the artifact catalog state.
2. Read the decision card before opening the full analysis.
3. Check unique observations, paths, analysis method, and reachability.
4. Treat documentation/source URLs as references, not attacker IOCs.
5. Run advisory and local-usage checks independently.
6. Add a verified artifact or corroborating source only when authorized.
7. Record a human verdict with evidence IDs; do not promote a heuristic score
   directly to `credible` or `critical`.
8. Run publication safety before creating a review-only draft.

## Reference Case Outcome

The historical `RSC-603DF0DC28E5` case for
`npm:@ajaymamtora/theme-manager@4.0.0` was safely reprocessed. Its attached
artifact is `collected`, while the calibrated assessment remains
`unconfirmed`, detection confidence is `0`, potential impact is `medium`, and
evidence quality is `weak_heuristic`. Repository, badge, registry, JetBrains,
and homepage URLs are retained as rejected `source_reference` candidates;
they are not attacker IOCs. No package code was executed.

This result is intentionally conservative. A future analyst can escalate only
when a structural manifest hook, reachable language-aware behavior, verified
artifact comparison, advisory, or other independent evidence supports it.
