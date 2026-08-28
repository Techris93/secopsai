# Research Quality Validation - August 2026

This record closes the ten production audit findings identified in the
Research Cases and artifact-analysis workflow. The changes are deterministic,
read-only by default, and do not execute package code or downloaded artifacts.

## Findings and fixes

1. **Research Cases render failure.** The dashboard detail renderer now defines
   its own artifact list and normalizes both the legacy readiness label and the
   structured readiness object. This removes the `artifacts is not defined`
   runtime failure and prevents an object from being rendered as
   `[object Object]`.
2. **JavaScript declaration false positive.** JavaScript is tokenized with
   comment, string, regular-expression, call-site, import, and member context.
   A named `function Function(value) {}` declaration and method declarations
   are excluded; actual constructor calls remain observable.
3. **Persistence context.** A persistence finding is emitted only when a
   write primitive receives a persistence destination (or a locally resolved
   destination variable). Merely mentioning `/etc/cron.d` beside an unrelated
   `/tmp` write no longer produces a finding.
4. **Python documentation noise.** Credential observations now come from AST
   environment lookups, subscripts, and file-read calls. Tokens in docstrings,
   comments, and ordinary strings are ignored.
5. **Critical impact calibration.** New cases default potential impact to
   severity. Legacy rows are never under-stated when severity is high or
   critical, and analysts can explicitly override impact through the API, CLI,
   and dashboard. The impact override is migrated with schema version 4.
6. **Publication readiness contract.** `get_case()` returns the structured
   readiness object plus the stable `publication_readiness_state` label. The
   dashboard consumes either shape safely.
7. **Local exposure semantics.** Mixed checked and unchecked subjects report
   `partially_checked`; `not_observed` is reserved for cases where every active
   subject was checked and absent.
8. **Archive decompression limits.** ZIP and TAR members are size-, ratio-,
   entry-, and cumulative-expansion-checked before content is read. Oversized
   or suspicious members are recorded as skipped limitations rather than
   allocating their decompressed contents.
9. **Read-only case reads.** `get_case()` no longer reclassifies IOC candidates,
   reconciles subjects, or persists calibration during a read. The explicit
   `research case reconcile` operation performs those audited writes.
10. **Test database isolation.** Supply-chain scan APIs accept an optional
    database path. Tests pass an isolated temporary database instead of writing
    to the operational SQLite store, while production retains the default path.

## Validation evidence

The regression suite includes direct cases for every finding, including:

- false-positive JavaScript, persistence, and Python documentation fixtures;
- critical impact defaults and explicit overrides;
- mixed local exposure and read-only database snapshots;
- migration from schema version 3 to version 4;
- archive members that are rejected before `ZipFile.read()` is called;
- Research Cases dashboard readiness/artifact rendering contracts;
- an isolated Chrome-extension scan database path.

Focused validation passed:

```text
43 passed: artifact signal calibration, research cases, and artifact analysis
74 passed, 13 subtests passed: dashboard intelligence, research automation,
and Triage Ops UI/API contracts
69 passed: research intake, artifacts, pipeline, and Artifact Fleet workflows
```

The complete core and dashboard commands are the source of truth for final
release validation. Browser verification must confirm that Research Cases loads
250-case responses without a JavaScript exception and displays the structured
readiness state. Static analysis remains the source of truth when no sandbox
result exists; no runtime behavior is inferred.

## Operator impact

- Use **Research -> Cases** for read-only inspection.
- Use the explicit **Reconcile** action only when legacy IOC or artifact state
  repair is intended; it creates an auditable event.
- Set **Potential impact** separately from severity when context requires it.
- Treat `partially_checked` as an evidence gap, not as a benign verdict.
- Treat archive limitations as a reason to obtain a provenance-verified sample,
  never as permission to execute the artifact.
