# Authorized Artifact Evidence Workflow

Mission Control can import an authorized package artifact through the local helper. The artifact is copied into the Core quarantine, hashed, and inspected without installation or execution.

## Operator flow

1. Open a research case in Mission Control and enter the research action token.
2. Open **Local artifact evidence**.
3. Select a `.nupkg`, `.zip`, `.vsix`, `.gem`, or `.whl` that you are authorized to analyze.
4. Confirm the ecosystem, package name, and version, and record the lawful source and authorization. Provenance is required; the import is rejected without it. Select **Import Authorized Artifact**.
5. Confirm the SHA-256 and quarantine state. Select **Inspect safely**.
6. Review archive members, lifecycle files, public URLs, external IP candidates, hashes, and limitations.
7. Select **Extract IOC Candidates**. Every candidate remains pending until reviewed.
8. Approve only indicators that are supported by the evidence. Generic registry and vendor URLs are suppressed.
9. Use the comparison action for exact local artifacts or compare a local artifact with a registry intake.
10. Record registry availability separately from the case status. A removed package is not automatically malicious, and an unavailable package is not proof that it was removed.

Raw bytes remain in local, owner-only quarantine. They are not sent to Supabase, Render, Cloudflare, or an AI provider. Archive validation rejects path traversal, drive-relative paths, symlinks, hardlinks, and device entries, and enforces entry-count, entry-size, and expanded-size limits for both ZIP packages and tar-based `.gem` packages. Dynamic analysis remains a separate, approval-gated workflow.

## CLI recovery path

The same operations are available to a local operator when the browser helper is unavailable:

```text
secopsai research artifact list
secopsai research artifact import --path ./package.nupkg --ecosystem nuget --package Example --version 1.0.0 --provenance '{"source":"Downloaded from nuget.org before removal; authorized research copy"}'
secopsai research artifact show ART-...
secopsai research artifact verify ART-...
secopsai research analysis run ART-...
secopsai research analysis compare ART-LEFT ART-RIGHT
secopsai research ioc-candidates extract RSC-...
secopsai research ioc-candidates review IOC-C-... --decision approved
secopsai research subject state SUB-... --registry-state removed --reason "Official flat-container returned 404 after prior availability"
secopsai research partner-request create RSC-... --recipient research@example.org --reason "Request exact archived artifact and provenance"
```

The Core CLI does not accept arbitrary shell commands for analysis. An optional NuGet analyzer is configured only as a pinned Docker image reference (immutable tag or `sha256` digest) and is run with no network, read-only filesystem, dropped capabilities, and bounded resources.
