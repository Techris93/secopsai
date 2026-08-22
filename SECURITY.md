# Security Policy

## Supported Versions

Security fixes are developed on `main` and included in the next published
release. The current stable release is the supported packaged version. Older
releases may not receive backported fixes.

## Report A Vulnerability

Send private reports to [security@secopsai.dev](mailto:security@secopsai.dev).
Do not open a public issue for an undisclosed vulnerability.

Include:

- The affected component and version or commit.
- A concise impact description.
- Reproduction steps using non-destructive evidence where possible.
- Relevant logs with credentials, customer data, and private telemetry removed.
- A safe way to contact you about the report.

Do not send live credentials, weaponized malware, customer data, or artifacts
you are not authorized to share. Contact the security address first when a
large or sensitive file transfer is necessary.

## Response Process

The project will acknowledge a reproducible report, assess severity and scope,
coordinate a fix, and agree on a disclosure timeline when appropriate. Please
allow reasonable time for validation and remediation before public disclosure.

## Security Boundaries

SecOpsAI is designed around local-first storage, no-execution artifact
inspection, server-side credentials, bounded model context, and explicit
approval gates. A report is especially useful when it shows a path that crosses
one of those boundaries, bypasses authorization, exposes protected data, or
causes an untrusted package or payload to execute.

See [Security and Data Handling](docs/security-and-data-handling.md) and the
[Threat Model](docs/threat-model.md) for the documented trust boundaries.
