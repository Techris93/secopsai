# Mini Shai-Hulud Red Hat Cloud Services Validation

## Why SecOpsAI Missed It

SecOpsAI could detect a malicious npm tarball if an affected artifact was scanned,
but the live monitoring path was too narrow:

- npm recent-release monitoring was driven by top-package watchlists, so it did
  not automatically sweep the `@redhat-cloud-services/*` namespace.
- `watch-registry` only supported single npm packages and Packagist namespaces.
- npm metadata snapshots did not record historical tarball integrity, shasum, or
  lifecycle-script changes for source-of-truth comparison.
- JavaScript artifact rules covered generic eval, subprocess, network, and
  credential access, but did not explicitly model the Mini Shai-Hulud cluster:
  AES-GCM embedded payloads, Bun temp staging, `gh auth token`, GitHub Actions
  runner secret harvesting, encrypted exfiltration, GitHub API dead-drop writes,
  daemonization, and marker strings.

## New Source-First Coverage

SecOpsAI now detects this class from source evidence before relying on vendor
writeups:

- npm namespace watch:
  `secopsai supply-chain watch-registry --ecosystem npm --namespace redhat-cloud-services --since 2h --dry-run --json`
- namespace burst rule:
  `NPM-NAMESPACE-MASS-PUBLISH-BURST`
- per-package metadata rules:
  `NPM-PACKAGE-VERSION-BURST`,
  `NPM-HISTORICAL-INTEGRITY-CHANGED`,
  `NPM-HISTORICAL-SHASUM-CHANGED`,
  `NPM-HISTORICAL-TARBALL-CHANGED`, and
  `NPM-METADATA-LIFECYCLE-HOOK`
- artifact rules for:
  `preinstall node index.js`, AES-GCM payload loaders, Bun temp staging,
  GitHub CLI token harvesting, GitHub Actions secret harvesting, token regex
  harvesting, GitHub API dead-drop writes, encrypted exfiltration envelopes,
  credential-file targeting, daemonization, locale avoidance, and Mini
  Shai-Hulud marker strings.

The scanner still does not execute package code, lifecycle scripts, Bun, shell
commands, or downloaded payloads.

## Emergency Advisory

The advisory file is:

`data/advisories/mini-shai-hulud-redhat-cloud-services-2026-06.json`

It covers observed compromised `@redhat-cloud-services/*` package versions and
adds source-backed remediation guidance. This advisory is enrichment and
backstop coverage; the primary fix is the namespace and artifact behavior
detection above.

Validate an affected package:

```bash
secopsai supply-chain advisory check --ecosystem npm --package @redhat-cloud-services/chrome --version 2.3.1 --json
```

## Operator Workflow

1. Run the namespace watch for a recent window.
2. Review `namespace_evidence.signals` for mass publish bursts.
3. Review each package `source_evidence.signals` for lifecycle hooks or
   historical integrity changes.
4. Scan suspicious artifacts or fixtures without execution.
5. Check local exposure in `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`,
   `npm-shrinkwrap.json`, `node_modules`, CI caches, and container layers.
6. Rotate credentials only when an affected version was installed or executed in
   an environment with secrets.

## Remaining Limitations

- npm namespace search can be rate-limited or incomplete, so operators should
  add important namespaces to scheduled watches.
- Removed/yanked packages may require advisory matching or cached artifacts.
- Historical integrity changes require a prior SecOpsAI snapshot.
- Attribution remains out of scope; SecOpsAI reports evidence, impact, and
  mitigation rather than naming an actor without source-backed proof.
