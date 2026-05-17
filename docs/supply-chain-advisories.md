# Emergency Supply Chain Advisories

Emergency advisories are SecOpsAI's local-first denylist path for package versions that are confirmed compromised by reliable sources but are no longer available for normal artifact diffing.

## When To Use This

Use advisories when a package version is confirmed malicious and one of these is true:

- The package artifact was removed, yanked, or returns 404.
- Diff generation fails but the package/version appears in a trusted campaign report.
- You need a fast block before the next full scanner release.
- You need SOC findings with sources, IOCs, and mitigation even when local manifests do not currently reference the package.

## Operator Workflow

```bash
# List active advisories.
secopsai supply-chain advisory list

# Check one package version.
secopsai supply-chain advisory check --ecosystem pypi --package guardrails-ai --version 0.10.1

# Explain why a version is malicious, even without a stored diff report.
secopsai supply-chain explain-verdict --ecosystem npm --package @squawk/mcp --version 0.9.5

# Check the node-ipc stealer/backdoor advisory.
secopsai supply-chain advisory check --ecosystem npm --package node-ipc --version 12.0.1
secopsai supply-chain explain-verdict --ecosystem npm --package node-ipc --version 12.0.1

# Show supported ecosystem capabilities and limitations.
secopsai supply-chain ecosystems

# Reconcile historical scanner errors after adding an advisory.
secopsai supply-chain reconcile-history --include-advisories
```

## Supported Ecosystems

Emergency advisory matching is ecosystem-generic. Live artifact diffing is
full-fidelity for npm and PyPI, and SecOpsAI now safely enables live
metadata/artifact adapters for crates.io, Packagist, Go Modules, Hugging Face
Hub, Maven Central, NuGet, Open VSX, and RubyGems.org where public registry APIs
allow it. Chrome Web Store remains local-artifact/advisory focused because
server-side CRX download is not reliably available without browser/session
context.

| Ecosystem | Identifier | Current support |
| --- | --- | --- |
| npm | `package` | Advisory, metadata fetch, artifact fetch, diff, behavior rules, monitor |
| PyPI | `project` | Advisory, metadata fetch, artifact fetch, diff, behavior rules, monitor |
| crates.io | `crate` | Advisory, crates.io metadata, `.crate` fetch/diff, Cargo/build.rs/proc-macro rules, package watch |
| Chrome Web Store | `extension-id` | Advisory, local CRX/ZIP artifact scan, extension manifest/background-script rules |
| Packagist | `vendor/package` | Advisory, Packagist metadata, dist archive fetch/diff, Composer/PHP rules, package watch |
| Go Modules | `module/path` | Advisory, Go proxy metadata, module ZIP fetch/diff, go.mod/source rules, package watch |
| Hugging Face Hub | `owner/repo` | Advisory, metadata/file-list/small source fetch, unsafe loading rules, package watch; model code/weights are never executed |
| Maven Central | `groupId:artifactId` | Advisory, Maven metadata, source JAR/POM fetch/diff, Java/POM rules, package watch |
| NuGet | `Package.Id` | Advisory, NuGet flat-container metadata, NUPKG fetch/diff, nuspec/PowerShell/build-target rules, version-delta watch |
| Open VSX | `namespace.extension` | Advisory, Open VSX metadata, VSIX fetch/diff, VS Code extension manifest/source rules, package watch |
| RubyGems.org | `gem` | Advisory, RubyGems metadata, GEM fetch/diff, gemspec/Rake/extconf Ruby rules, package watch |

Examples:

```bash
secopsai supply-chain advisory check --ecosystem crates --package secopsai-fixture-crate --version 1.2.3
secopsai supply-chain advisory check --ecosystem chrome-web-store --package fixtureextensionid --version 4.5.6
secopsai supply-chain advisory check --ecosystem packagist --package vendor/fixture --version 1.0.0
secopsai supply-chain advisory check --ecosystem go --package github.com/example/fixture --version v1.2.3
secopsai supply-chain advisory check --ecosystem huggingface --package secopsai/fixture-model --version main
secopsai supply-chain advisory check --ecosystem maven --package com.example:fixture --version 2.0.0
secopsai supply-chain advisory check --ecosystem nuget --package fixture.package --version 3.0.0
secopsai supply-chain advisory check --ecosystem open-vsx --package secopsai.fixture --version 0.1.0
secopsai supply-chain advisory check --ecosystem rubygems --package fixture_gem --version 9.9.9
```

## Ingesting A New Advisory

Advisories live in `data/advisories/*.json` and can also be ingested from a local JSON file or HTTPS URL.

```bash
secopsai supply-chain advisory ingest /path/to/advisory.json
secopsai supply-chain advisory ingest https://example.com/secopsai/advisory.json
```

## Advisory Schema

```json
{
  "advisory_id": "SECOPSAI-ADV-YYYY-MM-CAMPAIGN",
  "campaign_id": "campaign-name",
  "title": "Campaign title",
  "summary": "Short analyst summary",
  "severity": "critical",
  "confidence": "high",
  "status": "active",
  "published_at": "2026-05-11T00:00:00Z",
  "updated_at": "2026-05-12T00:00:00Z",
  "ingested_at": "2026-05-12T00:00:00Z",
  "source_names": ["Trusted source"],
  "source_urls": ["https://example.com/report"],
  "affected": [
    {
      "ecosystem": "npm",
      "package": "@scope/package",
      "versions": ["1.2.3"],
      "version_ranges": [{"introduced": "2.0.0", "fixed": "2.0.5"}],
      "safe_versions": ["Use a maintainer-confirmed clean version"]
    }
  ],
  "iocs": {
    "domains": ["example.com"],
    "urls": ["https://example.com/payload.js"],
    "hashes": [],
    "file_paths": ["/tmp/payload.pyz"],
    "filenames": ["payload.pyz"],
    "commands": ["python3 /tmp/payload.pyz"]
  },
  "detection_rationale": ["Why this package/version is malicious"],
  "remediation": ["Block the version and rotate exposed credentials"]
}
```

Package identifiers are ecosystem-specific:

- crates.io: crate name and version.
- Chrome Web Store: extension ID or canonical extension name and version.
- Packagist: `vendor/package` and version.
- Go Modules: module path and semantic/module version.
- Hugging Face Hub: `owner/repo` plus revision/tag/commit where available.
- Maven Central: `groupId:artifactId` and version.
- NuGet: package ID and version.
- Open VSX: `namespace.extension` and version.
- PyPI: normalized project name and version.
- RubyGems.org: gem name and version.
- npm: package name and version.

## SOC Behavior

Advisory matches produce source-backed `SUPPLY-CHAIN-ADVISORY` findings. If a normal diff report exists, the advisory enriches the scanner verdict. If the artifact is unavailable, SecOpsAI records the verdict as malicious and clearly marks the evidence path as `artifact unavailable; advisory matched`.

Advisory-backed findings are not closed as `expected_behavior` just because a package is absent from local manifests. They remain actionable ecosystem intelligence until an analyst explicitly triages them.

## node-ipc Stealer/Backdoor Workflow

The `node-ipc` emergency advisory covers `node-ipc@9.1.6`,
`node-ipc@9.2.3`, and `node-ipc@12.0.1`. These versions are treated as
package-level malicious ecosystem intelligence even if no local lockfile
currently references them.

```bash
secopsai supply-chain advisory check --ecosystem npm --package node-ipc --version 9.1.6 --json
secopsai supply-chain advisory check --ecosystem npm --package node-ipc --version 9.2.3 --json
secopsai supply-chain advisory check --ecosystem npm --package node-ipc --version 12.0.1 --json

secopsai supply-chain explain-verdict --ecosystem npm --package node-ipc --version 12.0.1
```

Operator mitigation:

- Block `node-ipc@9.1.6`, `node-ipc@9.2.3`, and `node-ipc@12.0.1`.
- Audit `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`,
  `npm-shrinkwrap.json`, `node_modules/node-ipc`, CI runner caches, and
  container build layers.
- Rotate npm tokens, GitHub/GitLab tokens, cloud keys, SSH keys, CI/CD
  secrets, and developer-machine credentials only when an affected version was
  installed or loaded in an environment with secrets.
- Rebuild from clean lockfiles and purge compromised package-manager caches.
