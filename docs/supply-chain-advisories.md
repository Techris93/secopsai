# Emergency Supply Chain Advisories

Emergency advisories are SecOpsAI's local-first denylist path for package versions that are confirmed compromised by reliable sources but are no longer available for normal artifact diffing.

## When To Use This

Use advisories when a package version is confirmed malicious and one of these is true:

- The npm/PyPI artifact was removed, yanked, or returns 404.
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

# Reconcile historical scanner errors after adding an advisory.
secopsai supply-chain reconcile-history --include-advisories
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

## SOC Behavior

Advisory matches produce source-backed `SUPPLY-CHAIN-ADVISORY` findings. If a normal diff report exists, the advisory enriches the scanner verdict. If the artifact is unavailable, SecOpsAI records the verdict as malicious and clearly marks the evidence path as `artifact unavailable; advisory matched`.

Advisory-backed findings are not closed as `expected_behavior` just because a package is absent from local manifests. They remain actionable ecosystem intelligence until an analyst explicitly triages them.
