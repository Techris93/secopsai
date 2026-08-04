# Package supply-chain incident response

This runbook describes how SecOpsAI handles a newly reported package
campaign, using the August 2026 Keyv/Cacheable npm incident as the example.
It also records the boundary that matters most: an advisory feed creates a
high-priority lead. It does not, by itself, prove that every listed release is
malicious.

## Why this incident was missed

The previous path had three gaps:

1. The local launchd monitor ran only watchlist-scoped work. It did not run the
   complete global surveillance worker.
2. The npm changes feed records package names, but not the exact release
   version. Events that did not match a configured watchlist were marked
   `scored` without becoming a candidate.
3. SecOpsAI had no external advisory intake path. A package could be reported
   publicly while the local repository had no dependency reference and the
   dashboard had no lead to review.

Those conditions are now corrected for the current campaign feed. The worker
refreshes an allowlisted, source-backed package/version list, creates a
candidate and a canonical finding even when no local dependency is present,
and sends a minimized signed alert to Core when the external-alert webhook is
enabled.

## What the new path does

The research worker performs this sequence on its normal cycle:

1. Fetch the public Wiz package list through HTTPS from the pinned
   `raw.githubusercontent.com` host.
2. Enforce response-size and CSV-schema limits.
3. Store the source hash, source URL, campaign identifier, package, exact
   version, and collection time.
4. Create an idempotent `external_advisory_match` candidate and canonical
   finding for each package/version.
5. Mark the lead as `unverified` and explain that local exposure is not
   required for package verification.
6. Queue the normal bounded investigation autopilot. The autopilot can create
   a case and collect a quarantined artifact; it cannot execute package code,
   send disclosure, or publish an article.
7. Deliver only normalized alert context to Core through the signed webhook.
   Raw artifacts and scanner output remain on the worker disk.

Use the command below to refresh immediately on a local Core database:

```text
secopsai research external-intel refresh --force --json
```

The source feed is refreshed every five minutes by the worker. A failed fetch
keeps the previous records and creates a separate
`external_advisory_feed_degraded` alert. It never turns a failed refresh into
an empty or clean result.

## How to review a lead

Open **Findings** or **Research** and locate the package/version. Confirm:

- the exact package and version;
- the source URL and source hash;
- the campaign name and publication timestamp;
- whether the release is available from the official registry;
- whether the local organization uses the package (useful for exposure, not
  proof of maliciousness);
- the artifact SHA-256 after collection;
- lifecycle scripts, changed files, embedded resources, URLs, and hashes;
- comparison with a known-good version;
- any sandbox result, only after explicit approval.

Do not close a lead as false positive because it is absent from the local
repository. Absence means “not locally observed,” not “benign.” Conversely,
do not publish a maliciousness claim from an advisory list alone. Record the
independent evidence and its limitations.

## Current campaign references

The initial source-backed campaign record links to the following public
research and IOC data:

- [Aikido Keyv and Cacheable investigation](https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack)
- [Wiz Keyv and Cacheable investigation](https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack)
- [Socket Keyv and Cacheable investigation](https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain)
- [Wiz public package/version CSV](https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/main/reports/keyv-packages.csv)

These are provenance sources, not SecOpsAI verdicts. The source-backed
candidate remains open until the exact artifact is collected and reviewed.

## Deployment boundary

The Render worker and Core API use separate persistent disks. The worker must
be configured with:

```text
SECOPSAI_RESEARCH_EXTERNAL_ALERT_CHANNELS=webhook
SECOPSAI_RESEARCH_ALERT_WEBHOOK_URL=https://secopsai-core-api.onrender.com/api/v1/research/alerts/webhook
SECOPSAI_RESEARCH_ALERT_WEBHOOK_SECRET=<the shared server-side secret>
```

External candidates never inherit the operational email channel. This avoids
an email storm when one campaign lists hundreds of versions. Core accepts the
signed, minimized `external_advisory_match` and
`external_advisory_feed_degraded` types, creates a canonical finding, and
preserves analyst status on repeat delivery.

## Honest coverage statement

This change closes the specific “public campaign with no local dependency”
blind spot. It does not claim that npm is clean, that every registry event has
an exact version, or that an external report is independently verified. Full
pre-publication discovery still requires package-version enrichment, bounded
static analysis, package comparison, and an approval-gated sandbox where
justified. The dashboard must show these states as **reported**,
**unverified**, **evidence gap**, or **verified**, rather than flattening them
into one malicious/benign label.
