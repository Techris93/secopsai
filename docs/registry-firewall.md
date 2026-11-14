# Registry firewall

An npm and PyPI proxy that refuses package versions known to be malicious
(frontier phase 5). Worker: `cloudflare/secopsai-registry-firewall`.

## How it decides

- The blocklist is rebuilt every hour from `ossf/malicious-packages` by
  `scripts/build_blocklist.py` (workflow `blocklist-refresh.yml`) and stored as
  256 shards per ecosystem in the ledger bucket under `firewall/`.
- A report whose range starts at version 0 with no fix blocks every version of
  the package; otherwise only the listed versions are blocked.
- npm: blocked versions are removed from package documents, `dist-tags` move
  to the newest remaining version, and blocked tarballs get 403 even when a
  lockfile pins them.
- PyPI: blocked files are removed from both the JSON and HTML `/simple/` index.
- A package blocked at every version returns 403 with its advisory IDs.

## Use

The firewall needs `FIREWALL_TOKEN` (production environment secret), then
`deploy-registry-firewall.yml`. Clients present the token as their registry
credential:

```bash
npm config set registry https://<firewall-host>/npm/
npm config set //<firewall-host>/npm/:_authToken "$FIREWALL_TOKEN"
pip config set global.index-url "https://token:$FIREWALL_TOKEN@<firewall-host>/pypi/simple/"
```

## Lockfile check

`POST /check` with `{"packages": [{"ecosystem": "npm", "name": "left-pad", "version": "1.3.0"}]}`
(up to 2,000) returns the blocked entries and their advisory IDs, so CI can
check a lockfile without installing.

## Measure

`firewall-check.yml` reports the block rate on the benchmark's known-malicious
versions (through `/check`, with 100 npm tarballs confirmed refused end to end)
and the 95th percentile added latency for popular packages' metadata.
