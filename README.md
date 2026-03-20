# SecOpsAI

Intelligent attack detection for OpenClaw audit logs.

SecOpsAI is a local-first security pipeline that turns OpenClaw telemetry into actionable findings you can review, triage, and mitigate quickly.

## What it does

- Detects attack behavior in OpenClaw audit logs
- Groups and deduplicates detections into incident findings
- Stores findings in local SQLite
- Supports triage workflow: list, show, status, disposition, notes
- Provides mitigation guidance per finding
- Supports conversational workflows through plugin and WhatsApp bridge

## Why use it

- Local-first: no external APIs required
- Fast setup: one script and one environment
- Practical SOC flow: detect -> list -> show -> triage -> mitigate
- Automation-ready: daily runs and webhook bridge included
- Open source and easy to extend

## Quick Start

1. Install:

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
```

Security note: only run a `curl | bash` installer if you trust the publisher and the source code. If you prefer a safer path, clone the repo and inspect `docs/install.sh` + `setup.sh` before running.

When piped from `curl`, setup runs in non-interactive mode with safe defaults:

- optional native surfaces: disabled
- benchmark generation: enabled
- live export: disabled

Optional hardening controls for installer bootstrap:

- `SECOPSAI_INSTALL_REF=<git ref or commit>` to pin setup script source
- `SECOPSAI_INSTALL_SHA256=<sha256>` to enforce checksum verification

By default, `install.sh` uses a pinned immutable commit for secure installs.
If you explicitly want latest `main`, use:

```bash
SECOPSAI_INSTALL_REF=main curl -fsSL https://secopsai.dev/install.sh | bash
```

Optional runtime temp log directory:

- `SECOPSAI_TMP_DIR=/path` to override default temp log location (`$TMPDIR` or `/tmp`)

Fallback (manual setup):

```bash
git clone https://github.com/Techris93/secopsai.git
cd secopsai

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
python prepare.py  # Generate data/events.json and data/events_unlabeled.json
python -m pytest tests/ -v  # Optional: verify installation
```

2. Activate environment:

```bash
source .venv/bin/activate
```

3. Run live pipeline:

```bash
python run_openclaw_live.py
```

## CLI: `secopsai`

This project exposes a first-class CLI, `secopsai`, that runs the OpenClaw
pipeline in-process (no `subprocess` shells) and provides both pretty and JSON
output. The CLI is installed into the project's virtualenv by `install.sh`.

Usage examples (after activating venv):

```bash
# 1) Run the full live pipeline and persist findings
secopsai refresh
secopsai refresh --skip-export       # reuse existing native export

# 2) List and inspect findings (auto-refresh with cache)
secopsai list --severity high
secopsai list --severity high --json
secopsai list --severity high --cache-ttl 300   # reuse refresh from last 5 minutes

secopsai show OCF-XXXX
secopsai mitigate OCF-XXXX
secopsai check --type malware --severity high

# All subcommands accept --json for machine-friendly output
# (works either before or after the subcommand)
secopsai show OCF-XXXX --json
secopsai --json show OCF-XXXX
secopsai check --type malware --severity high --json
```

## Security

This repo includes security guardrails and continuous scanning:

- Threat model: `docs/threat-model.md`
- CI security scans (on PRs): Semgrep (SAST), Trivy (dependency scan), and Gitleaks (secrets)

## Threat Intelligence (IOC) pipeline

Security note: the intel pipeline downloads public IOC feeds and stores them locally under `data/intel/`. It does not call paid enrichment APIs by default.

secopsai also includes a local-first threat intel pipeline:

- Downloads open-source IOC feeds (URLhaus + ThreatFox)
- Normalizes + de-duplicates indicators
- Optional lightweight enrichment (DNS resolution)
- Matches IOCs against your latest OpenClaw replay events
- Persists matches into the same local SOC store (so `secopsai list/show` can be used)

Examples:

```bash
# Download feeds and store them locally under data/intel/
secopsai intel refresh --json

# (Optional) add local enrichment
secopsai intel refresh --enrich

# List a few stored IOCs
secopsai intel list --limit 20

# Match IOCs against latest replay and persist matches as findings
secopsai intel match --limit-iocs 500 --json
```

Behavior notes:

- `secopsai refresh` runs the full OpenClaw live pipeline by calling
  `export_real_openclaw_native`, `ingest_openclaw`, `openclaw_prepare`,
  `evaluate_openclaw`, and `openclaw_findings` directly in Python, then
  writes findings into the local SOC store (`soc_store`).
- After a successful `refresh`, a timestamp is written to `data/.last_refresh`.
- `list`, `show`, `mitigate`, and `check` will, by default, auto-refresh via the
  pipeline **unless** a recent refresh exists; the freshness window is controlled
  by `--cache-ttl` (default 60 seconds). Use `--no-refresh` on those commands to
  skip the pipeline entirely and operate on whatever is already in `soc_store`.
- The CLI is designed to be idempotent and automation-friendly: pretty output for
  humans, `--json` for integrations.
- `--json` is accepted either before or after subcommands, so both
  `secopsai --json list` and `secopsai list --json` work.
- The installer/editable package includes the runtime helper modules used by the
  CLI entrypoint, so `secopsai` works correctly from the installed virtualenv.

4. Review findings:

```bash
python soc_store.py list
python soc_store.py show OCF-<ID>
```

5. Triage finding:

```bash
python soc_store.py set-disposition OCF-<ID> true_positive
python soc_store.py set-status OCF-<ID> triaged
python soc_store.py add-note OCF-<ID> analyst "validated"
```

6. Get mitigation guidance:

```bash
python openclaw_plugin.py mitigate OCF-<ID>
```

## Daily operation

```bash
cd "$HOME/secopsai" && source .venv/bin/activate && python run_openclaw_live.py --skip-export && python soc_store.py list
```

macOS launchd helper:

```bash
bash scripts/install_openclaw_launchd.sh
```

## Conversational commands

- check malware
- check exfil
- list high
- show OCF-...
- triage OCF-...
- mitigate OCF-...

Twilio bridge:

```bash
python twilio_whatsapp_webhook.py --host 127.0.0.1 --port 8091
```

## Minimal files required to run

- setup.sh
- run_openclaw_live.py
- detect.py
- ingest_openclaw.py
- openclaw_prepare.py
- openclaw_findings.py
- soc_store.py
- openclaw_plugin.py
- scripts/openclaw_daily.sh
- scripts/install_openclaw_launchd.sh

Optional chat files:

- whatsapp_openclaw_router.py
- twilio_whatsapp_webhook.py
- scripts/run_twilio_whatsapp_bridge.sh

## Docs

- docs/BEGINNER-LIVE-GUIDE.md
- docs/OpenClaw-Integration.md
- docs/deployment-guide.md
- docs/rules-registry.md
- docs/api-reference.md

## Contributing

See CONTRIBUTING.md.

## License

MIT (see LICENSE).
