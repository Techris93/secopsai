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

Fallback:

```bash
curl -fsSL https://raw.githubusercontent.com/Techris93/secopsai/main/setup.sh | bash
```

or

```bash
git clone https://github.com/Techris93/secopsai.git
cd secopsai
bash setup.sh
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

This project now provides a lightweight CLI wrapper `secopsai` that calls the same
top-level scripts in a safe way. The CLI is installed into the project's virtualenv
when you run `bash setup.sh` (editable install).

Usage examples (after activating venv):

```bash
secopsai refresh            # run pipeline (default cache TTL: 60s)
secopsai refresh --force    # force a refresh ignoring cache
secopsai refresh --cache-ttl 300  # set cache TTL to 5 minutes

secopsai list --severity high
secopsai show OCF-XXXX
secopsai mitigate OCF-XXXX
secopsai check --type malware --severity high

# For machine output, add --json to any command
secopsai list --severity high --json
```

Behavior notes:
- The `refresh` subcommand writes a timestamp file at `data/.last_refresh` after a
	successful run and will skip running the exporter if the last refresh is younger
	than the configured TTL (default 60s).
- `--force` ignores the cache and always runs the pipeline.
- The CLI is a safe wrapper that preserves existing script behavior; it can be
	extended later to call importable functions directly.

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
