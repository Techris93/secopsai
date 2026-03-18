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
curl -fsSL https://secopsai.dev/setup.sh | sh
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
