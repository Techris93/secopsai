# Beginner Guide: Run SecOpsAI Live Locally

This guide shows exactly how to run the product every day, review findings, and triage them.

## What you already have now

- Daily runner script: `scripts/openclaw_daily.sh`
- Scheduler installer: `scripts/install_openclaw_launchd.sh`
- Working live pipeline command: `python run_openclaw_live.py`

## Step 1: Activate your environment

```bash
cd ~/secopsai
source .venv/bin/activate
```

Why:

- Uses the project Python environment so all scripts run with the correct dependencies.

## Step 2: Run one full live pipeline

```bash
python run_openclaw_live.py
```

What this does:

1. Exports native OpenClaw telemetry into local files.
2. Ingests telemetry into a normalized audit stream.
3. Prepares replay files used by detectors.
4. Runs live-mode evaluation (`evaluate_openclaw.py --mode live`).
5. Generates findings and updates the local SOC SQLite store.

Why:

- This is the fastest way to verify end-to-end data flow and detection output.

## Step 3: Review detections

```bash
python soc_store.py list
```

What this does:

- Lists finding IDs, severity, current status, and analyst disposition.

Why:

- Gives you the queue of incidents to triage.

## Step 4: Inspect one finding deeply

```bash
python soc_store.py show FINDING_ID
```

Example:

```bash
python soc_store.py show OCF-41B2A43C8D2C24EA
```

What this does:

- Shows event evidence, attack types, matched rules, MITRE mapping, and notes.

Why:

- Lets you decide whether a finding is a true positive, false positive, or needs more review.

## Step 5: Triage and document your decision

```bash
python soc_store.py set-disposition FINDING_ID true_positive
python soc_store.py set-status FINDING_ID triaged
python soc_store.py add-note FINDING_ID analyst "validated"
```

Why:

- Creates an audit trail of analyst decisions.
- Makes future tuning and model calibration better.

## Step 6: Use one daily command

```bash
scripts/openclaw_daily.sh --skip-export
```

What this does:

- Runs the full live pipeline.
- Writes a timestamped log in `data/openclaw/logs/`.
- Prints the latest findings at the end.

Why `--skip-export`:

- Faster daily runs when your native input files are already present.

## Step 7: Automate daily run on macOS

Install scheduler:

```bash
scripts/install_openclaw_launchd.sh
```

Check scheduler:

```bash
launchctl list | grep secops.autoresearch.openclaw.daily
```

Tail logs:

```bash
tail -f data/openclaw/logs/launchd.out.log
```

Why:

- You get a reliable daily run without manually starting commands.

## Step 8: Simulate attacks and run auto-research training

```bash
scripts/simulate_attacks_and_train.sh
```

What this does:

1. Regenerates deterministic synthetic attacks and benign traffic.
2. Runs baseline benchmark with verbose per-rule output.
3. Optionally builds OpenClaw attack-mix data.
4. Runs quick threshold tuning (`tune.py --quick`).
5. Re-runs benchmark to compare current quality.

Why:

- This is the fastest safe loop to improve smart detection rules.
- You can iterate using measured F1, precision, and recall instead of guessing.

## Step 9: Use OpenClaw as a plugin now

Check malware presence:

```bash
python openclaw_plugin.py check --type malware
```

Check data exfiltration presence:

```bash
python openclaw_plugin.py check --type exfil
```

Check both:

```bash
python openclaw_plugin.py check --type both
```

What this does:

- Reads the local SOC findings store.
- Filters findings for malware/exfil indicators.
- Returns a compact machine-friendly JSON response (good for integrations).

Why:

- Gives you a stable plugin interface for OpenClaw now.
- Future integrations can call this interface without changing core detection logic.

## Step 10: Ask from WhatsApp-style commands

Local simulation (no external setup needed):

```bash
python whatsapp_openclaw_router.py --message "check malware"
python whatsapp_openclaw_router.py --message "check exfil"
python whatsapp_openclaw_router.py --message "show OCF-41B2A43C8D2C24EA"
```

Run webhook server for external provider integration later:

```bash
python whatsapp_openclaw_router.py --serve --host 127.0.0.1 --port 8090
```

What this does:

- Parses simple chat commands.
- Calls the plugin interface.
- Returns a concise response string (ready for WhatsApp reply messages).

Why:

- Lets you keep your WhatsApp workflow while the backend remains local and secure.
- Makes provider integration (Twilio/Meta/API gateway) a thin transport layer.

## Step 11: Connect real Twilio WhatsApp webhook

Run bridge locally:

```bash
scripts/run_twilio_whatsapp_bridge.sh
```

Expose local port with ngrok in a second terminal:

```bash
ngrok http 8091
```

Set your public URL for signature verification (replace with your ngrok URL):

```bash
export SECOPS_PUBLIC_WEBHOOK_URL="https://YOUR-NGROK-ID.ngrok-free.app/twilio/whatsapp"
```

Set Twilio auth token (from Twilio console):

```bash
export SECOPS_TWILIO_AUTH_TOKEN="YOUR_TWILIO_AUTH_TOKEN"
```

In Twilio WhatsApp Sandbox configuration:

- Set "When a message comes in" webhook to:
  `https://YOUR-NGROK-ID.ngrok-free.app/twilio/whatsapp`
- Method: `HTTP POST`

What this does:

- Twilio sends WhatsApp messages to your local bridge endpoint.
- Bridge verifies Twilio signature.
- Bridge routes text to your command handler (`check malware`, `check exfil`, etc.).
- Bridge returns TwiML reply that Twilio delivers back to WhatsApp.

Why:

- You can ask OpenClaw security questions directly in WhatsApp.
- Security checks remain local in your SecOps runtime.

Local testing without Twilio (development only):

```bash
export SECOPS_ALLOW_UNSIGNED=1
curl -X POST http://127.0.0.1:8091/twilio/whatsapp \
	-H "Content-Type: application/x-www-form-urlencoded" \
	--data "Body=check+malware"
```

Important:

- Keep `SECOPS_ALLOW_UNSIGNED=0` in production.

## Common daily operator flow (recommended)

```bash
# 1) Run pipeline (or let schedule run it)
scripts/openclaw_daily.sh --skip-export

# 2) List findings
python soc_store.py list

# 3) Triage top 1-3 HIGH findings
python soc_store.py show FINDING_ID
python soc_store.py set-disposition FINDING_ID true_positive
python soc_store.py set-status FINDING_ID triaged
python soc_store.py add-note FINDING_ID analyst "validated"
```

## If something fails

- Missing venv: run `source .venv/bin/activate`
- No findings generated: run `python run_openclaw_live.py --verbose` and inspect output
- Scheduler not firing: unload/load plist again:

```bash
launchctl unload ~/Library/LaunchAgents/com.secops.autoresearch.openclaw.daily.plist
launchctl load ~/Library/LaunchAgents/com.secops.autoresearch.openclaw.daily.plist
```
