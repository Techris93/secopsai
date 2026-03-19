# Deployment Guide

Instructions for deploying secopsai in production environments.

## Deployment Targets

secopsai can be deployed as:

1. **Standalone Service** — CLI tool for periodic telemetry analysis
2. **Daemon Service** — Continuous monitoring via systemd/launchd
3. **Container** — Docker/OCI image for infrastructure consistency
4. **CI/CD Integration** — GitHub Actions, GitLab CI, Jenkins for continuous validation
5. **SOC Integration** — API endpoint for SIEM platforms

Choose based on your infrastructure and workflow.

---

## Make Installer Commands Live On secopsai.dev (Beginner Guide)

Use this section if you want this command to work for everyone:

```bash
curl -fsSL https://secopsai.dev/install.sh | bash
```

### Step 1: Make sure the installer file is in docs/

This file must exist in your repo so your docs host publishes it at the site root:

- `docs/install.sh`

When MkDocs builds, it becomes:

- `https://<your-docs-host>/install.sh`

### Step 2: Deploy docs so the files are publicly reachable

If you use Cloudflare Pages:

1. Open Cloudflare Dashboard -> Workers & Pages -> your Pages project.
2. Confirm the production branch is your default branch (usually `main`).
3. Confirm build command is `mkdocs build`.
4. Confirm output directory is `site`.
5. Trigger a production deploy.

After deploy, test your docs domain directly (example `docs.secopsai.dev`):

```bash
curl -fsSLI https://docs.secopsai.dev/install.sh
```

You should see HTTP 200.

### Step 3: Point secopsai.dev to the deployment

You have two simple options.

Option A (recommended): make `secopsai.dev` itself serve this Pages project.

1. In Pages project settings, add custom domain `secopsai.dev`.
2. Let Cloudflare create/update DNS records automatically.
3. Wait for SSL status to become Active.

Now this should work directly:

```bash
curl -fsSLI https://secopsai.dev/install.sh
```

Option B: keep docs on `docs.secopsai.dev` and route only installer paths from apex domain.

Use either Redirect Rules or a Worker.

#### Option B1: Cloudflare Redirect Rules

Create one dynamic redirect:

1. If URL matches `https://secopsai.dev/install.sh`
2. Forward to `https://docs.secopsai.dev/install.sh` (Status 302 or 301)

#### Option B2: Cloudflare Worker (proxy, no URL change)

If you prefer users to stay on `secopsai.dev` without redirect, use the Worker script in:

- `scripts/cloudflare-installer-worker.js`

Quick setup:

1. Cloudflare Dashboard -> Workers & Pages -> Create Worker.
2. Paste script from `scripts/cloudflare-installer-worker.js`.
3. Deploy Worker.
4. Add route: `secopsai.dev/install.sh*`

### Step 4: Validate from terminal

Run all checks below:

```bash
curl -fsSLI https://secopsai.dev/install.sh
curl -fsSL https://secopsai.dev/install.sh | head -n 5
```

Expected results:

- HTTP status is 200
- Output starts with `#!/bin/sh`
- Output is shell script text, not HTML

---

## 1. Standalone Service Deployment

### Installation (Production)

Use release binaries rather than git clone:

```bash
# Download latest release
curl -L https://github.com/Techris93/secopsai/releases/download/v1.0.0/secopsai-1.0.0.tar.gz \
  -o secopsai.tar.gz

tar -xzf secopsai.tar.gz
cd secopsai

# Run setup with production defaults
SECOPS_ENV=production bash setup.sh
```

### Usage

```bash
# Run detection once
python detect.py

# Results written to:
# - findings.json
# - findings/OCF-TIMESTAMP.json (timestamped findings)
```

### Scheduling (cron)

Run detection every 6 hours:

```bash
# Edit crontab
crontab -e

# Add job
0 */6 * * * cd /opt/secopsai && /opt/secopsai/.venv/bin/python detect.py >> /var/log/secops-findings.log 2>&1
```

**Output Locations:**

- Findings: `/opt/secopsai/findings.json`
- Logs: `/var/log/secops-findings.log`

---

## 2. Daemon Service (Continuous)

### systemd Service (Linux)

Create `/etc/systemd/system/secopsai.service`:

```ini
[Unit]
Description=SecOps AutoResearch - OpenClaw Detection Daemon
After=network.target

[Service]
Type=simple
User=secops
WorkingDirectory=/opt/secopsai
Environment="PATH=/opt/secopsai/.venv/bin"
ExecStart=/opt/secopsai/.venv/bin/python -u run_openclaw_live.py
Restart=on-failure
RestartSec=30

# Resource limits
MemoryLimit=512M
CPUQuota=50%

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable secopsai
sudo systemctl start secopsai
```

Monitor logs:

```bash
sudo journalctl -u secopsai -f
```

### launchd Service (macOS)

Create `~/Library/LaunchAgents/dev.secops.autoresearch.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.secops.autoresearch</string>
    <key>Program</key>
    <string>/opt/secopsai/.venv/bin/python</string>
    <key>ProgramArguments</key>
    <array>
        <string>/opt/secopsai/.venv/bin/python</string>
        <string>/opt/secopsai/run_openclaw_live.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>WorkingDirectory</key>
    <string>/opt/secopsai</string>
    <key>StandardOutPath</key>
    <string>/var/log/secopsai.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/secopsai.err</string>
</dict>
</plist>
```

Load service:

```bash
launchctl load ~/Library/LaunchAgents/dev.secops.autoresearch.plist
```

---

## 3. Container Deployment

### Dockerfile

Create `Dockerfile`:

```dockerfile
FROM python:3.10-slim

WORKDIR /opt/secopsai

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project
COPY . .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create non-root user
RUN useradd -m -u 1000 secops && chown -R secops:secops /opt/secopsai
USER secops

# Health check
HEALTHCHECK --interval=5m --timeout=1m --start-period=1m --retries=3 \
    CMD python -c "import jsonschema; print('ok')" || exit 1

# Run detection
CMD ["python", "-u", "run_openclaw_live.py"]
```

### Build & Run

```bash
# Build
docker build -t secopsai:1.0.0 .

# Run once
docker run -v ~/.openclaw:/home/secops/.openclaw \
  -v ./findings:/opt/secopsai/findings \
  secopsai:1.0.0

# Run as daemon
docker run -d \
  --name secopsai \
  -v ~/.openclaw:/home/secops/.openclaw \
  -v ./findings:/opt/secopsai/findings \
  --restart unless-stopped \
  secopsai:1.0.0
```

### docker-compose.yml

```yaml
version: "3.8"

services:
  secopsai:
    image: secopsai:1.0.0
    container_name: secopsai
    volumes:
      - ~/.openclaw:/home/secops/.openclaw
      - ./findings:/opt/secopsai/findings
      - ./data:/opt/secopsai/data
    environment:
      - SECOPS_ENV=production
      - SECOPS_FINDINGS_DIR=/opt/secopsai/findings
    restart: unless-stopped
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
```

Run:

```bash
docker-compose up -d
```

---

## 4. CI/CD Integration

### GitHub Actions

Create `.github/workflows/secops-detect.yml`:

```yaml
name: SecOps Detection

on:
  schedule:
    - cron: "0 */6 * * *" # Every 6 hours
  workflow_dispatch: # Manual trigger

jobs:
  detect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt

      - name: Generate benchmark
        run: python generate_openclaw_attack_mix.py --stats

      - name: Run detection
        run: python evaluate_openclaw.py --labeled data/openclaw/replay/labeled/attack_mix.json --unlabeled data/openclaw/replay/unlabeled/attack_mix.json --mode benchmark

      - name: Upload findings
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: findings
          path: findings/

      - name: Create issue if attacks detected
        if: failure()
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.create({
              owner: context.repo.owner,
              repo: context.repo.repo,
              title: 'Security findings detected',
              body: 'Check findings artifact for details'
            })
```

### GitLab CI

Create `.gitlab-ci.yml`:

```yaml
stages:
  - detect
  - report

detect:
  stage: detect
  image: python:3.10
  script:
    - pip install -r requirements.txt
    - python generate_openclaw_attack_mix.py --stats
    - python evaluate_openclaw.py --labeled data/openclaw/replay/labeled/attack_mix.json --unlabeled data/openclaw/replay/unlabeled/attack_mix.json --mode benchmark
  artifacts:
    paths:
      - findings/
    reports:
      junit: findings/report.xml
  only:
    - schedules

report:
  stage: report
  image: python:3.10
  needs: ["detect"]
  script:
    - python findings.py
  artifacts:
    paths:
      - findings.json
```

---

## 5. SIEM Integration

### Splunk HEC (HTTP Event Collector)

```python
# send_to_splunk.py
import requests
import json

def send_findings_to_splunk(findings_json, splunk_hec_url, hec_token):
    """Send findings to Splunk HTTP Event Collector"""

    headers = {
        "Authorization": f"Splunk {hec_token}",
        "Content-Type": "application/json"
    }

    with open(findings_json) as f:
        report = json.load(f)

    for finding in report["findings"]:
        event = {
            "event": finding,
            "sourcetype": "secops:autoresearch",
            "source": "openclaw_detection"
        }

        response = requests.post(
            f"{splunk_hec_url}/services/collector",
            headers=headers,
            json=event,
            verify=False
        )

        if response.status_code != 200:
            print(f"Failed to send finding: {response.text}")

# Usage
send_findings_to_splunk(
    "findings.json",
    "https://splunk.example.com:8088",
    "your-hec-token"
)
```

### ELK Stack (Elasticsearch)

```python
# send_to_elasticsearch.py
from elasticsearch import Elasticsearch

def send_findings_to_elastic(findings_json, elastic_host="localhost:9200"):
    """Send findings to Elasticsearch"""

    es = Elasticsearch([elastic_host])

    with open(findings_json) as f:
        report = json.load(f)

    for finding in report["findings"]:
        es.index(
            index="secopsai",
            doc_type="_doc",
            body=finding
        )

    print(f"Indexed {len(report['findings'])} findings")

# Usage
send_findings_to_elastic("findings.json")
```

---

## Security Best Practices

### File Permissions

```bash
# Restrict findings to owner only
chmod 600 findings.json

# Restrict to secops user
sudo chown secops:secops /opt/secopsai
sudo chmod 750 /opt/secopsai
```

### Network Isolation

- Run on isolated network segment if analyzing sensitive telemetry
- Use VPN/bastion host for remote access
- TLS encrypt all data in transit

### Credential Management

```bash
# Store SIEM credentials in environment
export SPLUNK_HEC_TOKEN=xxxx

# Or use .env file (add to .gitignore)
echo "SPLUNK_HEC_TOKEN=xxxx" > .env
source .env
```

### Audit Logging

Enable audit logs:

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler('/var/log/secopsai-audit.log'),
        logging.StreamHandler()
    ]
)
```

---

## Monitoring & Alerting

### Health Checks

```bash
#!/bin/bash
# check_secops_health.sh

findings_file="/opt/secopsai/findings.json"

# Check if findings file exists and is recent
if [[ ! -f "$findings_file" ]]; then
    echo "CRITICAL: findings.json missing"
    exit 2
fi

file_age=$(($(date +%s) - $(stat -f%m "$findings_file" 2>/dev/null || stat -c%Y "$findings_file")))
if [[ $file_age -gt 86400 ]]; then  # > 24 hours
    echo "WARNING: findings.json is stale (${file_age}s old)"
    exit 1
fi

echo "OK: secopsai is healthy"
exit 0
```

### Alerting

```bash
#!/bin/bash
# alert_on_findings.sh

python findings.py

# Extract severity breakdown
critical=$(jq '.severity_breakdown.CRITICAL' findings.json)
high=$(jq '.severity_breakdown.HIGH' findings.json)

if [[ $critical -gt 0 ]]; then
    # Send alert
    curl -X POST https://your-alert-system/api/alerts \
        -d "severity=critical&count=$critical"
fi
```

---

## Troubleshooting Deployments

### Service not starting

```bash
# Check logs
sudo journalctl -u secopsai -n 50

# Test manually
/opt/secopsai/.venv/bin/python /opt/secopsai/run_openclaw_live.py
```

### No findings generated

```bash
# Check if local telemetry exists
ls -la ~/.openclaw/

# Test with benchmark
python generate_openclaw_attack_mix.py --stats
python evaluate_openclaw.py --labeled data/openclaw/replay/labeled/attack_mix.json --unlabeled data/openclaw/replay/unlabeled/attack_mix.json --mode benchmark
```

### OpenClaw CLI missing

```bash
# Install OpenClaw
curl -fsSL https://docs.openclaw.ai/install | sh
```

---

## Performance Tuning

### Resource Limits

Adjust based on your environment:

```yaml
# docker-compose.yml
services:
  secopsai:
    deploy:
      resources:
        limits:
          cpus: "1.0"
          memory: 512M
        reservations:
          cpus: "0.5"
          memory: 256M
```

### Batch Processing

For large telemetry volumes:

```python
# Process in chunks
batch_size = 10000
for i in range(0, len(events), batch_size):
    batch = events[i:i+batch_size]
    findings = run_detection(batch)
    # Process batch findings...
```

---

## Support & Updates

- **Release Notes**: https://github.com/Techris93/secopsai/releases
- **Upgrade Guide**: Follow changes in the Release Notes above
- **Issue Tracking**: [GitHub Issues](https://github.com/Techris93/secopsai/issues)

---

**Next:** [Rules Registry](rules-registry.md) for rule tuning in production.
