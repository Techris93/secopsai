# SecOpsAI Toolkit - DEPLOYMENT GUIDE

Complete deployment instructions for production environments.

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Integration](#integration)
5. [Monitoring Setup](#monitoring-setup)
6. [Incident Response](#incident-response)
7. [Maintenance](#maintenance)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        SecOpsAI Platform                         │
├─────────────────────────────────────────────────────────────────┤
│  Detection Layer                                                  │
│  ├── npm Registry Monitor (API polling, webhook)                 │
│  ├── Runtime Process Monitor (psutil/bpf)                        │
│  ├── SBOM Validator (lockfile analysis)                          │
│  └── YARA File Scanner (on-access/scheduled)                     │
├─────────────────────────────────────────────────────────────────┤
│  Analysis Layer                                                   │
│  ├── Sigma Rule Engine                                           │
│  ├── Threat Intelligence Feed                                    │
│  └── ML Anomaly Detection                                        │
├─────────────────────────────────────────────────────────────────┤
│  Response Layer                                                   │
│  ├── Automated Containment                                       │
│  ├── Incident Response Playbooks                                 │
│  └── Notification (SIEM/Ticketing)                               │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

### Production Deployment

#### Option 1: Package Installation (Recommended)

```bash
# Download release
curl -L https://github.com/secopsai/toolkit/releases/download/v1.0.0/secopsai-toolkit-1.0.0.tar.gz | tar xz
cd secopsai-toolkit-1.0.0

# Run installer
sudo ./scripts/setup.sh

# Verify installation
secopsai-npm-monitor --help
secopsai-runtime-monitor --status
```

#### Option 2: Docker Deployment

```bash
# Build image
docker build -t secopsai-toolkit:latest .

# Run with host monitoring
docker run -d \
  --name secopsai \
  --privileged \
  --pid=host \
  --net=host \
  -v /var/log/secopsai:/var/log/secopsai \
  -v /etc/secopsai:/etc/secopsai \
  secopsai-toolkit:latest

# View logs
docker logs -f secopsai
```

#### Option 3: Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: secopsai-monitor
  namespace: security
spec:
  selector:
    matchLabels:
      app: secopsai
  template:
    metadata:
      labels:
        app: secopsai
    spec:
      hostPID: true
      hostNetwork: true
      containers:
      - name: runtime-monitor
        image: secopsai/toolkit:latest
        securityContext:
          privileged: true
        volumeMounts:
        - name: logs
          mountPath: /var/log/secopsai
        - name: config
          mountPath: /etc/secopsai
      volumes:
      - name: logs
        hostPath:
          path: /var/log/secopsai
      - name: config
        configMap:
          name: secopsai-config
```

## Configuration

### Environment Variables

```bash
# Core settings
export SECOPSAI_ENV=production
export SECOPSAI_LOG_LEVEL=info
export SECOPSAI_CONFIG_PATH=/etc/secopsai/config.yaml

# Monitoring
export SECOPSAI_MONITOR_INTERVAL=5
export SECOPSAI_ALERT_WEBHOOK=https://hooks.slack.com/...

# npm settings
export SECOPSAI_NPM_REGISTRY=https://registry.npmjs.org
export SECOPSAI_NPM_BLOCK_SCRIPTS=true

# Registry credentials (for private registries)
export SECOPSAI_NPM_TOKEN=your-npm-token
export SECOPSAI_PYPI_TOKEN=your-pypi-token
```

### Production Config

```yaml
# /etc/secopsai/config.yaml
secopsai:
  environment: production
  
  monitoring:
    enabled: true
    interval_seconds: 5
    
  npm:
    policy:
      block_install_scripts: true
      require_provenance: true
      min_package_age_days: 7
      
  incident_response:
    auto_contain: false  # Require manual approval
    notifications:
      webhook_url: "${SLACK_WEBHOOK_URL}"
      email_alerts: true
      email_recipients:
        - security@company.com
        - soc@company.com
```

## Integration

### SIEM Integration

#### Splunk

```bash
# Install Splunk Universal Forwarder
# Configure inputs.conf

cat > /opt/splunkforwarder/etc/apps/secopsai/local/inputs.conf << 'EOF'
[monitor:///var/log/secopsai]
disabled = false
index = security
sourcetype = secopsai:json

[monitor:///var/log/secopsai-runtime-alerts.log]
disabled = false
index = security
sourcetype = secopsai:alerts
EOF
```

#### Elastic Stack

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/secopsai/*.log
  json.keys_under_root: true
  json.add_error_key: true
  processors:
    - add_fields:
        target: secopsai
        fields:
          environment: production

output.elasticsearch:
  hosts: ["https://elasticsearch:9200"]
  index: "secopsai-%{+yyyy.MM.dd}"
```

#### Custom SIEM (Webhook)

```python
# Custom webhook receiver example
from flask import Flask, request
import json

app = Flask(__name__)

@app.route('/secopsai/webhook', methods=['POST'])
def handle_alert():
    alert = request.json
    
    # Route based on severity
    if alert['severity'] == 'CRITICAL':
        create_pager_duty_incident(alert)
        send_slack_alert(alert, channel='#security-critical')
    elif alert['severity'] == 'HIGH':
        send_slack_alert(alert, channel='#security-alerts')
        create_jira_ticket(alert)
    
    return {'status': 'received'}
```

### CI/CD Integration

#### GitHub Actions

```yaml
name: SecOpsAI Security Check

on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup SecOpsAI
        run: |
          curl -sL https://secopsai.io/install.sh | bash
          
      - name: Validate SBOM
        run: |
          secopsai-sbom-validator \
            --sbom package-lock.json \
            --policy strict \
            --output sbom-results.json
            
      - name: Check Dependencies
        run: |
          secopsai-npm-monitor \
            --check-lockfile package-lock.json \
            --output dependency-report.json
            
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: |
            sbom-results.json
            dependency-report.json
```

#### GitLab CI

```yaml
security-scan:
  stage: test
  image: secopsai/toolkit:latest
  script:
    - secopsai-sbom-validator --sbom package-lock.json --policy strict
    - secopsai-npm-monitor --check-lockfile package-lock.json
  artifacts:
    reports:
      dependency_scanning: dependency-report.json
```

## Monitoring Setup

### Prometheus Metrics

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'secopsai'
    static_configs:
      - targets: ['localhost:9090']
    metrics_path: /metrics
```

Available metrics:
- `secopsai_alerts_total` - Total alerts by severity
- `secopsai_packages_scanned` - Packages scanned
- `secopsai_threats_detected` - Threats detected by type
- `secopsai_response_time` - Response time histogram

### Grafana Dashboard

Import `monitoring/grafana-dashboard.json` for pre-built dashboards:

- Alert Volume by Severity
- Package Risk Distribution
- Detection Rule Performance
- Incident Response Times

### Alerting Rules

```yaml
# alerting-rules.yml
groups:
  - name: secopsai
    rules:
      - alert: SupplyChainCompromise
        expr: secopsai_threats_detected{type="supply_chain"} > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Supply chain compromise detected"
          
      - alert: HighRiskPackageInstalled
        expr: secopsai_packages_scanned{risk_score > 50} > 0
        for: 5m
        labels:
          severity: high
```

## Incident Response

### Automated Response Levels

| Level | Trigger | Actions |
|-------|---------|---------|
| 1 | CRITICAL alert | Block egress, kill processes, alert SOC |
| 2 | HIGH alert | Quarantine files, isolate container |
| 3 | MEDIUM alert | Log detailed, notify team |
| 4 | LOW alert | Log only, batch for review |

### Response Procedures

#### npm Supply Chain Compromise

```bash
# Step 1: Automated containment
secopsai-response \
  --incident npm-supply-chain-compromise \
  --auto-execute-steps 1,3,4

# Step 2: Manual credential rotation
secopsai-response \
  --incident npm-supply-chain-compromise \
  --step 2 \
  --confirm

# Step 3: Verify cleanup
secopsai-sbom-validator \
  --sbom package-lock.json \
  --policy strict
```

#### Editor Exploit Response

```bash
# Suspend affected user sessions
secopsai-response \
  --incident editor-exploit-compromise \
  --target-user victim@company.com

# Collect forensic evidence
secopsai-response \
  --incident editor-exploit-compromise \
  --step 2

# Remediate
secopsai-harden --vim --emacs
```

## Maintenance

### Daily Tasks

```bash
# Check system health
secopsai-runtime-monitor --status

# Review alerts
tail -100 /var/log/secopsai-runtime-alerts.log | grep CRITICAL

# Update threat intelligence
secopsai-npm-monitor --update-threat-db
```

### Weekly Tasks

```bash
# Update rules
secopsai-update-rules

# Review false positives
secopsai-review-alerts --timeframe 7d

# Audit installed packages
secopsai-npm-monitor --audit-all
```

### Monthly Tasks

```bash
# Full system audit
secopsai-audit --comprehensive --output monthly-audit.pdf

# Update hardening
secopsai-harden --check-updates

# Tabletop exercise
secopsai-response --incident npm-supply-chain-compromise --dry-run
```

### Backup and Recovery

```bash
# Backup configuration
tar czf secopsai-backup-$(date +%Y%m%d).tar.gz \
  /etc/secopsai \
  /var/log/secopsai \
  /opt/secopsai/config

# Restore
sudo tar xzf secopsai-backup-YYYYMMDD.tar.gz -C /
sudo systemctl restart secopsai-monitor
```

## Troubleshooting

### Common Issues

#### High CPU Usage
```bash
# Check monitor interval
secopsai-config set monitoring.interval_seconds 10

# Exclude trusted processes
secopsai-config set monitoring.excluded_processes ["chrome","slack"]
```

#### False Positives
```bash
# Add to whitelist
secopsai-config add whitelist.packages ["internal-package"]

# Adjust rule sensitivity
secopsai-config set rules.sigma.npm_postinstall.severity medium
```

#### Missing Alerts
```bash
# Check service status
sudo systemctl status secopsai-monitor

# Verify webhook
secopsai-test-webhook --url https://hooks.slack.com/...

# Review logs
journalctl -u secopsai-monitor -f
```

## Security Considerations

1. **Principle of Least Privilege**
   - Runtime monitor requires root for process inspection
   - Registry monitor can run as unprivileged user
   - Response playbooks require elevated privileges

2. **Data Protection**
   - Logs may contain sensitive paths
   - Encrypt log storage at rest
   - Restrict log access to security team

3. **Network Security**
   - Outbound connections only to registries
   - Webhook calls use TLS 1.3
   - Proxy support for air-gapped environments

4. **Audit Trail**
   - All actions logged with timestamps
   - Response playbook execution tracked
   - Configuration changes audited

## Support

- Documentation: https://docs.secopsai.io
- Issues: https://github.com/secopsai/toolkit/issues
- Email: support@secopsai.io
- Slack: https://secopsai.slack.com

## License

MIT License - See LICENSE file
