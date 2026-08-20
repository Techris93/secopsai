# Authorized DAST

DAST targets require an HTTPS URL, an owner, and explicit authorization
evidence. Passive validation is the default. Active scanning requires a
separate approval flag and an allowlisted runner.

```bash
secopsai enterprise dast-validate \
  --target-id web-1 \
  --url https://app.example.test \
  --owner security \
  --authorized-by change-123 \
  --mode passive --json
```

SARIF results can be normalized into target-linked findings. SecOpsAI never
scans arbitrary external targets, follows unapproved scope, or stores raw
request/response secrets.
