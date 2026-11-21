# Authorized DAST

SecOpsAI coordinates dynamic application security testing (DAST) only against
targets you own and have authorized. It validates the target, builds the
scanner command and normalizes the results. It does not start a scan by
itself.

## Validate a target

```bash
secopsai enterprise dast-validate \
  --target-id web-1 \
  --url https://app.example.test \
  --owner security \
  --authorized-by change-123 \
  --mode passive --json
```

A target is accepted only when:

- the URL is an explicit `https://` URL with a host name
- it has a target ID, an owner and authorization evidence (`--authorized-by`,
  for example a change ticket)

The output repeats the target, shows the scanner command and reports
`execution: not_started`.

## Passive and active modes

| Mode | Default | Requirement | Command |
| --- | --- | --- | --- |
| `passive` | yes | A validated target | OWASP ZAP quick scan with `-scantime 1` |
| `active` | no | `--active-approved` as well | OWASP ZAP quick scan |

The command is an argument list, never a shell string. An allowlisted runner
decides whether and when to execute it.

## Scope

When a target has a scope, a requested URL must use HTTPS, the same host, and a
path under one of the scope prefixes. Without a scope, only the target's own
path and paths below it are in scope. SecOpsAI never follows links outside the
approved scope or scans arbitrary external targets.

## Results

Scanner output in SARIF (up to 10 MiB) becomes target-linked findings:

- severity: SARIF `error` → critical, `warning` → medium, anything else → low
- a stable ID (`DAST-` plus a hash of target, rule and location), so the same
  issue maps to the same finding across runs
- title, message, up to 20 locations and remediation text from the rule

Repeated observations of the same target, rule and location from DAST, SAST
or SCA merge into one finding, keeping the highest severity and up to 20
evidence references. Raw request and response bodies, which can hold secrets,
are not stored.
