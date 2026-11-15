# Alert notifications

| What | When | Where |
| --- | --- | --- |
| Critical alert | As it happens | Email to research@secopsai.dev |
| Every other alert | Once a day, 07:15 UTC | One digest email |
| Every alert | As it happens | Core and the dashboard inbox |

The policy is in `secopsai/notification_policy.py`; the Fast Lane and the
research worker both use it. Alerts that are not emailed are stored in the
ledger store (`digest/<day>/`) and `scripts/alert_digest.py` sends them as one
email (workflow `alert-digest.yml`).

## Automated triage in the digest

Each package alert is checked without downloading the package:

- **Known malicious:** ossf/malicious-packages lists the version; the install
  firewall already blocks it.
- **Removed:** the registry no longer serves the version.
- **Needs review:** still published and not listed anywhere. Work these in the
  dashboard inbox (`https://dashboard.secopsai.dev/#research/inbox`).

The digest never resolves an alert or contacts a registry: closing alerts and
disclosure stay with a person.

## Pause and resume

```bash
gh variable set SECOPSAI_EMAIL_PAUSED --body true    # pause every notification email
gh variable set SECOPSAI_EMAIL_PAUSED --body false   # resume
```

While paused, alerts still reach Core and the dashboard, digest entries are
still recorded, and the daily digest is written to the workflow run summary
instead of being sent. Approved disclosures to registries are not affected.
