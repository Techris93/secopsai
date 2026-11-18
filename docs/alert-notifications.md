# Alert notifications

| What | When | Where |
| --- | --- | --- |
| Urgent finding | As it happens, even while email is paused | Email to research@secopsai.dev |
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
  firewall already blocks it. A Fast Lane alert in this group is closed
  automatically in Core (owner `automation:ossf-listed`, with the `MAL-`
  advisory ids in the audit log). This is the only automated closure: Core
  accepts it only by signed webhook, for an open alert whose stored package
  version matches exactly.
- **Removed:** the registry no longer serves the version.
- **Needs review:** still published and not listed anywhere. Work these in the
  dashboard inbox (`https://dashboard.secopsai.dev/#research/inbox`).

Everything else stays open for a person, and nothing contacts a registry:
reporting and disclosure stay with a person.

## Urgent findings

The strongest machine signals are emailed at once so a person can review and
publish within minutes: a Fast Lane **critical** verdict (a hijack-shaped
release of a top package, such as a new Python start-up hook that harvests
secrets) and a model triage verdict of **true positive at 90% or more**. They
are rare (0 to 2 a day, 10 to 17 November 2026) and are sent even while
`SECOPSAI_EMAIL_PAUSED` holds every other email; urgent reviews from a
qualified reviewer use the same switch. Each finding is emailed once. Nothing
is published or reported: the email asks a person to review.

`SECOPSAI_URGENT_FINDING_EMAIL` in `fast-lane.yml` and `research-worker.yml`
turns them on (`"1"`) or off (`"0"`).

A Fast Lane urgent email starts with an **auto-check**:

- whether the release is still on the registry (removed or yanked usually
  means someone already reported it);
- whether anything risky is new since the previous release;
- whether the publisher changed;
- whether the start-up/install and flagged files match the project's GitHub
  repository at the release tag (`secopsai/source_match.py`; a hook missing
  from the repository is how a hijacked release usually looks);
- the model's triage verdict.

These lead to one reading: *likely malicious*, *likely benign* or *needs
review*, also shown in the subject. The Fast Lane waits up to
`SECOPSAI_URGENT_VERDICT_WAIT_SECONDS` (default 300, per run) for the verdict
and sends the email without it when time runs out. The auto-check is advice:
it never suppresses the email or closes anything.

## Pause and resume

```bash
gh variable set SECOPSAI_EMAIL_PAUSED --body true    # pause every notification email
gh variable set SECOPSAI_EMAIL_PAUSED --body false   # resume
```

While paused, alerts still reach Core and the dashboard, digest entries are
still recorded, and the daily digest is written to the workflow run summary
instead of being sent. Approved disclosures to registries are not affected.
