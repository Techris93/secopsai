# Penetration-Test Coordination

SecOpsAI tracks penetration-test engagements with outside testers or internal
red teams: the agreed scope, the authorization, the report and the retest. It
coordinates testing; it does not launch it.

## Record an engagement

```bash
secopsai enterprise workflow pentest --input engagement.json --json
```

```json
{
  "engagement_id": "PT-2026-Q4",
  "title": "External web application test",
  "owner": "security",
  "scope": ["https://app.example.test", "https://api.example.test/v2"],
  "authorized_by": "Statement of work SOW-118, signed 2026-10-02",
  "start_at": "2026-11-03",
  "end_at": "2026-11-14"
}
```

| Field | Rule |
| --- | --- |
| `scope` | Required; at least one entry, up to 200 |
| `authorized_by` | Required; the authorization evidence, such as a signed statement of work |
| `start_at`, `end_at` | Optional test window |

An engagement without scope or authorization is rejected. A new engagement
starts with `status: planned`; saving the same `engagement_id` again updates
it and keeps the previous save as a version.

## Version history

Every save keeps a numbered copy, with the actor and time:

```bash
secopsai enterprise workflow-versions pentest PT-2026-Q4 --json            # list versions
secopsai enterprise workflow-versions pentest PT-2026-Q4 --version 1 --json  # one version in full
```

The API serves the same at `GET /api/v1/enterprise/workflows/pentest/<id>/versions`.

## Quarantine a report

```bash
secopsai enterprise pentest-report submit --engagement-id PT-2026-Q4 --file report.pdf --json
secopsai enterprise pentest-report review --report-id PTR-... --decision accepted --note "Checked scope" --json
```

A report is accepted into quarantine only for an engagement with scope and
authorization on record. SecOpsAI hashes it (SHA-256), copies it to
`data/enterprise/quarantine/<organization>/<sha256>.quarantine` (or
`SECOPSAI_ENTERPRISE_QUARANTINE_DIR`) with owner-only permissions, and never
opens or executes it. Reports are limited to 50 MiB, and submitting the same
file twice returns the existing record. A reviewer then accepts or rejects it,
once; the decision, reviewer and note are recorded.

## Track items through retest

Items are recorded from an accepted report, linked to SecOpsAI findings and
assigned to owners:

```bash
secopsai enterprise pentest-item add --report-id PTR-... --title "Stored XSS in search" \
  --severity high --owner web-team --finding-id OCF-0042 --due-at 2026-12-15 --json
secopsai enterprise pentest-item update --item-id PTI-... --status fixed_pending_retest --json
secopsai enterprise pentest-item update --item-id PTI-... --status retest_passed --note "Verified by tester" --json
secopsai enterprise pentest-show --engagement-id PT-2026-Q4 --json
```

| From | Allowed next status |
| --- | --- |
| `open` | `fixed_pending_retest`, `accepted_risk` |
| `fixed_pending_retest` | `retest_passed`, `retest_failed` |
| `retest_failed` | `fixed_pending_retest`, `accepted_risk` |
| `accepted_risk` | `open` |
| `retest_passed` | none (closed) |

Accepting risk needs the `security_engineer` or `administrator` role. Every
change is kept in the item's history with the actor and time. `pentest-show`
lists the engagement's reports and items and reports `retest_status`:
`complete` when every item has passed retest or has accepted risk.

DAST results for targets in scope can be added through
[Authorized DAST](dast.md).

## Boundaries

SecOpsAI does not test arbitrary targets or send reports to third parties
automatically.
