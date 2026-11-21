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
it.

## Reports and retests

Store the tester's report as evidence through `POST /api/v1/enterprise/evidence`
(see [GRC Evidence](grc-evidence.md)), with the engagement ID in its metadata.
SecOpsAI records the report's SHA-256, so any later change to it is
detectable. DAST results for targets in scope can be added through
[Authorized DAST](dast.md).

Report quarantine, linking report items to findings, owner assignment and
retest tracking are not automated yet; track them in the engagement record and
your ticketing system.

## Boundaries

SecOpsAI does not test arbitrary targets or send reports to third parties
automatically.
