# Customer Questionnaires And RFPs

Security questionnaires and RFP answers are stored as drafts linked to
evidence. SecOpsAI never sends an answer to a customer: every response is
reviewed and delivered by a person.

## Save a questionnaire

```bash
secopsai enterprise workflow questionnaire --input questionnaire.json --json
```

```json
{
  "questionnaire_id": "Q-2026-ACME",
  "title": "Acme vendor security review",
  "owner": "security",
  "customer": "Acme Corp",
  "questions": [
    {
      "question_id": "DP-1",
      "question": "Is customer data encrypted at rest?",
      "answer": "Yes. See control SC-28 and the attached encryption evidence.",
      "evidence_refs": ["CTRL-SC-28", "EVID-0042"],
      "status": "draft"
    }
  ]
}
```

| Field | Limit |
| --- | --- |
| Questions per questionnaire | 2,000 |
| `question_id` (or `id`) | Required, 160 characters |
| `question` | 2,000 characters |
| `answer` | 10,000 characters |
| `evidence_refs` | 20 references per answer |

Saving the same `questionnaire_id` again replaces the stored record; earlier
versions are not kept, so export one before a major revision if you need it. The questionnaire's status
is always stored as `draft`; each answer keeps its own status for review
tracking.

## Linking evidence

Use `evidence_refs` to point at control IDs and evidence records from
[GRC Evidence](grc-evidence.md), so a reviewer can check each claim against
its source before the answer goes out.

## What not to include

Do not put customer secrets, private telemetry or internal credentials in
answers or evidence references. Answers are meant to be shared outside the
organization.
