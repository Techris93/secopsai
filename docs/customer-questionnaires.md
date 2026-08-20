# Customer Questionnaires And RFPs

Questionnaire records are versioned, evidence-linked drafts. Answers must be
reviewed before export or delivery; the system never sends customer responses
automatically.

Use the enterprise workflow CLI with a JSON questionnaire record:

```bash
secopsai enterprise workflow questionnaire --input questionnaire.json --json
```

Do not place customer secrets, private telemetry, or internal credentials in
answers or evidence references.
