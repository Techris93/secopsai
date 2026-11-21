# Threat Modeling

Threat models record a system's assets, the threats to them and the planned
mitigations, linked to SecOpsAI findings and research cases as evidence.
STRIDE is the method: spoofing, tampering, repudiation, information
disclosure, denial of service and elevation of privilege.

## Save a threat model

```bash
secopsai enterprise workflow threat-model --input threat-model.json --json
```

```json
{
  "threat_model_id": "TM-payments-api",
  "title": "Payments API",
  "owner": "platform-security",
  "assets": [
    {"id": "A1", "name": "Card tokens", "trust_boundary": "internal"}
  ],
  "threats": [
    {"id": "T1", "category": "information_disclosure", "asset": "A1",
     "description": "Token export through a compromised dependency",
     "evidence": ["CAN-0193", "OCF-0021"]}
  ],
  "mitigations": [
    {"id": "M1", "threat": "T1", "control": "Pin and verify dependencies",
     "owner": "platform", "status": "proposed"}
  ]
}
```

`threat_model_id`, `title` and `owner` identify the model. `assets`, `threats`
and `mitigations` are lists of objects with up to 500 entries each; their
fields are yours to define, so the record fits your existing template. Saving
the same ID again updates the model and keeps the previous save as a version.

Every saved model has `method: stride` and `status: draft` until a reviewer
moves it on.

## Version history

Every save keeps a numbered copy, with the actor and time:

```bash
secopsai enterprise workflow-versions threat-model TM-payments-api --json            # list versions
secopsai enterprise workflow-versions threat-model TM-payments-api --version 1 --json  # one version in full
```

The API serves the same at `GET /api/v1/enterprise/workflows/threat-model/<id>/versions`.

## Review

Model-generated suggestions remain proposals. A reviewer accepts threats,
mitigations and residual-risk decisions. SecOpsAI does not mark a threat as
mitigated on its own.
