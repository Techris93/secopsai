# GRC Evidence

SecOpsAI keeps a register of compliance controls and the evidence behind them,
linked to the findings and workflows that produced it. It manages evidence; it
does not certify an organization or replace an auditor.

## Frameworks

| ID | Framework |
| --- | --- |
| `soc2` | SOC 2 |
| `iso27001` | ISO/IEC 27001 |
| `iso42001` | ISO/IEC 42001 (AI management) |
| `hipaa` | HIPAA |
| `nist-csf` | NIST Cybersecurity Framework |
| `cis` | CIS Controls |
| `nis2` | NIS2 |

## Create or update a control

```bash
secopsai enterprise control --control-id AC-1 --framework soc2 \
  --title "Access review" --owner security --status not_started --json
```

- `--control-id`: letters, digits and `. _ : -`, up to 120 characters
- `--status`: defaults to `not_started`
- running the command again with the same control ID updates the record

## Evidence records

Record evidence against a control through the Core API:

```http
POST /api/v1/enterprise/evidence
{
  "control_id": "AC-1",
  "source": "Quarterly access review export, 2026-Q4",
  "evidence_type": "report",
  "content": "...",
  "expires_at": "2027-03-31",
  "reviewer": "security-lead"
}
```

| Field | Meaning |
| --- | --- |
| `control_id` | The control the evidence supports |
| `source` | Where the evidence came from (a report, export or finding) |
| `evidence_type` | A type you set; `other` if omitted |
| `content` or `metadata` | The evidence itself, up to 256 KiB, with credential-shaped fields redacted |
| `sha256` | Computed from the content unless you supply it, so later changes are detectable |
| `collected_at` | Set to the time of recording unless supplied |
| `expires_at` | When the evidence must be refreshed |
| `reviewer` | Who reviews it |
| `status` | `pending_review` unless supplied |

## Who can write

Control and evidence writes need a governance role: `operator`,
`security_engineer`, `administrator`, `auditor`, `reviewer` or
`intelligence_operator`. Analysts can read but not change the register. Every
record is scoped to one organization ID.

## Boundaries

This is evidence management and control mapping. SecOpsAI does not issue
attestations, mark a control as compliant on its own, or replace an auditor's
or compliance platform's control assessment.
