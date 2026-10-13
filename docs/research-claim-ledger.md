# Research Claim Ledger

The claim ledger is the boundary between evidence and persuasive writing. It
is created from a case summary, analyst brief, or draft and retained with the
case. A publication sentence is not confirmed merely because a model wrote it.

Before verification can mark a claim supported, a registered qualified reviewer
distinct from the author must record `research operation claim-assess`: the exact
statement, archived passage and offsets, provenance, scope, alternatives,
contradictions, limitations and explicit analytic confidence. Shared identifiers,
word overlap and extra references cannot supply that assessment. See
[Research Company Operation](research-company-operation.md) for the complete
review and release contract. Existing ledgers require re-verification under it.

## Claim states

| State | Meaning | Publication treatment |
| --- | --- | --- |
| `supported` | Canonical evidence directly supports the statement | May remain, subject to review |
| `qualified` | The statement is narrowed to what the evidence supports | Revision diff is retained |
| `unsupported` | No linked evidence supports it | Must be removed or qualified |
| `contradicted` | Canonical evidence conflicts with it | Must be removed or corrected |
| `unknown` | Verification is not possible yet | Blocks a factual assertion |

Each entry contains a claim ID, exact text span, claim type, confidence,
evidence IDs, contradicting evidence, extracted numbers/dates/identifiers,
source provenance, limitations, and reviewer state.

## Operator workflow

1. Build the ledger only after the full safe research bundle succeeds.
2. Run **Verify Claims** and inspect every unsupported or contradicted row.
3. Use **Resolve Unsupported Claims** to remove or qualify a sentence. Review
   its revision diff; automatic correction is never an invitation to invent a
   replacement fact.
4. Re-run verification after every draft edit. An edit can invalidate a prior
   support decision.
5. Treat external-source claims, static observations, imported sandbox
   observations, analyst inference, and unknowns as different evidence types.

## Common traps

- A source URL proves where a report came from; it does not prove that the
  source domain is attacker infrastructure.
- A package absent from the local lockfile does not prove that the package is
  benign or that an external incident did not occur.
- A static string is not proof that a process ran. A sandbox claim requires a
  sanitized output passage linked to the exact artifact hash and a current scoped
  experiment. A sandbox record's presence cannot substantiate unrelated claims.
- A hash, CVE, version, date, count, or attribution must match a canonical
  reviewed statement and precise evidence; a matching identifier alone cannot
  support a conclusion about execution, compromise or attacker identity.
- A failed job or empty execution log must remain visible in completeness
  reporting and cannot be summarized as a successful analysis.

## CLI inspection

```bash
secopsai research reliability build-claim-ledger RSC-XXXXXXXXXXXXXXXX --json
secopsai research reliability verify-claims RSC-XXXXXXXXXXXXXXXX --json
secopsai research reliability clip-claims RSC-XXXXXXXXXXXXXXXX --json
```

The resulting revision records explain which claim changed, why it was
unsupported or contradicted, and what evidence remains. Publication safety
uses the effective ledger, so removed claims cannot reappear through an older
draft revision.
