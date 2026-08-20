# GRC Evidence

Enterprise controls can be mapped to SOC 2, ISO 27001, ISO 42001, HIPAA, NIST
CSF, CIS, and NIS2. Evidence records include source, SHA-256, collection time,
reviewer, status, and expiry.

```bash
secopsai enterprise control --control-id AC-1 --framework soc2 \
  --title "Access review" --owner security --json
```

This provides evidence management and control mapping. It does not certify an
organization or replace an auditor/Vanta-style control assessment.
