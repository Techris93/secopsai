# Developer Security Awareness

SecOpsAI turns reviewed findings into targeted security training suggestions:
when findings show a pattern, it recommends the matching module and links the
findings that triggered it.

## Generate recommendations

```bash
secopsai enterprise awareness --input findings.json --json
```

The input is a JSON array of findings, each with a `finding_id` and a `title`
or `summary`. Export reviewed findings first; recommendations should come from
confirmed issues, not raw alerts.

## Modules

| Module | Recommended when findings mention | Focus |
| --- | --- | --- |
| `dependency-safety` | package, supply, dependency, slopsquat | Verifying AI-suggested and newly registered packages before installing |
| `credential-hygiene` | credential, token, secret, harvest | Spotting credential-file access and rotating affected secrets |
| `cloud-identity` | cloud, IAM, AWS, GCP, service account | Least-privilege cloud identities and suspicious token use |
| `kubernetes-posture` | Kubernetes, k8s, container, RBAC, privileged | Avoiding privileged workloads, broad RBAC and unpinned images |
| `secure-ci` | CI, pipeline, SAST, supply-chain | SAST, SCA, secrets scanning, SBOMs and protected release gates |

## Output

Each recommendation lists the module, its focus, the reason and up to 50
linked finding IDs, with `status: recommended`:

```json
{
  "module_id": "dependency-safety",
  "title": "Verify AI-suggested and newly registered packages before installation.",
  "reason": "Linked to reviewed SecOpsAI findings.",
  "finding_ids": ["CAN-0193", "CAN-0201"],
  "status": "recommended"
}
```

## Boundaries

Recommendations are about practices, not people: findings are not attributed
to individual developers. A future learning-management adapter may record
completion, but training records and security findings stay separate from
employment decisions.
