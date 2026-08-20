# Kubernetes Security

Kubernetes manifest checks and audit normalization are deterministic and
read-only. Run a dry-run posture check with:

```bash
secopsai enterprise kubernetes-scan --path deployment.yaml --json
```

Checks include privileged containers, host namespaces, hostPath mounts,
privilege escalation, unpinned images, cluster-admin bindings, and undefined
egress policy. Kubernetes audit events cover suspicious workload, secret, RBAC,
and admission changes.

Admission policy, workload mutation, secret rotation, and network-policy
changes are not performed automatically.
