# Kubernetes Security

SecOpsAI checks Kubernetes manifests before they reach a cluster and
normalizes Kubernetes audit events once they do. Both are deterministic and
read-only: SecOpsAI never applies, patches or deletes cluster objects.

## Scan a manifest

```bash
secopsai enterprise kubernetes-scan --path deployment.yaml --json
```

The file may hold several YAML documents. YAML needs PyYAML; JSON manifests
work without it. Files over 2 MiB are rejected.

## Checks

| Rule | Severity | Flags |
| --- | --- | --- |
| `K8S-PRIVILEGED-CONTAINER` | critical | A container with `securityContext.privileged: true` |
| `K8S-CLUSTER-ADMIN` | critical | A `ClusterRoleBinding` or `RoleBinding` to `cluster-admin` |
| `K8S-HOST-NETWORK` | high | `hostNetwork: true` |
| `K8S-HOST-NAMESPACE` | high | `hostPID` or `hostIPC: true` |
| `K8S-PRIVILEGE-ESCALATION` | high | `allowPrivilegeEscalation: true` |
| `K8S-HOSTPATH` | high | A `hostPath` volume (the finding names the volume and path) |
| `K8S-UNPINNED-IMAGE` | medium | An image with no tag or the `latest` tag |
| `K8S-EGRESS-UNDEFINED` | medium | A `NetworkPolicy` with no egress rules |

Container checks cover `containers`, `initContainers` and
`ephemeralContainers`, in bare pods and in workload templates.

## Output

The result names the file, its SHA-256 and every finding with its rule,
severity, message, location (`file#index:kind/name`) and evidence. It also
gives a dry-run admission decision:

- `admission: deny` when any finding is critical or high
- `admission: allow` otherwise
- `mode: dry_run` and `mutation_performed: false` always

Use the decision as a CI gate or a review prompt. Nothing is enforced in the
cluster.

## Audit events

Kubernetes audit events are ingested through the `kubernetes.audit` connector
(see [Cloud Connectors](cloud-connectors.md)). Each event records the user and
groups, the object (resource, namespace, name, API group) and an event type
such as `kubernetes.delete.secrets`. Create, delete, patch and update on
cluster roles, role bindings, secrets, pods and deployments are marked `high`.

## What is never automated

Admission policy, workload changes, secret rotation and network-policy changes
are proposals for an operator. SecOpsAI does not perform them.
