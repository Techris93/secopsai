# Implementation Checkpoints

## 083 Research job foundation

Status: complete locally.

Added durable `research_jobs` records, idempotency keys, lifecycle states, safe error fields, case timeline events, and CLI inspection. The local helper can invoke typed research actions; it does not expose arbitrary shell execution.

## 084 Safe package intake

Status: complete locally.

Added official-registry adapters for npm, PyPI, NuGet, Maven, RubyGems, Packagist, Go, and Open VSX. Intake uses quarantine, hashes, bounded in-memory archive inspection, manifest/lifecycle detection, and static indicators. Preview jobs remain unattached until the operator explicitly attaches verified evidence.

## 085-088 Research gates

Status: complete locally.

Added evidence matrices, human verdicts, disclosure drafts/status, publication safety reviews, waivers, and publication approval records. Existing Blog Ops remains the final editing and publish surface.

## 089 Sandbox control plane

Status: complete as a safe control plane; provider activation remains external.

Added request, approval, status, and sanitized-result records. The default provider is manual result import. A dedicated isolated execution provider still requires separate infrastructure and credentials; Core will not execute investigated packages locally.

## Verification

- Core virtualenv suite: 265 passed, 13 warnings, 4 subtests passed.
- New intake/workflow suite: 6 passed.
- Dashboard research automation suite: 3 passed.
- Dashboard JavaScript and Worker syntax checks: passed.
- Dashboard repository has no `build` script; its supported deployment is static Pages/Worker serving and is validated with `npm run check` plus Cloudflare deployment checks.
