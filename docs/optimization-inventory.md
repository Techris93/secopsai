# SecOpsAI Optimization Inventory

Generated during the May 2026 optimization pass.

## Fixed In This Pass

- Supply-chain advisories: Added a signature-aware advisory cache and package index so repeated advisory checks do not repeatedly parse every advisory JSON file. The cache is invalidated when advisory files change or when an advisory is ingested.
- CLI status: Added `secopsai status` as a stable operator entrypoint for the canonical repo/intel/OpenClaw/SOC/adaptive snapshot that previously required calling the reporting script directly.
- Blog verification: Extended `scripts/verify_blog.py` so the blog verifier confirms the news source registry includes direct government/vendor/project sources and does not silently regress into a single-source feed.
- CI hardening: Added the Node 24 migration environment flag to the standalone security-scan workflow to reduce action-runtime drift warnings.

## Safe Deferred Work

- Detection engine profiling: Run timing against representative large replay files before changing detection loops or rule behavior.
- OpenClaw replay streaming: The reporting snapshot still reads replay JSON arrays whole; convert to a streaming reader only after confirming all supported replay formats and fixtures.
- Full CLI refactor: `secopsai/cli.py` remains large. Split command handlers only with a dedicated compatibility test pass because many docs and workflows depend on current command names and output.
- Agent job policy: The local job allowlist can be made stricter, but should be changed alongside operator docs because it affects approved experiment workflows.

## Verification Expectations

Run the normal CI-equivalent checks after optimization changes:

```bash
python3 scripts/verify_blog.py
python3 scripts/verify_docs_examples.py
node --check blog/_worker.js
node --check blog/functions/api/comments.js
node --check blog/assets/blog.js
node --check blog/assets/comments.js
git diff --check
.venv/bin/python -m pytest -q
```
