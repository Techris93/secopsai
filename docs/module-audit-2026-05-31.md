# SecOpsAI Module Audit - 2026-05-31

This audit maps the repository modules by responsibility and records cleanup
decisions. The goal is to remove real duplication while preserving documented
entry points and compatibility shims.

## Core Runtime

| Area | Files | Responsibility | Cleanup decision |
| --- | --- | --- | --- |
| Packaged CLI | `secopsai/cli.py`, `cli.py` | Main `secopsai` command and repository-local wrapper. | Kept both. `cli.py` is intentionally a tiny wrapper for local `python cli.py` usage. |
| Pipeline | `secopsai/pipeline.py`, `detect.py`, `correlation.py`, `findings.py`, `soc_store.py` | Refresh, detect, correlate, and persist findings. | Kept. Top-level modules remain imported by the packaged CLI and tests. |
| Triage | `secopsai/triage/*` | Finding lifecycle, disposition, queue, reporting, and orchestration. | Kept. Responsibilities are split by domain, not duplicate implementations. |
| Supply chain | `secopsai/supply_chain.py`, `data/advisories/*`, `config/supply_chain_policy.example.toml` | Registry/advisory/package analysis and campaign discovery. | Kept. The older `supply-chain/` directory is the npm-distributed wrapper, not a replacement for this module. |
| Blog Ops | `secopsai/blog.py`, `blog/*` | Draft/review/publish/rebuild blog content and feeds. | Kept. Runtime code and generated/static blog assets are separate concerns. |
| Threat intel | `secopsai/intel.py`, `threat_intel_ingestor.py`, `threat_intel/*`, `blog/data/news-sources.json` | IOC refresh, source ingestion, and campaign/news sources. | Kept. There is overlap in vocabulary, but `secopsai/intel.py` is CLI/runtime, while `threat_intel_ingestor.py` is a standalone ingestion workflow. |
| Research and sessions | `secopsai/research.py`, `secopsai/sessions.py`, `secopsai/agent_core.py` | Analyst reports, session records, approvals, and isolated agent jobs. | Kept. No duplicate state writer was removed because all are referenced by tests/CLI. |
| Adaptive response | `secopsai/adaptive_response.py`, `adaptive_*`, `auto_rules/*` | Adaptive scoring, memory, rule generation, and validation. | Kept. Root-level adaptive scripts are documented standalone workflows. |
| OpenClaw adapters | `adapters/*`, `openclaw_adapters/*`, `openclaw_*` | Platform/event adapters and OpenClaw-native ingestion. | Kept. Adapter interfaces intentionally share method names (`collect`, `stream`, `normalize`). |
| Reports/rendering | `secopsai/report_renderers.py`, `scripts/secopsai_report_snapshot.py`, `scripts/secopsai_render_report.py` | Snapshot and render operator reports. | Kept. Snapshot collection and renderer implementation are separate. |
| Evaluation | `prepare.py`, `evaluate.py`, `evaluate_openclaw.py`, `eval/*`, `scripts/autoresearch_*` | Regression data generation, scoring, and tuning. | Kept. These are still referenced by docs and tests. |

## Cleanup Applied

- Removed `setup.py`. It duplicated `pyproject.toml` with stale package metadata
  (`version="0.0.0"` while `pyproject.toml` is the authoritative package
  metadata). Modern editable installs use `pyproject.toml`.
- Removed missing `config` from `pyproject.toml` `py-modules`. There is no
  tracked `config.py`, so advertising it created packaging noise.

## Intentional Overlaps Not Removed

- `cli.py` and `secopsai/cli.py`: local wrapper versus packaged CLI.
- `supply-chain/` and `secopsai/supply_chain.py`: npm wrapper/distribution
  package versus Python-native scanner/orchestrator.
- `adapters/*` and `openclaw_adapters/*`: platform collectors versus OpenClaw
  event normalizers.
- `blog/` and `secopsai/blog.py`: static/output assets versus CLI workflow
  implementation.
- `docs/`, `www/`, and `blog/` icon/favicon assets: duplicated deploy targets
  for separate sites, not import-time code duplication.

## Follow-Up Candidates

- `secopsai/supply_chain.py` and `secopsai/blog.py` are large modules. They are
  not duplicate modules, but future refactors could split them into smaller
  parser, policy, and command-service files.
- Root-level OpenClaw scripts are still documented public workflows. If the CLI
  eventually replaces all direct script usage, move them under `scripts/` with
  compatibility wrappers in a separate migration.
