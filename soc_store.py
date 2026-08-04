"""
Local findings store for OpenClaw and future SOC workflows.

This module provides a minimal SQLite-backed persistence layer for findings,
event mappings, and analyst notes while preserving analyst state across
regeneration runs.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def default_db_path() -> str:
    findings_dir = os.environ.get("SECOPS_FINDINGS_DIR")
    if findings_dir:
        return os.path.join(os.path.abspath(findings_dir), "openclaw_soc.db")
    return os.path.join(ROOT_DIR, "data", "openclaw", "findings", "openclaw_soc.db")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def connect(db_path: str | None = None) -> sqlite3.Connection:
    resolved_path = db_path or default_db_path()
    directory = os.path.dirname(resolved_path)
    os.makedirs(directory, exist_ok=True)
    try:
        os.chmod(directory, 0o700)  # nosec B103  # nosem
    except OSError:
        pass

    connection = sqlite3.connect(resolved_path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")
    try:
        os.chmod(resolved_path, 0o600)  # nosec B103
    except OSError:
        pass
    return connection


def _ensure_column(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db(db_path: str | None = None) -> None:
    with closing(connect(db_path)) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                severity TEXT NOT NULL,
                severity_score INTEGER NOT NULL,
                status TEXT NOT NULL,
                disposition TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS finding_events (
                finding_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY (finding_id, event_id),
                FOREIGN KEY (finding_id) REFERENCES findings (finding_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS notes (
                note_id INTEGER PRIMARY KEY AUTOINCREMENT,
                finding_id TEXT NOT NULL,
                author TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (finding_id) REFERENCES findings (finding_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_findings_status_severity_first_seen
                ON findings (status, severity_score DESC, first_seen ASC);
            CREATE INDEX IF NOT EXISTS idx_findings_severity_score_first_seen
                ON findings (severity, severity_score DESC, first_seen ASC);
            CREATE INDEX IF NOT EXISTS idx_findings_source
                ON findings (source);
            CREATE INDEX IF NOT EXISTS idx_findings_last_seen
                ON findings (last_seen);
            CREATE INDEX IF NOT EXISTS idx_notes_finding_note
                ON notes (finding_id, note_id);

            CREATE TABLE IF NOT EXISTS asset_graph_nodes (
                node_id TEXT PRIMARY KEY,
                node_type TEXT NOT NULL,
                label TEXT NOT NULL,
                source TEXT NOT NULL,
                source_id TEXT,
                properties_json TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS asset_graph_edges (
                edge_id TEXT PRIMARY KEY,
                edge_type TEXT NOT NULL,
                from_node_id TEXT NOT NULL,
                to_node_id TEXT NOT NULL,
                source TEXT NOT NULL,
                properties_json TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS edge_sync_state (
                source_instance TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                cursor_json TEXT NOT NULL,
                bundle_exported_at TEXT,
                last_synced_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS core_api_audit_logs (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                action TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                result TEXT NOT NULL,
                source_instance TEXT,
                details_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_asset_graph_nodes_type_label
                ON asset_graph_nodes (node_type, label);
            CREATE INDEX IF NOT EXISTS idx_asset_graph_nodes_source_id
                ON asset_graph_nodes (source, source_id);
            CREATE INDEX IF NOT EXISTS idx_asset_graph_edges_type_from
                ON asset_graph_edges (edge_type, from_node_id);
            CREATE INDEX IF NOT EXISTS idx_asset_graph_edges_to
                ON asset_graph_edges (to_node_id);
            CREATE INDEX IF NOT EXISTS idx_core_api_audit_time
                ON core_api_audit_logs (occurred_at DESC, audit_id DESC);

            CREATE TABLE IF NOT EXISTS intelligence_jobs (
                job_id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                target_id TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                attempt INTEGER NOT NULL DEFAULT 0,
                provider TEXT NOT NULL DEFAULT '',
                queued_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                updated_at TEXT NOT NULL,
                error_code TEXT,
                error_message TEXT,
                input_json TEXT NOT NULL,
                result_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS intelligence_job_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                message TEXT NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (job_id) REFERENCES intelligence_jobs (job_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_intelligence_jobs_status_queued
                ON intelligence_jobs (status, queued_at, job_id);
            CREATE INDEX IF NOT EXISTS idx_intelligence_jobs_updated
                ON intelligence_jobs (updated_at DESC, job_id DESC);
            CREATE INDEX IF NOT EXISTS idx_intelligence_job_events_job
                ON intelligence_job_events (job_id, event_id);

            CREATE TABLE IF NOT EXISTS agent_triage_settings (
                settings_id INTEGER PRIMARY KEY CHECK (settings_id = 1),
                mode TEXT NOT NULL,
                selected_model TEXT NOT NULL,
                poll_interval_seconds INTEGER NOT NULL,
                min_auto_close_confidence INTEGER NOT NULL,
                min_evidence_refs INTEGER NOT NULL,
                max_records_per_cycle INTEGER NOT NULL,
                auto_create_tuning_proposals INTEGER NOT NULL,
                auto_activate_tuning INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS agent_triage_runs (
                run_id TEXT PRIMARY KEY,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL,
                intelligence_job_id TEXT,
                selected_model TEXT NOT NULL,
                provider TEXT NOT NULL,
                deterministic_json TEXT NOT NULL,
                recommendation_json TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                final_action TEXT NOT NULL,
                reversible INTEGER NOT NULL DEFAULT 1,
                rollback_json TEXT NOT NULL,
                error_code TEXT,
                error_message TEXT,
                queued_at TEXT NOT NULL,
                completed_at TEXT,
                updated_at TEXT NOT NULL,
                UNIQUE (target_type, target_id, target_fingerprint),
                FOREIGN KEY (intelligence_job_id) REFERENCES intelligence_jobs (job_id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS investigation_autopilot_settings (
                settings_id INTEGER PRIMARY KEY CHECK (settings_id = 1),
                mode TEXT NOT NULL,
                minimum_severity TEXT NOT NULL,
                max_active_runs INTEGER NOT NULL,
                max_attempts INTEGER NOT NULL,
                auto_start_pipeline INTEGER NOT NULL,
                auto_extract_iocs INTEGER NOT NULL,
                auto_correlate INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS investigation_autopilot_runs (
                run_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                finding_fingerprint TEXT NOT NULL,
                case_id TEXT,
                pipeline_id TEXT,
                status TEXT NOT NULL,
                current_stage TEXT NOT NULL,
                last_successful_stage TEXT NOT NULL,
                attempt INTEGER NOT NULL DEFAULT 0,
                evidence_summary_json TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                blocker_code TEXT,
                blocker_message TEXT,
                retryable INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                updated_at TEXT NOT NULL,
                UNIQUE (finding_id, finding_fingerprint),
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE SET NULL,
                FOREIGN KEY (pipeline_id) REFERENCES research_pipeline_runs (pipeline_id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS idx_investigation_autopilot_status_updated
                ON investigation_autopilot_runs (status, updated_at DESC);

            CREATE TABLE IF NOT EXISTS detection_tuning_proposals (
                proposal_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT NOT NULL,
                change_type TEXT NOT NULL,
                proposed_value_json TEXT NOT NULL,
                rationale TEXT NOT NULL,
                expected_effect TEXT NOT NULL,
                status TEXT NOT NULL,
                shadow_metrics_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                applied_at TEXT,
                applied_by TEXT,
                FOREIGN KEY (run_id) REFERENCES agent_triage_runs (run_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_agent_triage_runs_status_updated
                ON agent_triage_runs (status, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_agent_triage_runs_target
                ON agent_triage_runs (target_type, target_id, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_detection_tuning_status
                ON detection_tuning_proposals (status, updated_at DESC);

            CREATE TABLE IF NOT EXISTS detection_learning_settings (
                settings_id INTEGER PRIMARY KEY CHECK (settings_id = 1),
                mode TEXT NOT NULL,
                minimum_examples INTEGER NOT NULL,
                holdout_percent INTEGER NOT NULL,
                maximum_false_negative_regression INTEGER NOT NULL,
                minimum_precision REAL NOT NULL,
                canary_percent INTEGER NOT NULL,
                auto_promote_shadow INTEGER NOT NULL,
                auto_promote_canary INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS detection_learning_examples (
                example_id TEXT PRIMARY KEY,
                organization_key TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                case_id TEXT,
                label TEXT NOT NULL,
                label_source TEXT NOT NULL,
                trust_score INTEGER NOT NULL,
                feature_version TEXT NOT NULL,
                features_json TEXT NOT NULL,
                split TEXT NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (organization_key, finding_id, feature_version)
            );

            CREATE TABLE IF NOT EXISTS detection_learning_feedback (
                feedback_id TEXT PRIMARY KEY,
                organization_key TEXT NOT NULL,
                subject_key TEXT NOT NULL,
                finding_id TEXT,
                event_id TEXT,
                outcome TEXT NOT NULL,
                learning_label TEXT,
                label_source TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                trust_score INTEGER NOT NULL,
                feature_version TEXT NOT NULL,
                features_json TEXT NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                actor TEXT NOT NULL,
                dedupe_key TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS detection_learning_datasets (
                dataset_id TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                feature_version TEXT NOT NULL,
                fingerprint TEXT NOT NULL UNIQUE,
                example_count INTEGER NOT NULL,
                label_counts_json TEXT NOT NULL,
                split_counts_json TEXT NOT NULL,
                source_policy_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS detection_learning_experiments (
                experiment_id TEXT PRIMARY KEY,
                dataset_id TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                status TEXT NOT NULL,
                model_json TEXT NOT NULL,
                metrics_json TEXT NOT NULL,
                guardrails_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (dataset_id) REFERENCES detection_learning_datasets (dataset_id)
            );

            CREATE TABLE IF NOT EXISTS detection_learning_proposals (
                proposal_id TEXT PRIMARY KEY,
                experiment_id TEXT NOT NULL,
                proposal_type TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                parameters_json TEXT NOT NULL,
                replay_metrics_json TEXT NOT NULL,
                rollback_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                activated_at TEXT,
                FOREIGN KEY (experiment_id) REFERENCES detection_learning_experiments (experiment_id)
            );

            CREATE TABLE IF NOT EXISTS detection_learning_deployments (
                deployment_id TEXT PRIMARY KEY,
                proposal_id TEXT NOT NULL,
                stage TEXT NOT NULL,
                traffic_percent INTEGER NOT NULL,
                status TEXT NOT NULL,
                observations_json TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (proposal_id) REFERENCES detection_learning_proposals (proposal_id)
            );

            CREATE TABLE IF NOT EXISTS detection_learning_bandit_actions (
                action_name TEXT PRIMARY KEY,
                pulls INTEGER NOT NULL,
                reward_sum REAL NOT NULL,
                reward_squared_sum REAL NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS daily_automation_settings (
                settings_id INTEGER PRIMARY KEY CHECK (settings_id = 1),
                enabled INTEGER NOT NULL DEFAULT 1,
                interval_seconds INTEGER NOT NULL DEFAULT 86400,
                max_alert_reviews INTEGER NOT NULL DEFAULT 25,
                max_investigations INTEGER NOT NULL DEFAULT 5,
                max_candidate_cases INTEGER NOT NULL DEFAULT 25,
                auto_promote_candidates INTEGER NOT NULL DEFAULT 1,
                run_learning INTEGER NOT NULL DEFAULT 1,
                last_run_at TEXT,
                next_run_at TEXT,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS daily_automation_runs (
                run_id TEXT PRIMARY KEY,
                trigger TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                next_run_at TEXT,
                summary_json TEXT NOT NULL,
                error_message TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS daily_automation_steps (
                step_id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL,
                step_name TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                result_json TEXT NOT NULL,
                error_message TEXT,
                FOREIGN KEY (run_id) REFERENCES daily_automation_runs (run_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_daily_automation_runs_status_time
                ON daily_automation_runs (status, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_daily_automation_steps_run_time
                ON daily_automation_steps (run_id, step_id);

            CREATE INDEX IF NOT EXISTS idx_detection_learning_examples_split
                ON detection_learning_examples (organization_key, split, label);
            CREATE INDEX IF NOT EXISTS idx_detection_learning_feedback_subject
                ON detection_learning_feedback (organization_key, subject_key, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_detection_learning_feedback_outcome
                ON detection_learning_feedback (organization_key, outcome, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_detection_learning_proposals_status
                ON detection_learning_proposals (status, updated_at DESC);

            CREATE TABLE IF NOT EXISTS research_resolution_settings (
                settings_id INTEGER PRIMARY KEY CHECK (settings_id = 1),
                mode TEXT NOT NULL,
                min_confidence INTEGER NOT NULL,
                min_evidence_refs INTEGER NOT NULL,
                max_cases_per_cycle INTEGER NOT NULL,
                auto_retract_rules INTEGER NOT NULL,
                updated_at TEXT NOT NULL,
                updated_by TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS research_resolution_runs (
                run_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                pipeline_id TEXT NOT NULL,
                case_fingerprint TEXT NOT NULL,
                status TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                decision_json TEXT NOT NULL,
                rollback_json TEXT NOT NULL,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                reviewed_at TEXT,
                reviewed_by TEXT,
                UNIQUE (case_id, case_fingerprint),
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_research_resolution_status
                ON research_resolution_runs (status, updated_at DESC);

            CREATE TABLE IF NOT EXISTS research_cases (
                case_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                case_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                status TEXT NOT NULL,
                owner TEXT NOT NULL,
                disclosure_status TEXT NOT NULL,
                embargo_until TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                closed_at TEXT,
                published_at TEXT,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS research_subjects (
                subject_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                subject_type TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                publisher TEXT NOT NULL,
                status TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (case_id, subject_type, ecosystem, name, version),
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_artifacts (
                artifact_id TEXT PRIMARY KEY,
                sha256 TEXT NOT NULL UNIQUE,
                filename TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                package_name TEXT NOT NULL,
                version TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                quarantine_path TEXT NOT NULL,
                state TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                analysis_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS research_case_artifacts (
                case_id TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (case_id, artifact_id),
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE,
                FOREIGN KEY (artifact_id) REFERENCES research_artifacts (artifact_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_ioc_candidates (
                candidate_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                reason TEXT NOT NULL,
                source_evidence_id TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                reviewed_at TEXT,
                reviewed_by TEXT,
                UNIQUE (case_id, ioc_type, value),
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE,
                FOREIGN KEY (source_evidence_id) REFERENCES research_evidence (evidence_id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS research_partner_requests (
                request_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                subject_id TEXT,
                requested_by TEXT NOT NULL,
                recipient TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                artifact_sha256 TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE,
                FOREIGN KEY (subject_id) REFERENCES research_subjects (subject_id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS research_artifact_jobs (
                job_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                artifact_id TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                queued_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                error_message TEXT,
                result_json TEXT NOT NULL,
                UNIQUE (case_id, artifact_id),
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE,
                FOREIGN KEY (artifact_id) REFERENCES research_artifacts (artifact_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_evidence (
                evidence_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                title TEXT NOT NULL,
                locator TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                provenance TEXT NOT NULL,
                notes TEXT NOT NULL,
                status TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_iocs (
                ioc_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                first_seen TEXT,
                last_seen TEXT,
                source_evidence_id TEXT,
                tags_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (case_id, ioc_type, value),
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE,
                FOREIGN KEY (source_evidence_id) REFERENCES research_evidence (evidence_id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS research_rules (
                rule_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                name TEXT NOT NULL,
                purpose TEXT NOT NULL,
                content TEXT NOT NULL,
                validation_status TEXT NOT NULL,
                validation_json TEXT NOT NULL,
                source_evidence_id TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (case_id, rule_type, name),
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE,
                FOREIGN KEY (source_evidence_id) REFERENCES research_evidence (evidence_id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS research_rule_proposals (
                proposal_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                rule_type TEXT NOT NULL,
                name TEXT NOT NULL,
                purpose TEXT NOT NULL,
                content TEXT NOT NULL,
                source_evidence_id TEXT,
                source_kind TEXT NOT NULL,
                validation_status TEXT NOT NULL,
                validation_json TEXT NOT NULL,
                test_json TEXT NOT NULL,
                status TEXT NOT NULL,
                reviewer TEXT,
                review_note TEXT NOT NULL,
                active_rule_id TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (case_id, rule_type, name),
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE,
                FOREIGN KEY (source_evidence_id) REFERENCES research_evidence (evidence_id) ON DELETE SET NULL,
                FOREIGN KEY (active_rule_id) REFERENCES research_rules (rule_id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS research_case_findings (
                case_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                relationship TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (case_id, finding_id),
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_case_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                message TEXT NOT NULL,
                data_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_research_cases_status_updated
                ON research_cases (status, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_research_cases_type_updated
                ON research_cases (case_type, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_research_subjects_case
                ON research_subjects (case_id, subject_type);
            CREATE INDEX IF NOT EXISTS idx_research_evidence_case
                ON research_evidence (case_id, evidence_type);
            CREATE INDEX IF NOT EXISTS idx_research_iocs_case_type
                ON research_iocs (case_id, ioc_type);
            CREATE INDEX IF NOT EXISTS idx_research_rules_case_type
                ON research_rules (case_id, rule_type, status);
            CREATE INDEX IF NOT EXISTS idx_research_rule_proposals_case_status
                ON research_rule_proposals (case_id, status, rule_type);
            CREATE INDEX IF NOT EXISTS idx_research_events_case_time
                ON research_case_events (case_id, created_at);

            CREATE TABLE IF NOT EXISTS research_jobs (
                job_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                requested_by TEXT NOT NULL,
                attempt INTEGER NOT NULL DEFAULT 0,
                queued_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                updated_at TEXT NOT NULL,
                error_code TEXT,
                error_message TEXT,
                config_json TEXT NOT NULL,
                result_json TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_pipeline_runs (
                pipeline_id TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                case_id TEXT NOT NULL,
                status TEXT NOT NULL,
                requested_by TEXT NOT NULL,
                current_step TEXT NOT NULL,
                revision INTEGER NOT NULL DEFAULT 1,
                config_json TEXT NOT NULL,
                summary_json TEXT NOT NULL,
                error_code TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_pipeline_steps (
                step_id TEXT PRIMARY KEY,
                pipeline_id TEXT NOT NULL,
                step_key TEXT NOT NULL,
                step_order INTEGER NOT NULL,
                status TEXT NOT NULL,
                intelligence_job_id TEXT,
                result_json TEXT NOT NULL,
                error_code TEXT,
                error_message TEXT,
                started_at TEXT,
                completed_at TEXT,
                updated_at TEXT NOT NULL,
                UNIQUE (pipeline_id, step_key),
                FOREIGN KEY (pipeline_id) REFERENCES research_pipeline_runs (pipeline_id) ON DELETE CASCADE,
                FOREIGN KEY (intelligence_job_id) REFERENCES intelligence_jobs (job_id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS research_review_items (
                item_id TEXT PRIMARY KEY,
                pipeline_id TEXT NOT NULL,
                case_id TEXT NOT NULL,
                source_key TEXT NOT NULL,
                item_type TEXT NOT NULL,
                content TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                status TEXT NOT NULL,
                reviewer TEXT,
                review_note TEXT NOT NULL,
                edited_content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (pipeline_id, source_key),
                FOREIGN KEY (pipeline_id) REFERENCES research_pipeline_runs (pipeline_id) ON DELETE CASCADE,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_claims (
                claim_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                statement TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                status TEXT NOT NULL,
                supporting_evidence_json TEXT NOT NULL,
                contradicting_evidence_json TEXT NOT NULL,
                missing_evidence_json TEXT NOT NULL,
                limitations_json TEXT NOT NULL,
                rationale TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_verdicts (
                verdict_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                rationale TEXT NOT NULL,
                evidence_ids_json TEXT NOT NULL,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_disclosures (
                disclosure_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                status TEXT NOT NULL,
                recipient TEXT NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                affected_scope_json TEXT NOT NULL,
                attachments_json TEXT NOT NULL,
                embargo_until TEXT,
                approved_by TEXT,
                sent_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_publication_reviews (
                review_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                status TEXT NOT NULL,
                blockers_json TEXT NOT NULL,
                warnings_json TEXT NOT NULL,
                checks_json TEXT NOT NULL,
                waivers_json TEXT NOT NULL,
                approved_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_sandbox_requests (
                request_id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                justification TEXT NOT NULL,
                requested_behaviors_json TEXT NOT NULL,
                status TEXT NOT NULL,
                provider TEXT NOT NULL,
                approved_by TEXT,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_registry_sources (
                source_id TEXT PRIMARY KEY,
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                base_url TEXT NOT NULL,
                capabilities_json TEXT NOT NULL,
                coverage_mode TEXT NOT NULL,
                terms_url TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (ecosystem, name)
            );

            CREATE TABLE IF NOT EXISTS research_watchlists (
                watchlist_id TEXT PRIMARY KEY,
                ecosystem TEXT NOT NULL,
                watch_type TEXT NOT NULL,
                identifier TEXT NOT NULL,
                normalized_identifier TEXT NOT NULL,
                brand TEXT NOT NULL,
                known_publishers_json TEXT NOT NULL,
                known_repositories_json TEXT NOT NULL,
                known_namespaces_json TEXT NOT NULL,
                threshold REAL NOT NULL,
                exclusions_json TEXT NOT NULL,
                priority TEXT NOT NULL,
                owner TEXT NOT NULL,
                expires_at TEXT,
                reason TEXT NOT NULL,
                source_evidence_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (ecosystem, watch_type, normalized_identifier)
            );

            CREATE TABLE IF NOT EXISTS research_monitors (
                monitor_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                watchlist_id TEXT,
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL,
                priority TEXT NOT NULL,
                coverage_mode TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_run_at TEXT,
                last_success_at TEXT,
                last_error TEXT,
                next_run_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (source_id) REFERENCES research_registry_sources (source_id),
                FOREIGN KEY (watchlist_id) REFERENCES research_watchlists (watchlist_id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS research_monitor_cursors (
                monitor_id TEXT PRIMARY KEY,
                cursor_json TEXT NOT NULL,
                rate_limit_json TEXT NOT NULL,
                coverage_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (monitor_id) REFERENCES research_monitors (monitor_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_monitor_runs (
                run_id TEXT PRIMARY KEY,
                monitor_id TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                error_message TEXT,
                coverage_json TEXT NOT NULL,
                FOREIGN KEY (monitor_id) REFERENCES research_monitors (monitor_id) ON DELETE CASCADE
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_research_monitor_one_running
                ON research_monitor_runs (monitor_id) WHERE status = 'running';

            CREATE TABLE IF NOT EXISTS research_registry_events (
                event_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                publisher TEXT NOT NULL,
                source_url TEXT NOT NULL,
                artifact_url TEXT NOT NULL,
                artifact_sha256 TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                FOREIGN KEY (source_id) REFERENCES research_registry_sources (source_id)
            );

            CREATE TABLE IF NOT EXISTS research_candidates (
                candidate_id TEXT PRIMARY KEY,
                event_id TEXT,
                watchlist_id TEXT,
                ecosystem TEXT NOT NULL,
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                reference_identifier TEXT NOT NULL,
                score REAL NOT NULL,
                score_components_json TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL,
                case_id TEXT,
                evidence_json TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                algorithm_version TEXT NOT NULL,
                UNIQUE (ecosystem, package, version, reference_identifier),
                FOREIGN KEY (event_id) REFERENCES research_registry_events (event_id) ON DELETE SET NULL,
                FOREIGN KEY (watchlist_id) REFERENCES research_watchlists (watchlist_id) ON DELETE SET NULL,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS research_promotion_policies (
                ecosystem TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 0,
                score_threshold REAL NOT NULL DEFAULT 90,
                minimum_evidence INTEGER NOT NULL DEFAULT 2,
                require_publisher INTEGER NOT NULL DEFAULT 0,
                mode TEXT NOT NULL DEFAULT 'draft_case',
                updated_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS research_promotion_events (
                event_id TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL,
                policy_ecosystem TEXT NOT NULL,
                decision TEXT NOT NULL,
                reasons_json TEXT NOT NULL,
                case_id TEXT,
                actor TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(candidate_id, policy_ecosystem, decision),
                FOREIGN KEY (candidate_id) REFERENCES research_candidates (candidate_id) ON DELETE CASCADE,
                FOREIGN KEY (case_id) REFERENCES research_cases (case_id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS research_campaigns (
                campaign_id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                attribution TEXT NOT NULL,
                summary TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS research_campaign_links (
                campaign_id TEXT NOT NULL,
                left_type TEXT NOT NULL,
                left_id TEXT NOT NULL,
                right_type TEXT NOT NULL,
                right_id TEXT NOT NULL,
                relationship TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                algorithm_version TEXT NOT NULL,
                human_state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (campaign_id, left_type, left_id, right_type, right_id, relationship),
                FOREIGN KEY (campaign_id) REFERENCES research_campaigns (campaign_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_alerts (
                alert_id TEXT PRIMARY KEY,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                candidate_id TEXT,
                campaign_id TEXT,
                case_id TEXT,
                dedupe_key TEXT NOT NULL UNIQUE,
                reason TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                status TEXT NOT NULL,
                owner TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS research_external_advisory_sources (
                source_id TEXT PRIMARY KEY,
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                source_url TEXT NOT NULL,
                interval_seconds INTEGER NOT NULL DEFAULT 300,
                last_fetch_at TEXT,
                source_hash TEXT,
                status TEXT NOT NULL DEFAULT 'new',
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (ecosystem, source_url)
            );

            CREATE TABLE IF NOT EXISTS research_external_advisory_records (
                record_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                advisory_id TEXT NOT NULL,
                campaign_id TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                source_url TEXT NOT NULL,
                source_hash TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE (source_id, ecosystem, package, version),
                FOREIGN KEY (source_id) REFERENCES research_external_advisory_sources (source_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_npm_package_snapshots (
                package TEXT PRIMARY KEY,
                source_url TEXT NOT NULL,
                metadata_sha256 TEXT NOT NULL,
                versions_json TEXT NOT NULL,
                known_versions_json TEXT NOT NULL DEFAULT '[]',
                latest_version TEXT NOT NULL,
                last_published_at TEXT,
                last_event_seq TEXT,
                status TEXT NOT NULL DEFAULT 'baseline',
                last_error TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS research_npm_release_analyses (
                analysis_id TEXT PRIMARY KEY,
                source_event_id TEXT,
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                artifact_sha256 TEXT,
                status TEXT NOT NULL,
                score INTEGER NOT NULL DEFAULT 0,
                indicators_json TEXT NOT NULL,
                intake_json TEXT NOT NULL,
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (package, version, artifact_sha256)
            );

            CREATE TABLE IF NOT EXISTS research_npm_enrichment_runs (
                run_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                events_seen INTEGER NOT NULL DEFAULT 0,
                packages_fetched INTEGER NOT NULL DEFAULT 0,
                versions_created INTEGER NOT NULL DEFAULT 0,
                analyses_started INTEGER NOT NULL DEFAULT 0,
                candidates_created INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                error_message TEXT
            );

            CREATE TABLE IF NOT EXISTS research_notification_deliveries (
                delivery_id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                channel TEXT NOT NULL,
                destination TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                provider_id TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (alert_id) REFERENCES research_alerts (alert_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_disclosure_deliveries (
                delivery_id TEXT PRIMARY KEY,
                disclosure_id TEXT NOT NULL,
                channel TEXT NOT NULL,
                destination TEXT NOT NULL,
                status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                provider_id TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (disclosure_id) REFERENCES research_disclosures (disclosure_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS research_comparisons (
                comparison_id TEXT PRIMARY KEY,
                left_ecosystem TEXT NOT NULL,
                left_package TEXT NOT NULL,
                left_version TEXT NOT NULL,
                right_ecosystem TEXT NOT NULL,
                right_package TEXT NOT NULL,
                right_version TEXT NOT NULL,
                result_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (left_ecosystem, left_package, left_version, right_ecosystem, right_package, right_version)
            );

            CREATE TABLE IF NOT EXISTS registry_collectors (
                collector_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                name TEXT NOT NULL,
                feed_url TEXT NOT NULL,
                mode TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                config_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (source_id) REFERENCES research_registry_sources (source_id)
            );

            CREATE TABLE IF NOT EXISTS registry_cursors (
                collector_id TEXT PRIMARY KEY,
                cursor_value TEXT NOT NULL,
                last_event_at TEXT,
                last_run_id TEXT,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (collector_id) REFERENCES registry_collectors (collector_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS registry_feed_events (
                feed_event_id TEXT PRIMARY KEY,
                collector_id TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                package TEXT NOT NULL,
                version TEXT NOT NULL,
                event_type TEXT NOT NULL,
                registry_timestamp TEXT NOT NULL,
                page_url TEXT NOT NULL,
                leaf_url TEXT NOT NULL,
                leaf_fetched INTEGER NOT NULL DEFAULT 0,
                metadata_json TEXT NOT NULL,
                idempotency_key TEXT NOT NULL UNIQUE,
                collected_at TEXT NOT NULL,
                processing_state TEXT NOT NULL,
                FOREIGN KEY (collector_id) REFERENCES registry_collectors (collector_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS registry_ingestion_runs (
                run_id TEXT PRIMARY KEY,
                collector_id TEXT NOT NULL,
                status TEXT NOT NULL,
                cursor_before TEXT NOT NULL,
                cursor_after TEXT NOT NULL,
                pages_processed INTEGER NOT NULL DEFAULT 0,
                events_seen INTEGER NOT NULL DEFAULT 0,
                events_stored INTEGER NOT NULL DEFAULT 0,
                events_duplicate INTEGER NOT NULL DEFAULT 0,
                failures INTEGER NOT NULL DEFAULT 0,
                coverage_mode TEXT NOT NULL,
                error_message TEXT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (collector_id) REFERENCES registry_collectors (collector_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS registry_coverage_windows (
                window_id TEXT PRIMARY KEY,
                collector_id TEXT NOT NULL,
                run_id TEXT,
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                expected_pages INTEGER NOT NULL,
                processed_pages INTEGER NOT NULL,
                events_stored INTEGER NOT NULL,
                state TEXT NOT NULL,
                gap_reason TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (collector_id) REFERENCES registry_collectors (collector_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS registry_dead_letters (
                dead_letter_id TEXT PRIMARY KEY,
                collector_id TEXT NOT NULL,
                run_id TEXT,
                url TEXT NOT NULL,
                item_kind TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                error_message TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_retry_at TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (collector_id) REFERENCES registry_collectors (collector_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS registry_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                collector_id TEXT NOT NULL,
                serial TEXT NOT NULL,
                item_count INTEGER NOT NULL,
                names_hash TEXT NOT NULL,
                names_blob BLOB NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (collector_id) REFERENCES registry_collectors (collector_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_research_jobs_case_status
                ON research_jobs (case_id, status, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_research_jobs_status_time
                ON research_jobs (status, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_research_pipeline_case_time
                ON research_pipeline_runs (case_id, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_research_pipeline_status_time
                ON research_pipeline_runs (status, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_research_pipeline_steps_run
                ON research_pipeline_steps (pipeline_id, step_order);
            CREATE INDEX IF NOT EXISTS idx_research_review_items_run_status
                ON research_review_items (pipeline_id, status, created_at);
            CREATE INDEX IF NOT EXISTS idx_research_claims_case
                ON research_claims (case_id, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_research_verdicts_case
                ON research_verdicts (case_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_research_disclosures_case
                ON research_disclosures (case_id, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_research_publication_reviews_case
                ON research_publication_reviews (case_id, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_research_sandbox_case
                ON research_sandbox_requests (case_id, updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_research_candidates_status_score
                ON research_candidates (status, score DESC, last_seen DESC);
            CREATE INDEX IF NOT EXISTS idx_research_candidates_ecosystem_package
                ON research_candidates (ecosystem, package, version);
            CREATE INDEX IF NOT EXISTS idx_research_monitors_due
                ON research_monitors (enabled, next_run_at);
            CREATE INDEX IF NOT EXISTS idx_research_alerts_status_time
                ON research_alerts (status, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_external_advisory_records_active
                ON research_external_advisory_records (active, ecosystem, package, version);
            CREATE INDEX IF NOT EXISTS idx_external_advisory_sources_status
                ON research_external_advisory_sources (status, last_fetch_at);
            CREATE INDEX IF NOT EXISTS idx_research_npm_snapshots_updated
                ON research_npm_package_snapshots (updated_at, status);
            CREATE INDEX IF NOT EXISTS idx_research_npm_release_analyses_status
                ON research_npm_release_analyses (status, updated_at);
            CREATE INDEX IF NOT EXISTS idx_research_npm_enrichment_runs_started
                ON research_npm_enrichment_runs (started_at DESC);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_registry_one_running
                ON registry_ingestion_runs (collector_id) WHERE status = 'running';
            CREATE INDEX IF NOT EXISTS idx_registry_feed_events_cursor
                ON registry_feed_events (collector_id, registry_timestamp);
            CREATE INDEX IF NOT EXISTS idx_registry_feed_events_package
                ON registry_feed_events (ecosystem, package, version);
            CREATE INDEX IF NOT EXISTS idx_registry_dead_letters_due
                ON registry_dead_letters (status, next_retry_at);
            CREATE INDEX IF NOT EXISTS idx_registry_coverage_state
                ON registry_coverage_windows (collector_id, state, window_start);
            CREATE INDEX IF NOT EXISTS idx_registry_snapshots_collector
                ON registry_snapshots (collector_id, created_at DESC);
            """
        )
        for table in ("research_subjects", "research_evidence", "research_iocs"):
            _ensure_column(connection, table, "status", "TEXT NOT NULL DEFAULT 'active'")
        for column, definition in (
            ("registry_state", "TEXT NOT NULL DEFAULT 'unknown'"),
            ("artifact_state", "TEXT NOT NULL DEFAULT 'missing'"),
            ("validation_state", "TEXT NOT NULL DEFAULT 'unverified'"),
            ("state_reason", "TEXT NOT NULL DEFAULT ''"),
            ("state_checked_at", "TEXT"),
        ):
            _ensure_column(connection, "research_subjects", column, definition)
        _ensure_column(connection, "research_npm_package_snapshots", "known_versions_json", "TEXT NOT NULL DEFAULT '[]'")
        _ensure_column(connection, "research_npm_package_snapshots", "last_published_at", "TEXT")
        connection.commit()


def _existing_state(connection: sqlite3.Connection, finding_id: str) -> Dict[str, str] | None:
    row = connection.execute(
        "SELECT status, disposition, created_at FROM findings WHERE finding_id = ?",
        (finding_id,),
    ).fetchone()
    if row is None:
        return None
    return {
        "status": str(row["status"]),
        "disposition": str(row["disposition"]),
        "created_at": str(row["created_at"]),
    }


def upsert_finding(connection: sqlite3.Connection, finding: Dict[str, Any], source: str) -> None:
    existing = _existing_state(connection, finding["finding_id"])
    now = utc_now()
    status = existing["status"] if existing else str(finding.get("status", "open"))
    disposition = existing["disposition"] if existing else str(finding.get("disposition", "unreviewed"))
    created_at = existing["created_at"] if existing else str(finding.get("created_at", now))

    persisted = dict(finding)
    persisted["status"] = status
    persisted["disposition"] = disposition

    connection.execute(
        """
        INSERT INTO findings (
            finding_id, title, summary, severity, severity_score, status,
            disposition, source, first_seen, last_seen, created_at,
            updated_at, payload_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(finding_id) DO UPDATE SET
            title = excluded.title,
            summary = excluded.summary,
            severity = excluded.severity,
            severity_score = excluded.severity_score,
            source = excluded.source,
            first_seen = excluded.first_seen,
            last_seen = excluded.last_seen,
            updated_at = excluded.updated_at,
            payload_json = excluded.payload_json
        """,
        (
            persisted["finding_id"],
            persisted["title"],
            persisted["summary"],
            persisted["severity"],
            int(persisted["severity_score"]),
            status,
            disposition,
            source,
            persisted["first_seen"],
            persisted["last_seen"],
            created_at,
            now,
            json.dumps(persisted, sort_keys=True),
        ),
    )

    connection.execute("DELETE FROM finding_events WHERE finding_id = ?", (persisted["finding_id"],))
    connection.executemany(
        "INSERT INTO finding_events (finding_id, event_id) VALUES (?, ?)",
        [(persisted["finding_id"], event_id) for event_id in persisted.get("event_ids", [])],
    )


def persist_findings(findings: Iterable[Dict[str, Any]], source: str, db_path: str | None = None) -> str:
    resolved_path = db_path or default_db_path()
    init_db(resolved_path)
    findings = list(findings)
    current_ids = {finding["finding_id"] for finding in findings}
    with closing(connect(resolved_path)) as connection:
        for finding in findings:
            upsert_finding(connection, finding, source)

        stale_rows = connection.execute(
            "SELECT finding_id FROM findings WHERE source = ?",
            (source,),
        ).fetchall()
        stale_ids = [str(row["finding_id"]) for row in stale_rows if str(row["finding_id"]) not in current_ids]
        for finding_id in stale_ids:
            connection.execute("DELETE FROM findings WHERE finding_id = ?", (finding_id,))

        connection.commit()
    return resolved_path


def set_finding_status(finding_id: str, status: str, db_path: str | None = None) -> None:
    init_db(db_path)
    with closing(connect(db_path)) as connection:
        connection.execute(
            "UPDATE findings SET status = ?, updated_at = ? WHERE finding_id = ?",
            (status, utc_now(), finding_id),
        )
        connection.commit()


def set_finding_disposition(finding_id: str, disposition: str, db_path: str | None = None) -> None:
    init_db(db_path)
    with closing(connect(db_path)) as connection:
        connection.execute(
            "UPDATE findings SET disposition = ?, updated_at = ? WHERE finding_id = ?",
            (disposition, utc_now(), finding_id),
        )
        connection.commit()


def add_note(finding_id: str, author: str, note: str, db_path: str | None = None) -> None:
    init_db(db_path)
    with closing(connect(db_path)) as connection:
        connection.execute(
            "INSERT INTO notes (finding_id, author, note, created_at) VALUES (?, ?, ?, ?)",
            (finding_id, author, note, utc_now()),
        )
        connection.commit()


def list_findings(
    db_path: str | None = None,
    *,
    severity: str | None = None,
    status: str | None = None,
    source: str | None = None,
    limit: int | None = None,
    include_payload: bool = False,
) -> List[Dict[str, Any]]:
    init_db(db_path)
    if limit is not None and limit <= 0:
        return []
    clauses: List[str] = []
    params: List[Any] = []
    if severity:
        clauses.append("lower(severity) = lower(?)")
        params.append(severity)
    if status:
        clauses.append("lower(status) = lower(?)")
        params.append(status)
    if source:
        clauses.append("source = ?")
        params.append(source)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    fields = (
        "finding_id, title, severity, severity_score, status, disposition, "
        "first_seen, last_seen, source, payload_json"
        if include_payload
        else "finding_id, title, severity, severity_score, status, disposition, first_seen, last_seen"
    )
    query = (
        f"SELECT {fields} FROM findings{where} "
        "ORDER BY severity_score DESC, first_seen ASC"
    )
    if limit is not None and limit > 0:
        query += " LIMIT ?"
        params.append(int(limit))
    with closing(connect(db_path)) as connection:
        rows = connection.execute(query, tuple(params)).fetchall()
    results: List[Dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        if include_payload:
            try:
                payload = json.loads(str(item.pop("payload_json")))
            except json.JSONDecodeError:
                payload = {}
            payload.update(
                {
                    "finding_id": item.get("finding_id"),
                    "title": item.get("title"),
                    "severity": item.get("severity"),
                    "severity_score": item.get("severity_score"),
                    "status": item.get("status"),
                    "disposition": item.get("disposition"),
                    "first_seen": item.get("first_seen"),
                    "last_seen": item.get("last_seen"),
                    "source": item.get("source"),
                }
            )
            results.append(payload)
        else:
            results.append(item)
    return results


def get_finding(finding_id: str, db_path: str | None = None) -> Dict[str, Any] | None:
    init_db(db_path)
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            "SELECT payload_json, status, disposition FROM findings WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
        if row is None:
            return None

        finding = json.loads(str(row["payload_json"]))
        finding["status"] = str(row["status"])
        finding["disposition"] = str(row["disposition"])
        notes = connection.execute(
            "SELECT author, note, created_at FROM notes WHERE finding_id = ? ORDER BY note_id ASC",
            (finding_id,),
        ).fetchall()
        finding["notes"] = [dict(note) for note in notes]
        return finding


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Local SOC findings store CLI")
    parser.add_argument("--db-path", default=default_db_path(), help="SQLite database path")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List stored findings")

    show_parser = subparsers.add_parser("show", help="Show one finding with notes")
    show_parser.add_argument("finding_id", help="Finding identifier")

    disposition_parser = subparsers.add_parser("set-disposition", help="Update finding disposition")
    disposition_parser.add_argument("finding_id", help="Finding identifier")
    disposition_parser.add_argument("disposition", help="New disposition value")

    status_parser = subparsers.add_parser("set-status", help="Update finding status")
    status_parser.add_argument("finding_id", help="Finding identifier")
    status_parser.add_argument("status", help="New status value")

    note_parser = subparsers.add_parser("add-note", help="Attach a note to a finding")
    note_parser.add_argument("finding_id", help="Finding identifier")
    note_parser.add_argument("author", help="Note author")
    note_parser.add_argument("note", help="Note text")

    return parser.parse_args()


def format_finding_row(finding: Dict[str, Any]) -> str:
    return (
        f"{finding['finding_id']} | {finding['severity'].upper():8s} | "
        f"status={finding['status']} | disposition={finding['disposition']} | {finding['title']}"
    )


def main() -> int:
    args = parse_args()

    if args.command == "list":
        findings = list_findings(args.db_path)
        for finding in findings:
            print(format_finding_row(finding))
        print(f"total_findings={len(findings)}")
        return 0

    if args.command == "show":
        finding = get_finding(args.finding_id, args.db_path)
        if finding is None:
            print(f"error: finding not found: {args.finding_id}")
            return 1
        print(json.dumps(finding, indent=2))
        return 0

    if args.command == "set-disposition":
        set_finding_disposition(args.finding_id, args.disposition, args.db_path)
        print(f"updated_disposition={args.disposition}")
        return 0

    if args.command == "set-status":
        set_finding_status(args.finding_id, args.status, args.db_path)
        print(f"updated_status={args.status}")
        return 0

    if args.command == "add-note":
        add_note(args.finding_id, args.author, args.note, args.db_path)
        print(f"note_added_for={args.finding_id}")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
