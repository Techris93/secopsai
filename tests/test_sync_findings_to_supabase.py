import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import sync_findings_to_supabase as syncmod


class SyncFindingsSchemaTests(unittest.TestCase):
    def test_normalized_row_matches_dashboard_schema(self):
        finding = {
            "finding_id": "OCF-123",
            "title": "Test finding",
            "summary": "Something happened",
            "severity": "high",
            "severity_score": 75,
            "status": "open",
            "disposition": "unreviewed",
            "source": "/tmp/source.json",
            "first_seen": "2026-03-29T00:00:00Z",
            "last_seen": "2026-03-29T00:05:00Z",
            "created_at": "2026-03-29T00:00:00Z",
            "updated_at": "2026-03-29T00:05:00Z",
            "rule_id": "RULE-109",
            "rule_name": "OpenClaw Data Exfiltration",
            "mitre": "T1041",
            "event_count": 2,
            "event_ids": ["evt-1", "evt-2"],
            "recommended_actions": ["Rotate secrets"],
        }
        row = syncmod.normalize_row(finding)
        self.assertIsNotNone(row)
        validated = syncmod.validate_row_mapping(
            [row],
            syncmod.DEFAULT_SCHEMA_SQL,
            table_name="findings",
        )
        self.assertIn("external_finding_id", validated)
        self.assertIn("raw_payload", validated)

    def test_validate_row_mapping_rejects_unknown_columns(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            schema_path = Path(temp_dir) / "schema.sql"
            schema_path.write_text(
                """
                create table if not exists public.findings (
                  external_finding_id text,
                  title text,
                  raw_payload jsonb
                );
                """,
                encoding="utf-8",
            )
            with self.assertRaises(syncmod.SchemaValidationError):
                syncmod.validate_row_mapping(
                    [{"external_finding_id": "1", "title": "x", "raw_payload": {}, "unknown_col": 1}],
                    schema_path,
                    table_name="findings",
                )


class SyncFindingsExecutionTests(unittest.TestCase):
    def test_execute_sync_dry_run_reports_summary(self):
        finding = {
            "finding_id": "OCF-123",
            "title": "Test finding",
            "summary": "Something happened",
            "severity": "high",
            "severity_score": 75,
            "status": "open",
            "disposition": "unreviewed",
            "source": "/tmp/source.json",
            "first_seen": "2026-03-29T00:00:00Z",
            "last_seen": "2026-03-29T00:05:00Z",
            "created_at": "2026-03-29T00:00:00Z",
            "updated_at": "2026-03-29T00:05:00Z",
            "rule_id": "RULE-109",
            "rule_name": "OpenClaw Data Exfiltration",
            "mitre": "T1041",
            "event_count": 2,
            "event_ids": ["evt-1", "evt-2"],
            "recommended_actions": ["Rotate secrets"],
        }
        args = syncmod.parse_args([
            "--dry-run",
            "--skip-schema-check",
        ])
        with mock.patch.object(syncmod, "load_local_findings", return_value=syncmod.LoadResult("sqlite", "/tmp/db", [finding])):
            summary = syncmod.execute_sync(args)
        self.assertTrue(summary.dry_run)
        self.assertEqual(summary.normalized_rows, 1)
        self.assertEqual(summary.synced_rows, 0)

    def test_execute_sync_is_idempotent_over_same_rows(self):
        finding = {
            "finding_id": "OCF-123",
            "title": "Test finding",
            "summary": "Something happened",
            "severity": "high",
            "severity_score": 75,
            "status": "open",
            "disposition": "unreviewed",
            "source": "/tmp/source.json",
            "first_seen": "2026-03-29T00:00:00Z",
            "last_seen": "2026-03-29T00:05:00Z",
            "created_at": "2026-03-29T00:00:00Z",
            "updated_at": "2026-03-29T00:05:00Z",
            "rule_id": "RULE-109",
            "rule_name": "OpenClaw Data Exfiltration",
            "mitre": "T1041",
            "event_count": 2,
            "event_ids": ["evt-1", "evt-2"],
            "recommended_actions": ["Rotate secrets"],
        }
        args = syncmod.parse_args([
            "--supabase-url",
            "https://example.supabase.co",
            "--supabase-key",
            "test-key",
            "--skip-schema-check",
        ])
        with mock.patch.object(syncmod, "load_local_findings", return_value=syncmod.LoadResult("sqlite", "/tmp/db", [finding])), \
             mock.patch.object(syncmod, "postgrest_upsert", return_value=(201, "")) as upsert_mock:
            summary1 = syncmod.execute_sync(args)
            summary2 = syncmod.execute_sync(args)
        self.assertEqual(summary1.synced_rows, 1)
        self.assertEqual(summary2.synced_rows, 1)
        self.assertEqual(upsert_mock.call_count, 2)
        first_rows = upsert_mock.call_args_list[0].args[3]
        second_rows = upsert_mock.call_args_list[1].args[3]
        self.assertEqual(first_rows, second_rows)

    def test_postgrest_upsert_errors_are_wrapped(self):
        with mock.patch.object(syncmod.request, "urlopen", side_effect=syncmod.error.URLError("boom")):
            with self.assertRaises(syncmod.SyncRequestError):
                syncmod.postgrest_upsert(
                    "https://example.supabase.co",
                    "test-key",
                    "findings",
                    [{"external_finding_id": "1"}],
                )


if __name__ == "__main__":
    unittest.main()
