import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import soc_store
from secopsai.triage import apply_action, generate_summary, list_actions, orchestrate_findings


def _write_findings(db_path: str, findings):
    soc_store.persist_findings(findings, source="secopsai-test", db_path=db_path)


class TriageOrchestratorTests(unittest.TestCase):
    def test_orchestrate_auto_closes_expected_behavior(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            queue_file = str(temp_path / "queue.json")
            report_path = temp_path / "pkg-report.md"
            report_path.write_text("fake report", encoding="utf-8")
            findings = [
                {
                    "finding_id": "SCM-AUTO001",
                    "title": "Suspicious pypi package release: duckdb@1.5.2.dev38",
                    "summary": "Suspicious release.",
                    "severity": "critical",
                    "severity_score": 95,
                    "status": "open",
                    "disposition": "unreviewed",
                    "source": "secopsai-supply-chain",
                    "first_seen": "2026-04-08T00:00:00Z",
                    "last_seen": "2026-04-08T00:00:00Z",
                    "platform": "supply_chain",
                    "package": "duckdb",
                    "ecosystem": "pypi",
                    "new_version": "1.5.2.dev38",
                    "old_version": "1.5.2.dev37",
                    "report_path": str(report_path),
                }
            ]
            _write_findings(db_path, findings)
            with mock.patch("secopsai.triage.supply_chain.supply_chain.explain_policy", return_value={"allow_matches": [], "deny_matches": []}), \
                 mock.patch("secopsai.triage.supply_chain.supply_chain.explain_verdict", return_value={"score": 11, "effective_threshold": 10, "matched_rules": []}), \
                 mock.patch("secopsai.triage.supply_chain._reputation_summary", return_value={"release_count": 20}):
                result = orchestrate_findings(
                    db_path=db_path,
                    search_root=str(temp_path),
                    report_dir=str(temp_path / "triage"),
                    summary_dir=str(temp_path / "orchestrator"),
                    queue_file=queue_file,
                    author="tester",
                )

            self.assertEqual(result.processed, 1)
            self.assertEqual(result.auto_applied, 1)
            self.assertEqual(result.queued, 0)
            updated = soc_store.get_finding("SCM-AUTO001", db_path)
            self.assertEqual(updated["status"], "closed")
            self.assertEqual(updated["disposition"], "expected_behavior")
            self.assertTrue(Path(result.summary_json).exists())
            self.assertTrue(Path(result.summary_markdown).exists())

    def test_orchestrate_queues_needs_review_for_present_package(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            queue_file = str(temp_path / "queue.json")
            report_path = temp_path / "pkg-report.md"
            report_path.write_text("fake report", encoding="utf-8")
            (temp_path / "package.json").write_text('{"dependencies":{"widget":"1.0.1"}}', encoding="utf-8")
            findings = [
                {
                    "finding_id": "SCM-QUEUE001",
                    "title": "Suspicious npm package release: widget@1.0.1",
                    "summary": "Suspicious release.",
                    "severity": "critical",
                    "severity_score": 90,
                    "status": "open",
                    "disposition": "unreviewed",
                    "source": "secopsai-supply-chain",
                    "first_seen": "2026-04-08T00:00:00Z",
                    "last_seen": "2026-04-08T00:00:00Z",
                    "platform": "supply_chain",
                    "package": "widget",
                    "ecosystem": "npm",
                    "new_version": "1.0.1",
                    "old_version": "1.0.0",
                    "report_path": str(report_path),
                }
            ]
            _write_findings(db_path, findings)
            with mock.patch("secopsai.triage.supply_chain.supply_chain.explain_policy", return_value={"allow_matches": [], "deny_matches": []}), \
                 mock.patch("secopsai.triage.supply_chain.supply_chain.explain_verdict", return_value={"score": 14, "effective_threshold": 10, "matched_rules": [{"rule": "semantic dynamic execution"}]}), \
                 mock.patch("secopsai.triage.supply_chain._reputation_summary", return_value={"release_count": 4}):
                result = orchestrate_findings(
                    db_path=db_path,
                    search_root=str(temp_path),
                    report_dir=str(temp_path / "triage"),
                    summary_dir=str(temp_path / "orchestrator"),
                    queue_file=queue_file,
                )

            self.assertEqual(result.auto_applied, 0)
            self.assertEqual(result.queued, 1)
            queued = list_actions(path=queue_file)
            self.assertEqual(len(queued), 1)
            self.assertEqual(queued[0]["action_type"], "close_finding")
            self.assertEqual(queued[0]["payload"]["disposition"], "needs_review")

    def test_apply_allowlist_action_closes_finding(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            queue_file = str(temp_path / "queue.json")
            report_path = temp_path / "pkg-report.md"
            report_path.write_text("fake report", encoding="utf-8")
            findings = [
                {
                    "finding_id": "SCM-ALLOW001",
                    "title": "Suspicious npm package release: nano-brain@2026.7.1",
                    "summary": "Suspicious release.",
                    "severity": "critical",
                    "severity_score": 90,
                    "status": "open",
                    "disposition": "unreviewed",
                    "source": "secopsai-supply-chain",
                    "first_seen": "2026-04-08T00:00:00Z",
                    "last_seen": "2026-04-08T00:00:00Z",
                    "platform": "supply_chain",
                    "package": "nano-brain",
                    "ecosystem": "npm",
                    "new_version": "2026.7.1",
                    "old_version": "2026.7.0",
                    "report_path": str(report_path),
                }
            ]
            _write_findings(db_path, findings)
            with mock.patch("secopsai.triage.supply_chain.supply_chain.explain_policy", return_value={"allow_matches": [], "deny_matches": []}), \
                 mock.patch("secopsai.triage.supply_chain.supply_chain.explain_verdict", return_value={"score": 7, "effective_threshold": 10, "matched_rules": [{"rule": "ast-aware semantic findings"}]}), \
                 mock.patch("secopsai.triage.supply_chain._reputation_summary", return_value={"release_count": 20}):
                result = orchestrate_findings(
                    db_path=db_path,
                    search_root=str(temp_path),
                    report_dir=str(temp_path / "triage"),
                    summary_dir=str(temp_path / "orchestrator"),
                    queue_file=queue_file,
                    auto_apply_safe=False,
                )

            self.assertEqual(result.queued, 1)
            action_id = list_actions(path=queue_file)[0]["action_id"]
            with mock.patch("secopsai.triage.orchestrator.supply_chain_mod.allowlist_add", return_value={"target": "npm:nano-brain"}), \
                 mock.patch("secopsai.triage.orchestrator.supply_chain_mod.reconcile_history", return_value={"reclassified": 1}):
                updated = apply_action(action_id, queue_file=queue_file, db_path=db_path, author="tester", yes=True)

            self.assertEqual(updated["status"], "applied")
            finding = soc_store.get_finding("SCM-ALLOW001", db_path)
            self.assertEqual(finding["disposition"], "false_positive")
            self.assertEqual(finding["status"], "closed")

    def test_generate_summary_writes_reports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            queue_file = str(temp_path / "queue.json")
            findings = [
                {
                    "finding_id": "OCF-SUM001",
                    "title": "OpenClaw Policy Denials",
                    "summary": "Repeated policy denials.",
                    "severity": "low",
                    "severity_score": 20,
                    "status": "open",
                    "disposition": "unreviewed",
                    "source": "secopsai-cli",
                    "first_seen": "2026-04-08T00:00:00Z",
                    "last_seen": "2026-04-08T00:00:00Z",
                }
            ]
            _write_findings(db_path, findings)
            Path(queue_file).write_text(json.dumps([{"action_id": "ACT-0001", "status": "pending"}]), encoding="utf-8")

            summary = generate_summary(
                db_path=db_path,
                queue_file=queue_file,
                summary_dir=str(temp_path / "summaries"),
            )

            self.assertEqual(summary["open_findings"], 1)
            self.assertEqual(summary["pending_actions"], 1)
            self.assertTrue(Path(summary["summary_json"]).exists())
            self.assertTrue(Path(summary["summary_markdown"]).exists())


if __name__ == "__main__":
    unittest.main()
