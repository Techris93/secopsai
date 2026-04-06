import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import soc_store
from secopsai.triage import close_finding, investigate_finding, list_triage_findings, start_finding, suggest_supply_chain_fp_action


def _write_findings(db_path: str, findings):
    soc_store.persist_findings(findings, source="secopsai-test", db_path=db_path)


class TriageTests(unittest.TestCase):
    def test_suggest_supply_chain_fp_action_prefers_expected_behavior_for_unreferenced_package(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            report_path = temp_path / "npm-widget-1.0.0-to-1.0.1.md"
            report_path.write_text("fake report", encoding="utf-8")
            findings = [
                {
                    "finding_id": "SCM-TEST-SUGGEST",
                    "title": "Suspicious npm package release: widget@1.0.1",
                    "summary": "Deterministic rules flagged: ast-aware semantic findings",
                    "severity": "high",
                    "severity_score": 80,
                    "status": "open",
                    "disposition": "unreviewed",
                    "source": "secopsai-supply-chain",
                    "first_seen": "2026-04-06T00:00:00Z",
                    "last_seen": "2026-04-06T00:00:00Z",
                    "event_ids": ["evt-1"],
                    "rule_ids": ["SUPPLY-CHAIN-NATIVE"],
                    "platform": "supply_chain",
                    "package": "widget",
                    "ecosystem": "npm",
                    "new_version": "1.0.1",
                    "old_version": "1.0.0",
                    "report_path": str(report_path),
                    "analysis": "heuristics only",
                    "verdict": "malicious",
                    "rank": 5,
                }
            ]
            _write_findings(db_path, findings)

            with mock.patch("secopsai.triage.supply_chain.supply_chain.explain_policy", return_value={"allow_matches": [], "deny_matches": []}), \
                 mock.patch("secopsai.triage.supply_chain.supply_chain.explain_verdict", return_value={
                     "score": 4,
                     "effective_threshold": 10,
                     "matched_rules": [{"rule": "ast-aware semantic findings"}],
                 }), \
                 mock.patch("secopsai.triage.supply_chain._reputation_summary", return_value={"release_count": 5}):
                result = suggest_supply_chain_fp_action(
                    "SCM-TEST-SUGGEST",
                    db_path=db_path,
                    search_root=str(temp_path),
                )

        self.assertEqual(result["suggestion"]["action"], "allowlist_package")
        self.assertIn("allowlist add", result["suggestion"]["commands"][0])

    def test_supply_chain_investigation_writes_reports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            report_path = temp_path / "npm-widget-1.0.0-to-1.0.1.md"
            report_path.write_text("fake report", encoding="utf-8")
            findings = [
                {
                    "finding_id": "SCM-TEST123",
                    "title": "Suspicious npm package release: widget@1.0.1",
                    "summary": "Deterministic rules flagged: ast-aware semantic findings, manifest executable entrypoints",
                    "severity": "high",
                    "severity_score": 80,
                    "status": "open",
                    "disposition": "unreviewed",
                    "source": "secopsai-supply-chain",
                    "first_seen": "2026-04-06T00:00:00Z",
                    "last_seen": "2026-04-06T00:00:00Z",
                    "event_ids": ["evt-1"],
                    "rule_ids": ["SUPPLY-CHAIN-NATIVE"],
                    "platform": "supply_chain",
                    "package": "widget",
                    "ecosystem": "npm",
                    "new_version": "1.0.1",
                    "old_version": "1.0.0",
                    "report_path": str(report_path),
                    "analysis": "weak heuristics only",
                    "verdict": "malicious",
                    "rank": 5,
                }
            ]
            _write_findings(db_path, findings)
            (temp_path / "package.json").write_text('{"dependencies":{"widget":"1.0.1"}}', encoding="utf-8")

            with mock.patch("secopsai.triage.supply_chain.supply_chain.explain_policy", return_value={"allow_matches": [], "deny_matches": []}), \
                 mock.patch("secopsai.triage.supply_chain.supply_chain.explain_verdict", return_value={
                     "score": 6,
                     "effective_threshold": 10,
                     "matched_rules": [
                         {"rule": "ast-aware semantic findings"},
                         {"rule": "manifest executable entrypoints"},
                     ],
                 }), \
                 mock.patch("secopsai.triage.supply_chain._reputation_summary", return_value={"release_count": 20}):
                result = investigate_finding(
                    "SCM-TEST123",
                    db_path=db_path,
                    search_root=str(temp_path),
                    report_dir=str(temp_path / "triage"),
                )

            self.assertEqual(result["category"], "supply_chain")
            self.assertIn("json_report", result)
            self.assertTrue(Path(result["json_report"]).exists())
            self.assertTrue(Path(result["markdown_report"]).exists())
            self.assertTrue(result["investigation"]["dependency_presence"]["present"])

    def test_start_close_and_list_triage_findings(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            findings = [
                {
                    "finding_id": "OCF-TEST123",
                    "title": "OpenClaw Policy Denials",
                    "summary": "OpenClaw Policy Denials matched 3 events across 1 session scope.",
                    "severity": "low",
                    "severity_score": 25,
                    "status": "open",
                    "disposition": "unreviewed",
                    "source": "secopsai_cli",
                    "first_seen": "2026-04-06T00:00:00Z",
                    "last_seen": "2026-04-06T00:00:00Z",
                    "event_ids": ["evt-1", "evt-2", "evt-3"],
                    "rule_ids": ["RULE-104"],
                    "events": [
                        {"status": "failed", "action": "end", "session_key": "s1"},
                        {"status": "failed", "action": "end", "session_key": "s1"},
                        {"status": "blocked", "action": "deny", "session_key": "s1"},
                    ],
                }
            ]
            _write_findings(db_path, findings)

            started = start_finding("OCF-TEST123", db_path=db_path, author="analyst", note="Started")
            self.assertEqual(started["status"], "in_review")

            rows = list_triage_findings(db_path=db_path, status="in_review")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["category"], "policy_denial")

            closed = close_finding(
                "OCF-TEST123",
                db_path=db_path,
                disposition="tune_policy",
                status="triaged",
                author="analyst",
                note="Repeated benign workflow; tune the rule.",
            )
            self.assertEqual(closed["status"], "triaged")
            self.assertEqual(closed["disposition"], "tune_policy")
            self.assertEqual(closed["notes"][-1]["author"], "analyst")


if __name__ == "__main__":
    unittest.main()
