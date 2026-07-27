import sys
import tempfile
import unittest
import json
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import soc_store
from secopsai.triage import close_finding, investigate_finding, list_triage_findings, start_finding
from secopsai.triage.host import investigate_host


def _write_findings(db_path: str, findings):
    soc_store.persist_findings(findings, source="secopsai-test", db_path=db_path)


class TriageTests(unittest.TestCase):
    def test_exfil_investigation_downgrades_local_approved_reporting_activity(self):
        finding = {
            "finding_id": "OCF-LOCAL001",
            "title": "OpenClaw Data Exfiltration",
            "events": [
                {
                    "event_type": "tool",
                    "status": "running",
                    "approval_state": "",
                    "command": "python3 - <<'PY'\\nprint('local report')\\nPY",
                },
                {
                    "event_type": "exec",
                    "status": "completed",
                    "approval_state": "approved",
                    "command": "brv curate \"daily brief\"",
                },
            ],
        }

        result = investigate_host(finding)
        self.assertEqual(result["recommended_disposition"], "tune_policy")
        self.assertIn("approved local OpenClaw reporting", result["summary"])

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

    def test_supply_chain_dependency_presence_ignores_irrelevant_package_json_scripts_in_venv(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            report_path = temp_path / "pypi-build-1.4.2-to-1.4.3.md"
            report_path.write_text("fake report", encoding="utf-8")
            findings = [
                {
                    "finding_id": "SCM-BUILD001",
                    "title": "Suspicious pypi package release: build@1.4.3",
                    "summary": "Deterministic rules flagged: subprocess spawn",
                    "severity": "critical",
                    "severity_score": 90,
                    "status": "open",
                    "disposition": "unreviewed",
                    "source": "secopsai-supply-chain",
                    "first_seen": "2026-04-06T00:00:00Z",
                    "last_seen": "2026-04-06T00:00:00Z",
                    "event_ids": ["evt-1"],
                    "rule_ids": ["SUPPLY-CHAIN-NATIVE"],
                    "platform": "supply_chain",
                    "package": "build",
                    "ecosystem": "pypi",
                    "new_version": "1.4.3",
                    "old_version": "1.4.2",
                    "report_path": str(report_path),
                    "analysis": "strong signal test",
                    "verdict": "malicious",
                    "rank": 9,
                }
            ]
            _write_findings(db_path, findings)

            pyright_package_json = temp_path / ".venv/lib/python3.14/site-packages/pyright/dist/package.json"
            pyright_package_json.parent.mkdir(parents=True, exist_ok=True)
            pyright_package_json.write_text(
                json.dumps({"scripts": {"build": "webpack --mode production"}}),
                encoding="utf-8",
            )

            with mock.patch("secopsai.triage.supply_chain.supply_chain.explain_policy", return_value={"allow_matches": [], "deny_matches": []}), \
                 mock.patch("secopsai.triage.supply_chain.supply_chain.explain_verdict", return_value={
                     "score": 17,
                     "effective_threshold": 10,
                     "matched_rules": [
                         {"rule": "subprocess spawn"},
                     ],
                 }), \
                 mock.patch("secopsai.triage.supply_chain._reputation_summary", return_value={"release_count": 20}):
                result = investigate_finding(
                    "SCM-BUILD001",
                    db_path=db_path,
                    search_root=str(temp_path),
                    report_dir=str(temp_path / "triage"),
                )

            self.assertFalse(result["investigation"]["dependency_presence"]["present"])
            self.assertEqual(
                result["investigation"]["exposure_assessment"]["status"],
                "not_observed_in_scope",
            )
            self.assertEqual(result["investigation"]["recommended_disposition"], "needs_review")
            self.assertEqual(
                result["investigation"]["actionability"]["package_intelligence"],
                "actionable",
            )

    def test_advisory_backed_package_stays_true_positive_without_local_reference(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            report_path = temp_path / "npm-widget-1.0.0-to-1.0.1.md"
            report_path.write_text("fake report", encoding="utf-8")
            findings = [
                {
                    "finding_id": "SCM-ADVISORY001",
                    "title": "Suspicious npm package release: widget@1.0.1",
                    "summary": "Source-backed advisory matched the exact version.",
                    "severity": "critical",
                    "severity_score": 98,
                    "status": "open",
                    "disposition": "unreviewed",
                    "source": "secopsai-supply-chain",
                    "first_seen": "2026-04-06T00:00:00Z",
                    "last_seen": "2026-04-06T00:00:00Z",
                    "platform": "supply_chain",
                    "package": "widget",
                    "ecosystem": "npm",
                    "new_version": "1.0.1",
                    "old_version": "1.0.0",
                    "report_path": str(report_path),
                    "verdict": "malicious",
                    "advisory_matches": [
                        {
                            "advisory_id": "ADV-TEST-001",
                            "source_urls": ["https://example.test/advisory"],
                        }
                    ],
                    "advisory_ids": ["ADV-TEST-001"],
                }
            ]
            _write_findings(db_path, findings)

            with mock.patch(
                "secopsai.triage.supply_chain.supply_chain.explain_policy",
                return_value={"allow_matches": [], "deny_matches": []},
            ), mock.patch(
                "secopsai.triage.supply_chain.supply_chain.explain_verdict",
                return_value={
                    "score": 20,
                    "effective_threshold": 10,
                    "verdict": "malicious",
                    "matched_rules": [{"rule": "emergency advisory match"}],
                },
            ), mock.patch(
                "secopsai.triage.supply_chain._reputation_summary",
                return_value={"release_count": 2},
            ):
                result = investigate_finding(
                    "SCM-ADVISORY001",
                    db_path=db_path,
                    search_root=str(temp_path),
                    report_dir=str(temp_path / "triage"),
                )

            investigation = result["investigation"]
            self.assertEqual(investigation["recommended_disposition"], "true_positive")
            self.assertEqual(
                investigation["threat_assessment"]["verdict"], "confirmed_malicious"
            )
            self.assertEqual(
                investigation["exposure_assessment"]["status"], "not_observed_in_scope"
            )
            self.assertEqual(
                investigation["actionability"]["local_response"],
                "verify_enterprise_exposure",
            )
            markdown = Path(result["markdown_report"]).read_text(encoding="utf-8")
            self.assertIn("Package Threat Assessment", markdown)
            self.assertIn("Environment Exposure Assessment", markdown)

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
            self.assertEqual(list_triage_findings(db_path=db_path, status="open"), [])
            triaged_rows = list_triage_findings(db_path=db_path, status="triaged")
            self.assertEqual(len(triaged_rows), 1)
            self.assertEqual(triaged_rows[0]["finding_id"], "OCF-TEST123")

    def test_supply_chain_close_is_excluded_from_open_list_for_db_override(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            findings = [
                {
                    "finding_id": "SCM-TEST001",
                    "title": "Suspicious pypi package release: demo@1.2.3",
                    "summary": "Deterministic rules flagged: network egress, startup persistence",
                    "severity": "critical",
                    "severity_score": 90,
                    "status": "open",
                    "disposition": "unreviewed",
                    "source": "secopsai-supply-chain",
                    "first_seen": "2026-04-09T10:00:00Z",
                    "last_seen": "2026-04-09T10:00:00Z",
                    "event_ids": ["evt-1"],
                    "rule_ids": ["SUPPLY-CHAIN-NATIVE"],
                    "platform": "supply_chain",
                    "package": "demo",
                    "ecosystem": "pypi",
                    "new_version": "1.2.3",
                    "old_version": "1.2.2",
                    "report_path": "/tmp/demo.md",
                    "analysis": "demo analysis",
                    "verdict": "malicious",
                    "rank": 42,
                },
                {
                    "finding_id": "SCM-TEST002",
                    "title": "Suspicious npm package release: other@9.9.9",
                    "summary": "Deterministic rules flagged: shell downloader",
                    "severity": "critical",
                    "severity_score": 90,
                    "status": "open",
                    "disposition": "unreviewed",
                    "source": "secopsai-supply-chain",
                    "first_seen": "2026-04-09T10:10:00Z",
                    "last_seen": "2026-04-09T10:10:00Z",
                    "event_ids": ["evt-2"],
                    "rule_ids": ["SUPPLY-CHAIN-NATIVE"],
                    "platform": "supply_chain",
                    "package": "other",
                    "ecosystem": "npm",
                    "new_version": "9.9.9",
                    "old_version": "9.9.8",
                    "report_path": "/tmp/other.md",
                    "analysis": "other analysis",
                    "verdict": "malicious",
                    "rank": 43,
                },
            ]
            _write_findings(db_path, findings)

            close_finding(
                "SCM-TEST001",
                db_path=db_path,
                disposition="needs_review",
                status="closed",
                author="analyst",
                note="Regression test note for db override filtering.",
            )

            open_rows = list_triage_findings(db_path=db_path, status="open")
            self.assertEqual([row["finding_id"] for row in open_rows], ["SCM-TEST002"])

            closed_rows = list_triage_findings(db_path=db_path, status="closed")
            self.assertEqual([row["finding_id"] for row in closed_rows], ["SCM-TEST001"])

    def test_triage_list_uses_batched_store_rows_for_category_filtering(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            _write_findings(
                db_path,
                [
                    {
                        "finding_id": "SCM-BATCH001",
                        "title": "Suspicious npm package release: demo@1.0.0",
                        "summary": "supply-chain test",
                        "severity": "high",
                        "severity_score": 80,
                        "status": "open",
                        "disposition": "unreviewed",
                        "source": "secopsai-supply-chain",
                        "first_seen": "2026-04-09T10:00:00Z",
                        "last_seen": "2026-04-09T10:00:00Z",
                        "event_ids": [],
                        "platform": "supply_chain",
                    },
                    {
                        "finding_id": "OCF-BATCH002",
                        "title": "OpenClaw Policy Denials",
                        "summary": "policy denial test",
                        "severity": "low",
                        "severity_score": 10,
                        "status": "open",
                        "disposition": "unreviewed",
                        "source": "secopsai_cli",
                        "first_seen": "2026-04-09T11:00:00Z",
                        "last_seen": "2026-04-09T11:00:00Z",
                        "event_ids": [],
                    },
                ],
            )

            with mock.patch("soc_store.get_finding", side_effect=AssertionError("N+1 detail lookup")):
                rows = list_triage_findings(db_path=db_path, status="open", category="supply_chain", limit=5)

            self.assertEqual([row["finding_id"] for row in rows], ["SCM-BATCH001"])
            self.assertEqual(rows[0]["category"], "supply_chain")


if __name__ == "__main__":
    unittest.main()
