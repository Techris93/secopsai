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
from secopsai.triage import (
    apply_action,
    generate_summary,
    list_actions,
    orchestrate_findings,
    reconcile_exposure_closures,
)


def _write_findings(db_path: str, findings):
    soc_store.persist_findings(findings, source="secopsai-test", db_path=db_path)


class TriageOrchestratorTests(unittest.TestCase):
    def test_reconcile_exposure_closures_is_narrow_previewable_and_audited(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            base = {
                "title": "Suspicious npm package release",
                "summary": "Deterministic rules flagged credential access.",
                "severity": "critical",
                "severity_score": 90,
                "status": "closed",
                "disposition": "expected_behavior",
                "source": "secopsai-supply-chain",
                "first_seen": "2026-04-08T00:00:00Z",
                "last_seen": "2026-04-08T00:00:00Z",
                "platform": "supply_chain",
                "ecosystem": "npm",
                "new_version": "1.0.1",
                "old_version": "1.0.0",
                "verdict": "malicious",
            }
            soc_store.persist_findings(
                [
                    {**base, "finding_id": "SCM-LEGACY001", "package": "legacy-package"},
                    {**base, "finding_id": "SCM-MANUAL002", "package": "manual-package"},
                    {
                        **base,
                        "finding_id": "SCM-BENIGN003",
                        "package": "benign-package",
                        "verdict": "benign",
                    },
                ],
                source="secopsai-supply-chain",
                db_path=db_path,
            )
            soc_store.add_note(
                "SCM-LEGACY001",
                "old-orchestrator",
                "Package is not referenced in local dependency manifests; treating as ecosystem intelligence outside current risk boundary.",
                db_path,
            )
            soc_store.add_note(
                "SCM-MANUAL002",
                "analyst",
                "Expected behavior was confirmed from source and maintainer evidence.",
                db_path,
            )
            soc_store.add_note(
                "SCM-BENIGN003",
                "old-orchestrator",
                "Package is not referenced in local dependency manifests.",
                db_path,
            )

            preview = reconcile_exposure_closures(db_path=db_path)
            self.assertEqual(preview["candidate_count"], 1)
            self.assertEqual(preview["reopened_count"], 0)
            self.assertEqual(
                soc_store.get_finding("SCM-LEGACY001", db_path)["status"], "closed"
            )

            applied = reconcile_exposure_closures(db_path=db_path, apply=True)
            self.assertEqual(applied["reopened_count"], 1)
            reopened = soc_store.get_finding("SCM-LEGACY001", db_path)
            self.assertEqual(reopened["status"], "open")
            self.assertEqual(reopened["disposition"], "unreviewed")
            self.assertIn("policy correction", reopened["notes"][-1]["note"])
            self.assertEqual(
                soc_store.get_finding("SCM-MANUAL002", db_path)["status"], "closed"
            )
            self.assertEqual(
                soc_store.get_finding("SCM-BENIGN003", db_path)["status"], "closed"
            )

    def test_orchestrate_keeps_external_package_intelligence_open_without_local_reference(self):
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
            self.assertEqual(result.auto_applied, 0)
            self.assertEqual(result.queued, 1)
            updated = soc_store.get_finding("SCM-AUTO001", db_path)
            self.assertEqual(updated["status"], "in_review")
            self.assertEqual(updated["disposition"], "unreviewed")
            queued = list_actions(path=queue_file)
            self.assertEqual(queued[0]["payload"]["disposition"], "needs_review")
            self.assertIn("local exposure was not observed", queued[0]["summary"].lower())
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

    def test_weak_external_signal_requires_review_instead_of_automatic_allowlist(self):
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
            action = list_actions(path=queue_file)[0]
            self.assertEqual(action["action_type"], "close_finding")
            self.assertEqual(action["payload"]["disposition"], "needs_review")
            updated = apply_action(
                action["action_id"],
                queue_file=queue_file,
                db_path=db_path,
                author="tester",
                yes=True,
            )

            self.assertEqual(updated["status"], "applied")
            finding = soc_store.get_finding("SCM-ALLOW001", db_path)
            self.assertEqual(finding["disposition"], "needs_review")
            self.assertEqual(finding["status"], "triaged")

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

    def test_generate_summary_counts_open_findings_beyond_display_limit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            findings = []
            for idx in range(25):
                findings.append(
                    {
                        "finding_id": f"SCM-SUM{idx:03d}",
                        "title": f"Closed finding {idx}",
                        "summary": "Closed finding.",
                        "severity": "critical",
                        "severity_score": 90 - idx,
                        "status": "closed",
                        "disposition": "expected_behavior",
                        "source": "secopsai-test",
                        "first_seen": "2026-04-08T00:00:00Z",
                        "last_seen": "2026-04-08T00:00:00Z",
                    }
                )
            findings.extend(
                [
                    {
                        "finding_id": "OCF-SUMOPEN1",
                        "title": "OpenClaw Policy Denials",
                        "summary": "Open finding.",
                        "severity": "low",
                        "severity_score": 20,
                        "status": "open",
                        "disposition": "unreviewed",
                        "source": "secopsai-test",
                        "first_seen": "2026-04-08T00:00:00Z",
                        "last_seen": "2026-04-08T00:00:00Z",
                    },
                    {
                        "finding_id": "OCF-SUMOPEN2",
                        "title": "OpenClaw Data Exfiltration",
                        "summary": "Open finding.",
                        "severity": "low",
                        "severity_score": 20,
                        "status": "open",
                        "disposition": "unreviewed",
                        "source": "secopsai-test",
                        "first_seen": "2026-04-08T00:00:00Z",
                        "last_seen": "2026-04-08T00:00:00Z",
                    },
                ]
            )
            _write_findings(db_path, findings)
            summary = generate_summary(db_path=db_path, summary_dir=str(temp_path / "summaries"), limit=20)
            self.assertEqual(summary["open_findings"], 2)
            self.assertEqual(len(summary["findings"]), 20)


if __name__ == "__main__":
    unittest.main()
