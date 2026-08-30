from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import soc_store
from secopsai import cli
from secopsai.research import build_preflight_report, research_finding, research_package
from secopsai.sessions import create_session, load_session


def _write_findings(db_path: str, findings: list[dict]) -> None:
    soc_store.persist_findings(findings, source="secopsai-test", db_path=db_path)


class ResearchTests(unittest.TestCase):
    def test_build_preflight_report_flags_stale_replay_and_export_bridge(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            repo = temp_path / "repo"
            logs = temp_path / "logs"
            openclaw_home = temp_path / "openclaw"
            (repo / "data" / "intel").mkdir(parents=True, exist_ok=True)
            (repo / "data" / "openclaw" / "replay" / "labeled").mkdir(parents=True, exist_ok=True)
            (repo / "data" / "openclaw" / "replay" / "unlabeled").mkdir(parents=True, exist_ok=True)
            (repo / "data" / "openclaw" / "findings").mkdir(parents=True, exist_ok=True)
            (logs).mkdir(parents=True, exist_ok=True)
            (openclaw_home / "agents" / "main" / "sessions").mkdir(parents=True, exist_ok=True)

            (repo / "data" / "intel" / "iocs.json").write_text(
                json.dumps(
                    {
                        "generated_at": "2026-04-22T01:00:00Z",
                        "iocs": [{"ioc_type": "url", "value": "https://bad.test", "source": "urlhaus", "tags": ["malware_download"]}],
                    }
                ),
                encoding="utf-8",
            )
            replay_payload = [{"timestamp": "2026-04-16T18:01:29Z", "event_type": "tool", "status": "failed"}]
            (repo / "data" / "openclaw" / "replay" / "labeled" / "current.json").write_text(
                json.dumps(replay_payload),
                encoding="utf-8",
            )
            (repo / "data" / "openclaw" / "replay" / "unlabeled" / "current.json").write_text(
                json.dumps(replay_payload),
                encoding="utf-8",
            )
            (repo / "data" / "openclaw" / "findings" / "openclaw-findings-20260416-181650.json").write_text(
                json.dumps(
                    {
                        "generated_at": "2026-04-16T18:16:50Z",
                        "total_events": 2533,
                        "total_detections": 0,
                        "total_candidate_findings": 0,
                        "total_findings": 0,
                    }
                ),
                encoding="utf-8",
            )
            session_file = openclaw_home / "agents" / "main" / "sessions" / "latest.jsonl"
            session_file.write_text("{}\n", encoding="utf-8")

            with mock.patch("scripts.secopsai_report_snapshot._now_utc") as mocked_now:
                from datetime import datetime, timezone

                mocked_now.return_value = datetime(2026, 4, 22, 12, 0, 0, tzinfo=timezone.utc)
                preflight = build_preflight_report(
                    repo=str(repo),
                    workspace_logs=str(logs),
                    openclaw_home=str(openclaw_home),
                )

            self.assertEqual(preflight["status"], "block")
            issue_codes = {item["code"] for item in preflight["issues"]}
            self.assertIn("telemetry_stale", issue_codes)
            self.assertIn("export_bridge_stale", issue_codes)

    def test_build_preflight_report_warns_when_openclaw_source_is_idle(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            repo = temp_path / "repo"
            logs = temp_path / "logs"
            openclaw_home = temp_path / "openclaw"
            (repo / "data" / "intel").mkdir(parents=True, exist_ok=True)
            (repo / "data" / "openclaw" / "replay" / "labeled").mkdir(parents=True, exist_ok=True)
            (repo / "data" / "openclaw" / "replay" / "unlabeled").mkdir(parents=True, exist_ok=True)
            (repo / "data" / "openclaw" / "findings").mkdir(parents=True, exist_ok=True)
            logs.mkdir(parents=True, exist_ok=True)
            (openclaw_home / "agents" / "main" / "sessions").mkdir(parents=True, exist_ok=True)

            (repo / "data" / "intel" / "iocs.json").write_text(
                json.dumps({"generated_at": "2026-04-22T01:00:00Z", "iocs": []}),
                encoding="utf-8",
            )
            replay_payload = [{"timestamp": "2026-04-16T18:01:29Z", "event_type": "tool", "status": "ok"}]
            (repo / "data" / "openclaw" / "replay" / "labeled" / "current.json").write_text(
                json.dumps(replay_payload),
                encoding="utf-8",
            )
            (repo / "data" / "openclaw" / "replay" / "unlabeled" / "current.json").write_text(
                json.dumps(replay_payload),
                encoding="utf-8",
            )
            (repo / "data" / "openclaw" / "findings" / "openclaw-findings-20260422-110000.json").write_text(
                json.dumps(
                    {
                        "generated_at": "2026-04-22T11:00:00Z",
                        "total_events": 1,
                        "total_detections": 0,
                        "total_candidate_findings": 0,
                        "total_findings": 0,
                    }
                ),
                encoding="utf-8",
            )
            session_file = openclaw_home / "agents" / "main" / "sessions" / "old.jsonl"
            session_file.write_text("{}\n", encoding="utf-8")
            old_epoch = 1776708000  # 2026-04-20T18:00:00Z
            os.utime(session_file, (old_epoch, old_epoch))

            with mock.patch("scripts.secopsai_report_snapshot._now_utc") as mocked_now:
                from datetime import datetime, timezone

                mocked_now.return_value = datetime(2026, 4, 22, 12, 0, 0, tzinfo=timezone.utc)
                preflight = build_preflight_report(
                    repo=str(repo),
                    workspace_logs=str(logs),
                    openclaw_home=str(openclaw_home),
                )

            self.assertEqual(preflight["status"], "warn")
            issue_codes = {item["code"] for item in preflight["issues"]}
            self.assertIn("openclaw_source_idle", issue_codes)
            self.assertNotIn("telemetry_stale", issue_codes)
            self.assertNotIn("export_bridge_stale", issue_codes)
            self.assertIn("openclaw_source_idle", preflight["staleness_flags"])

    def test_research_package_writes_reports_and_detects_local_presence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            report_path = temp_path / "diff-report.md"
            report_path.write_text("# Diff\n", encoding="utf-8")
            (temp_path / "package.json").write_text(
                json.dumps({"dependencies": {"widget": "1.0.1"}}),
                encoding="utf-8",
            )

            with mock.patch(
                "secopsai.research.load_recent_results",
                return_value=[
                    {
                        "ecosystem": "npm",
                        "package": "widget",
                        "new_version": "1.0.1",
                        "verdict": "suspicious",
                        "report_path": str(report_path),
                    }
                ],
            ), mock.patch(
                "secopsai.research.explain_policy",
                return_value={"effective_threshold": 10, "allow_matches": [], "deny_matches": [], "precedence": ["global"]},
            ):
                payload = research_package(
                    ecosystem="npm",
                    package="widget",
                    version="1.0.1",
                    search_root=str(temp_path),
                    report_dir=str(temp_path / "reports"),
                )

            self.assertTrue(payload["local_presence"]["present"])
            self.assertTrue(Path(payload["json_report"]).exists())
            self.assertTrue(Path(payload["markdown_report"]).exists())
            self.assertIn(str(report_path), Path(payload["markdown_report"]).read_text(encoding="utf-8"))
            self.assertIn("inside the current code boundary", " ".join(payload["observations"]))

    def test_research_package_prunes_generated_project_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            generated_report = temp_path / "reports" / "old-run" / "package.json"
            generated_report.parent.mkdir(parents=True)
            generated_report.write_text(
                json.dumps({"dependencies": {"generated-only-package": "1.0.0"}}),
                encoding="utf-8",
            )

            with mock.patch("secopsai.research.ROOT", temp_path), mock.patch(
                "secopsai.research.load_recent_results",
                return_value=[],
            ), mock.patch(
                "secopsai.research.explain_policy",
                return_value={"effective_threshold": 10, "allow_matches": [], "deny_matches": [], "precedence": ["global"]},
            ):
                payload = research_package(
                    ecosystem="npm",
                    package="generated-only-package",
                    version="1.0.0",
                    search_root=str(temp_path),
                    report_dir=str(temp_path / "output"),
                )

            self.assertFalse(payload["local_presence"]["present"])
            self.assertEqual(payload["local_presence"]["manifest_matches"], [])
            self.assertEqual(payload["local_presence"]["repo_matches"], [])

    def test_research_finding_supply_chain_sources_accept_local_report_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            report_path = temp_path / "diff-report.md"
            report_path.write_text("# Diff\n", encoding="utf-8")
            _write_findings(
                db_path,
                [
                    {
                        "finding_id": "SCM-LOCALREPORT",
                        "title": "Suspicious npm package release: widget@1.0.1",
                        "summary": "Deterministic rules flagged widget.",
                        "severity": "critical",
                        "severity_score": 90,
                        "status": "open",
                        "disposition": "unreviewed",
                        "source": "secopsai-supply-chain",
                        "first_seen": "2026-04-06T00:00:00Z",
                        "last_seen": "2026-04-06T00:00:00Z",
                        "platform": "supply_chain",
                        "package": "widget",
                        "ecosystem": "npm",
                        "new_version": "1.0.1",
                    }
                ],
            )

            with mock.patch(
                "secopsai.research.load_recent_results",
                return_value=[
                    {
                        "ecosystem": "npm",
                        "package": "widget",
                        "new_version": "1.0.1",
                        "verdict": "suspicious",
                        "report_path": str(report_path),
                    }
                ],
            ), mock.patch(
                "secopsai.research.explain_policy",
                return_value={"effective_threshold": 10, "allow_matches": [], "deny_matches": [], "precedence": ["global"]},
            ):
                payload = research_finding(
                    finding_id="SCM-LOCALREPORT",
                    db_path=db_path,
                    search_root=str(temp_path),
                    report_dir=str(temp_path / "reports"),
                )

            self.assertIn(str(report_path), Path(payload["markdown_report"]).read_text(encoding="utf-8"))

    def test_research_finding_cli_attaches_reports_to_session(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            session_dir = str(temp_path / "sessions")
            report_dir = temp_path / "reports"
            report_dir.mkdir(parents=True, exist_ok=True)
            json_report = report_dir / "research.json"
            markdown_report = report_dir / "research.md"
            json_report.write_text("{}", encoding="utf-8")
            markdown_report.write_text("# Research\n", encoding="utf-8")
            _write_findings(
                db_path,
                [
                    {
                        "finding_id": "SCM-RESEARCH1",
                        "title": "Suspicious npm package release: widget@1.0.1",
                        "summary": "Deterministic rules flagged widget.",
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
                    }
                ],
            )

            session = create_session(
                kind="triage",
                title="Research SCM-RESEARCH1",
                subject={"finding_id": "SCM-RESEARCH1"},
                initial_plan=[],
                path=session_dir,
            )

            stdout = io.StringIO()
            with mock.patch.object(
                cli,
                "research_finding_report",
                return_value={
                    "summary": "widget appears in local manifests",
                    "observations": ["widget is present"],
                    "json_report": str(json_report),
                    "markdown_report": str(markdown_report),
                },
            ), redirect_stdout(stdout):
                exit_code = cli.main(
                    [
                        "--json",
                        "research",
                        "finding",
                        "SCM-RESEARCH1",
                        "--db-path",
                        db_path,
                        "--session-id",
                        session["session_id"],
                        "--session-dir",
                        session_dir,
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["session_id"], session["session_id"])
            loaded = load_session(session["session_id"], session_dir)
            artifact_kinds = {item["kind"] for item in loaded["artifacts"]}
            self.assertEqual(artifact_kinds, {"research_json_report", "research_markdown_report"})


if __name__ == "__main__":
    unittest.main()
