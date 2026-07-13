from __future__ import annotations

import io
import json
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
from secopsai.sessions import load_session


def _write_findings(db_path: str, findings: list[dict]) -> None:
    soc_store.persist_findings(findings, source="secopsai-test", db_path=db_path)


class SessionCliTests(unittest.TestCase):
    def test_session_create_from_finding_seeds_triage_subject_and_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            session_dir = str(temp_path / "sessions")
            _write_findings(
                db_path,
                [
                    {
                        "finding_id": "SCM-TEST123",
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
                    }
                ],
            )

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli.main(
                    [
                        "--json",
                        "session",
                        "create",
                        "--finding-id",
                        "SCM-TEST123",
                        "--db-path",
                        db_path,
                        "--session-dir",
                        session_dir,
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["session"]["kind"], "triage")
            self.assertEqual(payload["session"]["subject"]["finding_id"], "SCM-TEST123")
            self.assertEqual(len(payload["session"]["plan"]), 4)

    def test_triage_investigate_open_session_attaches_reports_and_updates_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            session_dir = str(temp_path / "sessions")
            json_report = temp_path / "triage-report.json"
            markdown_report = temp_path / "triage-report.md"
            json_report.write_text("{}", encoding="utf-8")
            markdown_report.write_text("# Report\n", encoding="utf-8")
            finding = {
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
                "event_ids": ["evt-1"],
                "rule_ids": ["RULE-104"],
                "events": [{"status": "failed", "action": "deny", "session_key": "s1"}],
            }
            _write_findings(db_path, [finding])

            fake_result = {
                "finding_id": "OCF-TEST123",
                "category": "policy_denial",
                "finding": finding,
                "investigation": {
                    "recommended_disposition": "tune_policy",
                    "confidence": "medium",
                    "summary": "Repeated benign workflow; review the policy.",
                    "next_actions": ["Tune the rule"],
                },
                "json_report": str(json_report),
                "markdown_report": str(markdown_report),
            }

            stdout = io.StringIO()
            with mock.patch.object(cli, "investigate_finding", return_value=fake_result), redirect_stdout(stdout):
                exit_code = cli.main(
                    [
                        "--json",
                        "triage",
                        "investigate",
                        "OCF-TEST123",
                        "--db-path",
                        db_path,
                        "--session-dir",
                        session_dir,
                        "--open-session",
                    ]
                )

            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            session = load_session(payload["session_id"], session_dir)
            artifact_kinds = {item["kind"] for item in session["artifacts"]}
            plan_status = {item["title"]: item["status"] for item in session["plan"]}

            self.assertEqual(artifact_kinds, {"triage_json_report", "triage_markdown_report"})
            self.assertEqual(plan_status["Review finding context"], "completed")
            self.assertEqual(plan_status["Investigate locally"], "completed")
            self.assertEqual(plan_status["Decide disposition"], "in_progress")

    def test_session_resolve_approval_apply_can_close_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            session_dir = str(temp_path / "sessions")
            _write_findings(
                db_path,
                [
                    {
                        "finding_id": "OCF-TEST999",
                        "title": "OpenClaw Policy Denials",
                        "summary": "Repeated denials across a benign workflow.",
                        "severity": "low",
                        "severity_score": 25,
                        "status": "open",
                        "disposition": "unreviewed",
                        "source": "secopsai_cli",
                        "first_seen": "2026-04-06T00:00:00Z",
                        "last_seen": "2026-04-06T00:00:00Z",
                        "event_ids": ["evt-1"],
                        "rule_ids": ["RULE-104"],
                        "events": [{"status": "failed", "action": "deny", "session_key": "s1"}],
                    }
                ],
            )

            create_stdout = io.StringIO()
            with redirect_stdout(create_stdout):
                create_exit = cli.main(
                    [
                        "--json",
                        "session",
                        "create",
                        "--kind",
                        "triage",
                        "--finding-id",
                        "OCF-TEST999",
                        "--db-path",
                        db_path,
                        "--session-dir",
                        session_dir,
                    ]
                )
            self.assertEqual(create_exit, 0)
            session_id = json.loads(create_stdout.getvalue())["session"]["session_id"]

            request_stdout = io.StringIO()
            with redirect_stdout(request_stdout):
                request_exit = cli.main(
                    [
                        "--json",
                        "session",
                        "request-approval",
                        session_id,
                        "--type",
                        "triage_close",
                        "--finding-id",
                        "OCF-TEST999",
                        "--disposition",
                        "expected_behavior",
                        "--status",
                        "closed",
                        "--note",
                        "Approved internal reporting workflow.",
                        "--db-path",
                        db_path,
                        "--session-dir",
                        session_dir,
                    ]
                )
            self.assertEqual(request_exit, 0)
            approval_id = json.loads(request_stdout.getvalue())["approval"]["approval_id"]

            resolve_stdout = io.StringIO()
            with redirect_stdout(resolve_stdout):
                resolve_exit = cli.main(
                    [
                        "--json",
                        "session",
                        "resolve-approval",
                        session_id,
                        approval_id,
                        "--approve",
                        "--apply",
                        "--decided-by",
                        "lead-analyst",
                        "--db-path",
                        db_path,
                        "--session-dir",
                        session_dir,
                    ]
                )

            self.assertEqual(resolve_exit, 0)
            resolved = json.loads(resolve_stdout.getvalue())
            self.assertEqual(resolved["approval"]["state"], "approved")
            self.assertEqual(resolved["applied"]["kind"], "triage_close")

            updated_finding = soc_store.get_finding("OCF-TEST999", db_path)
            self.assertIsNotNone(updated_finding)
            self.assertEqual(updated_finding["status"], "closed")
            self.assertEqual(updated_finding["disposition"], "expected_behavior")

            session = load_session(session_id, session_dir)
            self.assertEqual(session["status"], "closed")

    def test_approved_edge_scan_queues_through_local_helper_without_raw_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            session_dir = str(temp_path / "sessions")
            edge_root = temp_path / "edge"
            edge_script = edge_root / "scripts" / "edge"
            edge_script.parent.mkdir(parents=True)
            edge_script.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > '" + str(temp_path / "edge-args.txt") + "'\n"
                "printf '%s' 'raw nmap output must never enter Core'\n",
                encoding="utf-8",
            )
            edge_script.chmod(0o700)

            create_stdout = io.StringIO()
            with redirect_stdout(create_stdout):
                self.assertEqual(
                    cli.main(
                        [
                            "--json",
                            "session",
                            "create",
                            "--kind",
                            "edge_scan",
                            "--title",
                            "Approved Edge scan",
                            "--session-dir",
                            session_dir,
                        ]
                    ),
                    0,
                )
            session_id = json.loads(create_stdout.getvalue())["session"]["session_id"]

            request_stdout = io.StringIO()
            with redirect_stdout(request_stdout):
                self.assertEqual(
                    cli.main(
                        [
                            "--json",
                            "session",
                            "request-approval",
                            session_id,
                            "--type",
                            "custom",
                            "--summary",
                            "Queue approved Edge scan",
                            "--payload",
                            json.dumps(
                                {
                                    "kind": "edge_scan",
                                    "target_cidr": "10.20.30.7/24",
                                    "include_wifi": True,
                                }
                            ),
                            "--session-dir",
                            session_dir,
                        ]
                    ),
                    0,
                )
            approval_id = json.loads(request_stdout.getvalue())["approval"]["approval_id"]

            resolve_stdout = io.StringIO()
            with redirect_stdout(resolve_stdout):
                self.assertEqual(
                    cli.main(
                        [
                            "--json",
                            "session",
                            "resolve-approval",
                            session_id,
                            approval_id,
                            "--approve",
                            "--apply",
                            "--edge-root",
                            str(edge_root),
                            "--session-dir",
                            session_dir,
                        ]
                    ),
                    0,
                )

            resolved = json.loads(resolve_stdout.getvalue())
            self.assertEqual(resolved["applied"]["kind"], "edge_scan")
            self.assertEqual(resolved["applied"]["result"]["status"], "queued")
            self.assertEqual(
                (temp_path / "edge-args.txt").read_text(encoding="utf-8").splitlines(),
                ["queue", "10.20.30.0/24", "--cloud", "--wifi"],
            )
            serialized = json.dumps(load_session(session_id, session_dir))
            self.assertNotIn("raw nmap output", serialized)
            self.assertIn("edge_scan_queued", serialized)


if __name__ == "__main__":
    unittest.main()
