from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from secopsai.agent_core import DoomLoopDetector, ToolRouter, compact_session_context, list_jobs, run_isolated_job
from secopsai.sessions import add_event, create_session


class AgentCoreTests(unittest.TestCase):
    def test_tool_router_blocks_write_and_expensive_tools_until_allowed(self) -> None:
        router = ToolRouter()
        blocked = router.route("research package and apply approval action")
        self.assertTrue(any(item["tool"]["name"] == "research.package" for item in blocked["selected"]))
        self.assertTrue(any(item["reason"] == "write_gate" for item in blocked["blocked"]))

        allowed = router.route("apply approval action", allow_writes=True)
        self.assertTrue(any(item["tool"]["mode"] == "write" for item in allowed["selected"]))

    def test_doom_loop_detector_flags_repeated_events(self) -> None:
        detector = DoomLoopDetector(threshold=3)
        result = detector.analyze(
            [
                {"type": "tool", "message": "retry failed command", "status": "failed"},
                {"type": "tool", "message": "retry failed command", "status": "failed"},
                {"type": "tool", "message": "retry failed command", "status": "failed"},
            ]
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["repeated"][0]["streak"], 3)

    def test_compact_session_context_keeps_recent_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            session = create_session(
                title="Investigate SCM-1",
                kind="triage",
                subject={"finding_id": "SCM-1"},
                initial_plan=[{"title": "Inspect", "status": "completed"}],
                path=tmp,
            )
            add_event(session["session_id"], event_type="note", message="Collected evidence", path=tmp)
            compact = compact_session_context(session["session_id"], session_dir=tmp)
            self.assertEqual(compact["subject"]["finding_id"], "SCM-1")
            self.assertEqual(compact["progress"]["plan_completed"], 1)
            self.assertTrue(compact["recent_events"])

    def test_run_isolated_job_records_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            job = run_isolated_job(
                name="preflight-help",
                command=["python3", "-m", "secopsai.cli", "--help"],
                cwd=str(Path(__file__).resolve().parents[1]),
                timeout=30,
                path=tmp,
            )
            self.assertEqual(job["status"], "completed")
            self.assertTrue(Path(job["stdout_path"]).exists())
            self.assertEqual(list_jobs(path=tmp)[0]["job_id"], job["job_id"])


if __name__ == "__main__":
    unittest.main()
