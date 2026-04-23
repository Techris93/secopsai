import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from secopsai.sessions import (
    add_artifact,
    add_note,
    create_session,
    list_sessions,
    load_session,
    request_approval,
    resolve_approval,
    set_session_status,
    update_step,
)


class SessionRuntimeTests(unittest.TestCase):
    def test_session_lifecycle_persists_plan_notes_artifacts_and_approvals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.json"
            report_path.write_text("{}", encoding="utf-8")

            session = create_session(
                kind="triage",
                title="Triage OCF-1",
                subject={"finding_id": "OCF-1", "title": "Test Finding"},
                initial_plan=[{"title": "Review finding context", "status": "pending"}],
                path=temp_dir,
            )
            session_id = session["session_id"]

            add_note(session_id, message="Started review", author="analyst", path=temp_dir)
            update_step(
                session_id,
                step="Review finding context",
                status="completed",
                note="Context loaded",
                path=temp_dir,
            )
            add_artifact(
                session_id,
                kind="triage_json_report",
                artifact_path=str(report_path),
                label="JSON report",
                path=temp_dir,
            )
            approval = request_approval(
                session_id,
                approval_type="triage_close",
                summary="Approve closure",
                payload={"kind": "triage_close", "finding_id": "OCF-1"},
                requested_by="analyst",
                path=temp_dir,
            )
            resolve_approval(
                session_id,
                approval["approval_id"],
                decision="approved",
                note="Looks good",
                decided_by="lead",
                path=temp_dir,
            )
            set_session_status(session_id, status="closed", message="Completed", path=temp_dir)

            loaded = load_session(session_id, temp_dir)
            self.assertEqual(loaded["status"], "closed")
            self.assertEqual(loaded["subject"]["finding_id"], "OCF-1")
            self.assertEqual(loaded["plan"][0]["status"], "completed")
            self.assertEqual(loaded["artifacts"][0]["path"], str(report_path.resolve()))
            self.assertEqual(loaded["approvals"][0]["state"], "approved")
            self.assertEqual(loaded["approvals"][0]["decided_by"], "lead")
            self.assertEqual(list_sessions(finding_id="OCF-1", path=temp_dir)[0]["session_id"], session_id)


if __name__ == "__main__":
    unittest.main()
