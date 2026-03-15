import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ingest_openclaw
import openclaw_prepare


def write_jsonl(path: Path, records: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record))
            handle.write("\n")


class OpenClawIngestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.audit_schema = openclaw_prepare.load_json(str(REPO_ROOT / "schemas" / "openclaw_audit.schema.json"))

    def test_collect_records_from_native_surface_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_jsonl(
                root / "agent-events.jsonl",
                [
                    {
                        "ts": "2026-03-15T10:00:00Z",
                        "stream": "tool_execution_start",
                        "runId": "run-1",
                        "sessionKey": "agent:main:discord:dm:test",
                        "data": {
                            "phase": "start",
                            "toolName": "exec",
                            "toolCallId": "call-1",
                            "agentId": "main",
                            "args": {"command": "pwd"},
                            "mutating": False,
                        },
                    }
                ],
            )
            write_jsonl(
                root / "session-hooks.jsonl",
                [
                    {
                        "ts": "2026-03-15T10:00:01Z",
                        "hook": "session_start",
                        "context": {
                            "sessionId": "sess-1",
                            "sessionKey": "agent:main:discord:dm:test",
                            "agentId": "main",
                            "channel": "discord",
                        },
                    }
                ],
            )
            write_jsonl(
                root / "subagent-hooks.jsonl",
                [
                    {
                        "ts": "2026-03-15T10:00:02Z",
                        "hook": "subagent_spawned",
                        "runId": "run-1",
                        "sessionKey": "agent:main:discord:dm:test",
                        "childSessionKey": "agent:child:discord:dm:test",
                        "requesterSessionKey": "agent:main:discord:dm:test",
                    }
                ],
            )
            write_jsonl(
                root / "config-audit.jsonl",
                [
                    {
                        "ts": "2026-03-15T10:00:03Z",
                        "kind": "config.patch",
                        "action": "patch",
                        "sessionKey": "agent:main:discord:dm:test",
                        "changedPaths": ["tools.exec.security"],
                    }
                ],
            )
            write_jsonl(
                root / "restart-sentinels.jsonl",
                [
                    {
                        "ts": "2026-03-15T10:00:04Z",
                        "kind": "restart_scheduled",
                        "status": "ok",
                        "sessionKey": "agent:main:discord:dm:test",
                        "deliveryContext": {"channel": "discord", "threadId": "999"},
                    }
                ],
            )

            surface_paths = {
                "agent_events": [str(root / "agent-events.jsonl")],
                "session_hooks": [str(root / "session-hooks.jsonl")],
                "subagent_hooks": [str(root / "subagent-hooks.jsonl")],
                "config_audit": [str(root / "config-audit.jsonl")],
                "restart_sentinels": [str(root / "restart-sentinels.jsonl")],
            }
            records = ingest_openclaw.collect_records(surface_paths, "test-host", "openclaw-local-v1", "test-ingest")

            self.assertEqual(len(records), 5)
            self.assertEqual({record["surface"] for record in records}, {"tool", "session", "subagent", "config", "restart"})
            for record in records:
                openclaw_prepare.validate_adapter_record(record, self.audit_schema)

    def test_ingest_cli_writes_audit_bundle(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_path = root / "audit.jsonl"
            write_jsonl(
                root / "agent-events.jsonl",
                [
                    {
                        "ts": "2026-03-15T10:01:00Z",
                        "stream": "tool_execution_end",
                        "runId": "run-2",
                        "sessionKey": "agent:main:discord:dm:test",
                        "data": {
                            "phase": "end",
                            "toolName": "exec",
                            "toolCallId": "call-2",
                            "status": "completed",
                        },
                    }
                ],
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "ingest_openclaw.py"),
                    "--input-root",
                    str(root),
                    "--output",
                    str(output_path),
                    "--stats",
                ],
                capture_output=True,
                text=True,
                check=True,
            )

            self.assertIn("wrote_records=1", result.stdout)
            self.assertTrue(output_path.exists())
            lines = output_path.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertEqual(record["surface"], "tool")
            openclaw_prepare.validate_adapter_record(record, self.audit_schema)


if __name__ == "__main__":
    unittest.main()