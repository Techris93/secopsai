from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.docs_source_agent import build_report, write_report


class DocsSourceAgentTests(unittest.TestCase):
    def test_build_report_collects_verifier_result(self) -> None:
        with mock.patch("scripts.docs_source_agent.run_command", return_value={"ok": True, "command": ["python"], "returncode": 0, "stdout": "{}", "stderr": ""}):
            payload = build_report(run_build=False)
        self.assertTrue(payload["ok"])
        self.assertEqual(len(payload["checks"]), 1)
        self.assertIn("docs/OpenClaw-Plugin.md", payload["sources"])

    def test_write_report_writes_json_and_markdown(self) -> None:
        payload = {
            "generated_at": "2026-04-24T00:00:00Z",
            "ok": True,
            "sources": ["docs/index.md"],
            "checks": [{"ok": True, "command": ["python", "scripts/verify_docs_examples.py"]}],
            "recommended_actions": ["Keep docs current."],
        }
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_report(payload, output_dir=Path(tmp))
        self.assertTrue(paths["json_report"].endswith(".json"))
        self.assertTrue(paths["markdown_report"].endswith(".md"))


if __name__ == "__main__":
    unittest.main()
