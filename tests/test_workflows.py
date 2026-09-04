import json
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from secopsai import cli
from secopsai.workflows import get_workflow, list_workflows, render_workflow, workflow_names


ROOT = Path(__file__).resolve().parents[1]


class WorkflowCommandTests(unittest.TestCase):
    def test_workflow_catalog_has_expected_roles(self):
        names = set(workflow_names())

        self.assertIn("ship", names)
        self.assertIn("cso", names)
        self.assertIn("investigate", names)
        self.assertEqual(len(list_workflows()), len(names))

    def test_render_workflow_includes_commands_and_gates(self):
        rendered = render_workflow(get_workflow("investigate"))

        self.assertIn("No-fix-without-investigation".lower(), rendered.lower())
        self.assertIn("Suggested commands:", rendered)
        self.assertIn("Safety gates:", rendered)

    def test_cli_workflow_list_json(self):
        stdout = StringIO()

        with redirect_stdout(stdout):
            exit_code = cli.main(["--json", "workflow", "list"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["workflows"])
        self.assertIn("name", payload["workflows"][0])

    def test_cli_top_level_alias_json(self):
        stdout = StringIO()

        with redirect_stdout(stdout):
            exit_code = cli.main(["--json", "ship"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["workflow"]["name"], "ship")
        self.assertIn("commands", payload["workflow"])

    def test_mcp_audit_retries_transient_registry_failures_without_weakening_gate(self):
        workflow = (ROOT / ".github/workflows/test-and-build.yml").read_text(encoding="utf-8")

        self.assertIn("mcp-gateway:", workflow)
        self.assertIn("needs: [test, mcp-gateway, build-container]", workflow)
        self.assertNotIn("needs: [test, chatgpt-app, build-container]", workflow)
        self.assertIn("for attempt in 1 2 3", workflow)
        self.assertIn("npm audit --audit-level=moderate", workflow)
        self.assertIn('if [ "$attempt" -eq 3 ]', workflow)
        self.assertIn("exit 1", workflow)
        self.assertNotIn("npm audit --audit-level=moderate || true", workflow)


if __name__ == "__main__":
    unittest.main()
