from __future__ import annotations

import unittest
from pathlib import Path

from scripts.verify_docs_examples import (
    extract_doc_tool_names,
    extract_fenced_commands,
    extract_plugin_tool_names,
    normalize_example_command,
    validate_secopsai_command,
)


class VerifyDocsExamplesTests(unittest.TestCase):
    def test_extract_fenced_commands_only_returns_secopsai_lines(self) -> None:
        markdown = """
```bash
# comment
secopsai triage list --status open
cd ~/secopsai
secopsai research preflight
```
"""
        self.assertEqual(
            extract_fenced_commands(markdown),
            [
                "secopsai triage list --status open",
                "secopsai research preflight",
            ],
        )

    def test_normalize_example_command_replaces_placeholders(self) -> None:
        normalized = normalize_example_command("secopsai triage investigate <FINDING_ID> --session-id <SESSION_ID>")
        self.assertIn("SCM-EXAMPLE0001", normalized)
        self.assertIn("SES-1234567890ab", normalized)

    def test_extract_fenced_commands_joins_shell_continuations(self) -> None:
        markdown = """
```bash
secopsai research reliability adjudicate-review SOR-XXXXXXXXXXXXXXXX \\
  --decision accept_primary \\
  --rationale "Evidence-backed rationale with enough detail."
```
"""
        self.assertEqual(
            extract_fenced_commands(markdown),
            [
                'secopsai research reliability adjudicate-review SOR-XXXXXXXXXXXXXXXX --decision accept_primary --rationale "Evidence-backed rationale with enough detail."'
            ],
        )

    def test_validate_secopsai_command_accepts_real_cli_shapes(self) -> None:
        result = validate_secopsai_command("secopsai triage investigate <FINDING_ID> --open-session --with-research --json")
        self.assertTrue(result["ok"], result)

    def test_tool_extractors_compare_docs_and_plugin_source(self) -> None:
        markdown = "`secopsai_list_findings` and `secopsai_research_finding`"
        typescript_source = 'name: "secopsai_list_findings"\nname: "secopsai_research_finding"\nname: "not_secopsai"'
        self.assertEqual(
            extract_doc_tool_names(markdown),
            ["secopsai_list_findings", "secopsai_research_finding"],
        )
        self.assertEqual(
            extract_plugin_tool_names(typescript_source),
            ["secopsai_list_findings", "secopsai_research_finding"],
        )

    def test_changelog_has_unreleased_workflow_sections(self) -> None:
        changelog = Path(__file__).resolve().parents[1] / "CHANGELOG.md"
        text = changelog.read_text(encoding="utf-8")
        self.assertIn("## Unreleased", text)
        self.assertIn("### Added", text)
        self.assertIn("### Security", text)


if __name__ == "__main__":
    unittest.main()
