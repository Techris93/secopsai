from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

from secopsai import cli


class RefreshCliTests(unittest.TestCase):
    def test_platform_refresh_runs_openclaw_pipeline_before_other_adapters(self) -> None:
        fake_adapter = mock.Mock()
        fake_adapter.collect.return_value = [{"raw": {"id": "evt-1"}}]
        fake_adapter.normalize.return_value = {"event_id": "evt-1"}
        pipeline_result = SimpleNamespace(
            exported=True,
            wrote_audit_jsonl="/tmp/audit.jsonl",
            wrote_labeled="/tmp/current.json",
            wrote_unlabeled="/tmp/unlabeled.json",
            findings_file="/tmp/findings.json",
            findings_db="/tmp/openclaw_soc.db",
            total_findings=2,
            total_detections=3,
            sync_attempted=False,
            sync_succeeded=False,
        )

        def _create_adapter(name: str):
            if name != "macos":
                raise AssertionError(f"unexpected adapter request: {name}")
            return fake_adapter

        with mock.patch.object(cli, "refresh_pipeline", return_value=pipeline_result) as pipeline_mock, \
             mock.patch.object(cli.AdapterRegistry, "create", side_effect=_create_adapter) as create_mock, \
             mock.patch.object(cli, "run_detection", return_value={"findings": [{"finding_id": "MAC-1"}]}), \
             mock.patch("soc_store.init_db"), \
             mock.patch("soc_store.persist_findings", return_value="/tmp/openclaw_soc.db") as persist_mock, \
             mock.patch("builtins.print"):
            summary = cli._run_adapter_refresh(
                "macos,openclaw",
                skip_export=False,
                openclaw_home="/tmp/openclaw-home",
                verbose=False,
            )

        pipeline_mock.assert_called_once_with(
            skip_export=False,
            openclaw_home="/tmp/openclaw-home",
            verbose=False,
        )
        create_mock.assert_called_once_with("macos")
        persist_mock.assert_called_once()
        self.assertEqual(persist_mock.call_args.kwargs["db_path"], "/tmp/openclaw_soc.db")
        self.assertEqual(summary["total_findings"], 3)
        self.assertEqual(summary["findings_db"], "/tmp/openclaw_soc.db")

        openclaw_result = next(item for item in summary["platform_results"] if item["platform"] == "openclaw")
        self.assertEqual(openclaw_result["mode"], "pipeline_refresh")
        self.assertEqual(openclaw_result["findings"], 2)


if __name__ == "__main__":
    unittest.main()
