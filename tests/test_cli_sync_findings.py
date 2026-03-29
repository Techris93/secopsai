import json
import unittest
from unittest import mock

from secopsai import cli
from scripts.sync_findings_to_supabase import SyncSummary


class SyncFindingsCliTests(unittest.TestCase):
    def test_sync_findings_json_output(self):
        summary = SyncSummary(
            source_kind="sqlite",
            source_path="/tmp/openclaw_soc.db",
            local_findings=3,
            normalized_rows=3,
            schema_checked=True,
            schema_ok=True,
            validated_columns=["external_finding_id", "title", "raw_payload"],
            synced_rows=3,
            dry_run=False,
            table="findings",
        )
        with mock.patch.object(cli, "execute_findings_sync", return_value=summary), \
             mock.patch("builtins.print") as print_mock:
            rc = cli.main(["--json", "sync-findings", "--skip-schema-check"])

        self.assertEqual(rc, 0)
        payload = json.loads(print_mock.call_args.args[0])
        self.assertEqual(payload["synced_rows"], 3)
        self.assertTrue(payload["schema_ok"])


if __name__ == "__main__":
    unittest.main()
