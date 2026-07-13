import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import soc_store
from secopsai import cli
from secopsai.edge_sync import import_bundle, sync_from_api
from secopsai.graph_store import list_assets, show_node
from secopsai.triage import list_triage_findings


def _bundle(edge_status: str = "open") -> dict:
    return {
        "schema_version": "secopsai.edge.bundle.v1",
        "exported_at": "2026-06-28T10:00:00Z",
        "source_instance": {
            "product": "secopsai_edge",
            "api": "secopsai-edge-api",
            "version": "0.1.0",
        },
        "cursor": {"mode": "full", "last_observed_at": "2026-06-28T10:00:00Z"},
        "graph": {
            "nodes": [
                {
                    "id": "edge:site:site-1",
                    "type": "site",
                    "label": "Pilot Office",
                    "source_id": "site-1",
                    "properties": {"name": "Pilot Office"},
                },
                {
                    "id": "edge:sensor:sensor-1",
                    "type": "sensor",
                    "label": "MacBook Sensor",
                    "source_id": "sensor-1",
                    "properties": {"site_id": "site-1", "hostname": "macbook", "status": "online"},
                },
                {
                    "id": "edge:scan:scan-1",
                    "type": "scan",
                    "label": "192.168.1.0/24",
                    "source_id": "scan-1",
                    "properties": {"target_cidr": "192.168.1.0/24", "completed_at": "2026-06-28T10:00:00Z"},
                },
                {
                    "id": "edge:asset:asset-1",
                    "type": "asset",
                    "label": "test-host",
                    "source_id": "asset-1",
                    "properties": {
                        "ip_address": "192.168.1.50",
                        "mac_address": "aa:bb:cc:dd:ee:ff",
                        "vendor": "Unknown",
                        "hostname": "test-host",
                        "status": "active",
                        "last_seen_at": "2026-06-28T10:00:00Z",
                    },
                },
                {
                    "id": "edge:service:asset-1:tcp:22",
                    "type": "service",
                    "label": "tcp/22",
                    "source_id": "asset-1:tcp:22",
                    "properties": {"asset_id": "asset-1", "port": 22, "protocol": "tcp", "state": "open"},
                },
            ],
            "edges": [
                {"id": "edge:e1", "type": "site_has_sensor", "from": "edge:site:site-1", "to": "edge:sensor:sensor-1", "properties": {}},
                {"id": "edge:e2", "type": "sensor_ran_scan", "from": "edge:sensor:sensor-1", "to": "edge:scan:scan-1", "properties": {}},
                {"id": "edge:e3", "type": "scan_observed_asset", "from": "edge:scan:scan-1", "to": "edge:asset:asset-1", "properties": {"observed_at": "2026-06-28T10:00:00Z"}},
                {"id": "edge:e4", "type": "asset_exposes_service", "from": "edge:asset:asset-1", "to": "edge:service:asset-1:tcp:22", "properties": {}},
            ],
        },
        "findings": [
            {
                "id": "edge-finding-1",
                "type": "risky_open_port",
                "title": "SSH exposed internally",
                "summary": "192.168.1.50 exposes tcp/22.",
                "severity": "medium",
                "status": edge_status,
                "site_node_id": "edge:site:site-1",
                "asset_node_id": "edge:asset:asset-1",
                "evidence": {"ip": "192.168.1.50", "port": 22},
                "mitre_attack": [{"id": "T1046", "name": "Network Service Discovery"}],
                "created_at": "2026-06-28T10:00:00Z",
                "updated_at": "2026-06-28T10:00:00Z",
            }
        ],
    }


class EdgeIntegrationTests(unittest.TestCase):
    def test_import_bundle_creates_graph_and_core_finding(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")

            first = import_bundle(_bundle(), db_path=db_path)
            second = import_bundle(_bundle(), db_path=db_path)

            self.assertEqual(first["nodes"], 5)
            self.assertEqual(second["findings"], 1)
            assets = list_assets(db_path=db_path)
            self.assertEqual(len(assets), 1)
            self.assertEqual(assets[0]["ip_address"], "192.168.1.50")
            self.assertIsNotNone(show_node("192.168.1.50", db_path=db_path))

            rows = list_triage_findings(db_path=db_path, source="secopsai_edge")
            self.assertEqual(len(rows), 1)
            self.assertTrue(rows[0]["finding_id"].startswith("EDGE-"))
            self.assertEqual(rows[0]["source"], "secopsai_edge")

    def test_edge_status_can_close_unmodified_core_finding(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")

            import_bundle(_bundle("open"), db_path=db_path)
            finding_id = list_triage_findings(db_path=db_path, source="secopsai_edge")[0]["finding_id"]
            import_bundle(_bundle("resolved"), db_path=db_path)

            finding = soc_store.get_finding(finding_id, db_path)
            self.assertEqual(finding["status"], "closed")
            self.assertEqual(finding["disposition"], "remediated")

    def test_reimport_preserves_analyst_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")

            import_bundle(_bundle("open"), db_path=db_path)
            finding_id = list_triage_findings(db_path=db_path, source="secopsai_edge")[0]["finding_id"]
            soc_store.set_finding_status(finding_id, "triaged", db_path)
            soc_store.set_finding_disposition(finding_id, "accepted_risk", db_path)
            import_bundle(_bundle("resolved"), db_path=db_path)

            finding = soc_store.get_finding(finding_id, db_path)
            self.assertEqual(finding["status"], "triaged")
            self.assertEqual(finding["disposition"], "accepted_risk")

    def test_cli_edge_import_and_graph_assets_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            bundle_path = temp_path / "edge-bundle.json"
            bundle_path.write_text(json.dumps(_bundle()), encoding="utf-8")

            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = cli.main(["--json", "edge", "import", "--bundle", str(bundle_path), "--db-path", db_path])
            payload = json.loads(stdout.getvalue())
            self.assertEqual(rc, 0)
            self.assertEqual(payload["findings"], 1)

            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = cli.main(["--json", "graph", "assets", "--db-path", db_path])
            payload = json.loads(stdout.getvalue())
            self.assertEqual(rc, 0)
            self.assertEqual(payload["assets"][0]["ip_address"], "192.168.1.50")

    @patch("secopsai.edge_sync.fetch_bundle")
    def test_sync_prefers_scoped_access_token_environment(self, fetch_bundle):
        fetch_bundle.return_value = _bundle()
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {
                "SECOPSAI_EDGE_API_URL": "https://edge.example.test",
                "SECOPSAI_EDGE_ACCESS_TOKEN": "scoped-core-export-token",
                "SECOPSAI_EDGE_ADMIN_TOKEN": "legacy-admin-token",
            },
        ):
            sync_from_api(db_path=str(Path(temp_dir) / "soc.db"))

        fetch_bundle.assert_called_once_with(
            "https://edge.example.test", "scoped-core-export-token"
        )


if __name__ == "__main__":
    unittest.main()
