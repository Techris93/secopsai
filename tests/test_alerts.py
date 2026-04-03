import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from secopsai import alerts


class AlertsTests(unittest.TestCase):
    def test_alert_new_openclaw_findings_deduplicates_finding_ids(self):
        findings = [
            {"finding_id": "OCF-1", "severity": "high", "title": "A"},
            {"finding_id": "OCF-2", "severity": "critical", "title": "B"},
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "slack_state.json"
            with mock.patch.object(alerts, "SLACK_STATE_PATH", state_path), \
                 mock.patch.object(alerts, "send_slack_message", return_value=True) as send_mock:
                first = alerts.alert_new_openclaw_findings(findings)
                second = alerts.alert_new_openclaw_findings(findings)

        self.assertTrue(first["sent"])
        self.assertEqual(first["new_findings"], 2)
        self.assertEqual(second["new_findings"], 0)
        self.assertFalse(second["sent"])
        send_mock.assert_called_once()


if __name__ == "__main__":
    unittest.main()
