import unittest
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from correlation import run_correlation


class CorrelationRegressionTests(unittest.TestCase):
    def test_run_correlation_accepts_time_window_parameter(self):
        findings = [
            {
                "id": "f1",
                "timestamp": "2026-04-11T06:00:00Z",
                "platform": "openclaw",
                "severity": "low",
                "user": "alice",
            },
            {
                "id": "f2",
                "timestamp": "2026-04-11T06:05:00Z",
                "platform": "macos",
                "severity": "low",
                "user": "alice",
            },
        ]
        result = run_correlation(findings, time_window_minutes=30)
        self.assertIn("total_correlations", result)
        self.assertIsInstance(result["total_correlations"], int)


if __name__ == "__main__":
    unittest.main()
