import json
import tempfile
import unittest
from pathlib import Path


import export_real_openclaw_native as exporter


class OpenClawNativeExportTests(unittest.TestCase):
    def test_gateway_lifecycle_rows_are_exported_as_restart_sentinels(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            logs = root / "logs"
            logs.mkdir()
            gateway_log = logs / "gateway.log"
            gateway_log.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "1": "http server listening (8 plugins: telegram)",
                                "time": "2026-04-28T18:52:08.460Z",
                            }
                        ),
                        json.dumps(
                            {
                                "1": "ordinary debug line that should be ignored",
                                "time": "2026-04-28T18:52:09.000Z",
                            }
                        ),
                        "2026-04-28T21:03:51.643+03:00 [telegram] [default] starting provider (@OpenSentinel_Bot)",
                    ]
                ),
                encoding="utf-8",
            )

            previous_home = exporter.OPENCLAW_HOME
            exporter.OPENCLAW_HOME = root
            try:
                rows = exporter.export_restart_sentinels()
            finally:
                exporter.OPENCLAW_HOME = previous_home

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["kind"], "restart_sentinel")
        self.assertEqual(rows[0]["ts"], "2026-04-28T18:52:08.460Z")
        self.assertIn("http server listening", rows[0]["message"])
        self.assertEqual(rows[1]["ts"], "2026-04-28T21:03:51.643+03:00")
        self.assertIn("starting provider", rows[1]["message"])


if __name__ == "__main__":
    unittest.main()
