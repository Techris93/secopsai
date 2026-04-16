import unittest
from unittest import mock

import threat_intel_ingestor as ingestor_mod


class ThreatIntelIngestorTests(unittest.TestCase):
    def test_fetch_github_pocs_retries_without_invalid_token(self):
        ingestor = ingestor_mod.ThreatIntelIngestor()

        unauthorized = mock.Mock()
        unauthorized.status_code = 401

        ok = mock.Mock()
        ok.status_code = 200
        ok.json.return_value = {"items": []}
        ok.raise_for_status.return_value = None

        with mock.patch.dict("os.environ", {"GITHUB_TOKEN": "bad-token"}, clear=False), \
             mock.patch.object(ingestor.session, "get", side_effect=[unauthorized, ok, ok, ok]) as get_mock, \
             mock.patch.object(ingestor_mod.time, "sleep", return_value=None):
            indicators = ingestor.fetch_github_pocs(days_back=1)

        self.assertEqual(indicators, [])
        self.assertEqual(get_mock.call_count, 4)
        self.assertEqual(get_mock.call_args_list[0].kwargs["headers"], {"Authorization": "token bad-token"})
        self.assertEqual(get_mock.call_args_list[1].kwargs["headers"], {})


if __name__ == "__main__":
    unittest.main()
