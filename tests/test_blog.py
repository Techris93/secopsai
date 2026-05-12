import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import soc_store
from secopsai import blog


class BlogPublishingTests(unittest.TestCase):
    def test_draft_advisory_publish_and_rebuild_feeds(self):
        advisory = {
            "advisory_id": "ADV-UNIT",
            "campaign_id": "unit-campaign",
            "title": "Unit supply-chain campaign",
            "summary": "Confirmed package compromise.",
            "severity": "critical",
            "confidence": "high",
            "source_urls": ["https://example.com/report"],
            "affected": [{"ecosystem": "npm", "package": "@scope/pkg", "versions": ["1.2.3"]}],
            "iocs": {"domains": ["example.com"]},
            "remediation": ["Block @scope/pkg@1.2.3."],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            (paths.root / "assets").mkdir(parents=True)
            (paths.root / "assets" / "comments.js").write_text("textContent", encoding="utf-8")
            (paths.root / "functions" / "api").mkdir(parents=True)
            (paths.root / "functions" / "api" / "comments.js").write_text("", encoding="utf-8")
            (paths.root / "favicon.svg").write_text("<svg/>", encoding="utf-8")
            with mock.patch.object(blog, "load_advisories", return_value=[advisory]):
                draft = blog.draft_advisory("unit-campaign", paths=paths)
            dry_run = blog.publish(draft["draft_path"], paths=paths)
            published = blog.publish(draft["draft_path"], confirm=True, paths=paths)

            self.assertFalse(dry_run["published"])
            self.assertTrue(published["published"])
            self.assertTrue((paths.root / "feed.json").exists())
            self.assertTrue((paths.root / "feed.xml").exists())
            feed = json.loads((paths.root / "feed.json").read_text(encoding="utf-8"))
            self.assertEqual(feed["items"][0]["title"], "Unit supply-chain campaign")

    def test_draft_finding_redacts_token_like_values(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "findings.db")
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            finding = {
                "finding_id": "SCM-UNIT",
                "title": "Suspicious package",
                "summary": "credential=UNIT_TEST_PLACEHOLDER_VALUE should be redacted",
                "severity": "critical",
                "severity_score": 98,
                "status": "open",
                "disposition": "unreviewed",
                "source": "secopsai-supply-chain",
                "first_seen": "2026-05-12T00:00:00Z",
                "last_seen": "2026-05-12T00:00:00Z",
                "event_ids": ["evt-1"],
                "analysis": "secret=UNIT_TEST_PLACEHOLDER_VALUE should not render",
            }
            soc_store.persist_findings([finding], "secopsai-supply-chain", db_path=db_path)
            payload = blog.draft_finding("SCM-UNIT", db_path=db_path, paths=paths)
            draft_text = Path(payload["draft_path"]).read_text(encoding="utf-8")

        self.assertIn("[REDACTED]", draft_text)
        self.assertNotIn("UNIT_TEST_PLACEHOLDER_VALUE", draft_text)

    def test_comments_setup_status_reports_missing_without_values(self):
        payload = blog.comments_setup_status(["SUPABASE_URL"])

        self.assertFalse(payload["configured"])
        self.assertEqual(payload["required_present"], ["SUPABASE_URL"])
        self.assertEqual(payload["required_missing"], ["SUPABASE_SERVICE_ROLE_KEY"])

    def test_draft_news_deduplicates_sources(self):
        feed_text = (
            '<?xml version="1.0"?><rss version="2.0"><channel><title>News</title>'
            "<item><title>Example security news</title><link>https://example.com/a</link>"
            "<description>Short summary.</description></item></channel></rss>"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            feed_path = Path(temp_dir) / "feed.xml"
            feed_path.write_text(feed_text, encoding="utf-8")
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            first = blog.draft_news(str(feed_path), paths=paths)
            with self.assertRaises(ValueError):
                blog.draft_news(str(feed_path), paths=paths)

        self.assertTrue(Path(first["draft_path"]).name.endswith(".json"))


if __name__ == "__main__":
    unittest.main()
