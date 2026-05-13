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
            self.assertEqual(feed["items"][0]["authors"][0]["name"], "SecOpsAI Threat Research")
            self.assertEqual(feed["items"][0]["severity"], "critical")
            self.assertGreaterEqual(feed["items"][0]["reading_time_minutes"], 1)
            index = (paths.root / "index.html").read_text(encoding="utf-8")
            post_html = Path(published["post_path"]).read_text(encoding="utf-8")
            self.assertIn("Featured research", index)
            self.assertIn("data-topic-filter", index)
            self.assertIn("post-sort", index)
            self.assertIn("Operator commands", post_html)
            self.assertIn("Affected artifacts", post_html)
            self.assertIn("References", post_html)

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

    def test_news_ingestion_fetches_deduplicates_and_drafts(self):
        feed_text = (
            '<?xml version="1.0"?><rss version="2.0"><channel><title>News</title>'
            "<item><title>Example security news</title><link>https://example.com/a</link>"
            "<description>Short summary.</description><pubDate>Wed, 13 May 2026 10:00:00 GMT</pubDate></item>"
            "<item><title>Second security news</title><link>https://example.com/b</link>"
            "<description>Another summary.</description></item></channel></rss>"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            feed_path = Path(temp_dir) / "feed.xml"
            feed_path.write_text(feed_text, encoding="utf-8")
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.data.mkdir(parents=True)
            paths.news_sources.write_text(
                json.dumps({
                    "sources": [
                        {
                            "name": "Fixture Feed",
                            "feed_url": str(feed_path),
                            "type": "rss",
                            "category": "Security News",
                            "enabled": True,
                            "default_tags": ["Fixture"],
                        },
                        {
                            "name": "Broken Feed",
                            "feed_url": str(Path(temp_dir) / "missing.xml"),
                            "type": "rss",
                            "category": "Security News",
                            "enabled": True,
                        },
                    ]
                }),
                encoding="utf-8",
            )
            sources = blog.news_sources_list(paths=paths)
            first_fetch = blog.news_fetch(limit=5, paths=paths)
            second_fetch = blog.news_fetch(limit=5, paths=paths)
            drafts = blog.news_draft(limit=1, paths=paths)
            draft_text = Path(drafts["created"][0]).read_text(encoding="utf-8")

            self.assertEqual(sources["enabled"], 2)
            self.assertEqual(first_fetch["created"], 2)
            self.assertEqual(second_fetch["created"], 0)
            self.assertTrue(first_fetch["errors"])
            self.assertEqual(drafts["total"], 1)
            self.assertIn("requires human review", draft_text)

    def test_news_publish_approved_is_gated(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.drafts.mkdir(parents=True)
            draft = blog._base_post(
                title="External story",
                summary="External summary.",
                categories=["Security News"],
                sources=["https://example.com/story"],
            )
            draft.update({
                "external_news": True,
                "review_status": "needs_review",
                "body_markdown": "# External story\n\nNeeds review.",
            })
            draft_path = paths.drafts / "external-story.json"
            draft_path.write_text(json.dumps(draft), encoding="utf-8")
            blocked = blog.news_publish_approved(paths=paths)
            draft["review_status"] = "approved"
            draft_path.write_text(json.dumps(draft), encoding="utf-8")
            approved = blog.news_publish_approved(paths=paths)

        self.assertEqual(blocked["total"], 0)
        self.assertEqual(approved["total"], 1)

    def test_news_review_commands_update_status_without_json_hand_editing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.drafts.mkdir(parents=True)
            draft = blog._base_post(
                title="Review me",
                summary="Review summary.",
                categories=["Security News"],
                sources=["https://example.com/review"],
                slug="review-me",
            )
            draft.update({
                "external_news": True,
                "review_status": "needs_review",
                "body_markdown": "# Review me\n\nNeeds review.",
            })
            draft_path = paths.drafts / "review-me.json"
            draft_path.write_text(json.dumps(draft), encoding="utf-8")

            queue = blog.news_review_list(paths=paths)
            shown = blog.news_review_show("review-me", paths=paths)
            approved = blog.news_review_update("review-me", status="approved", note="looks good", paths=paths)

        self.assertEqual(queue["total"], 1)
        self.assertEqual(shown["title"], "Review me")
        self.assertIn("Needs review", shown["body_markdown"])
        self.assertEqual(approved["review_status"], "approved")


if __name__ == "__main__":
    unittest.main()
