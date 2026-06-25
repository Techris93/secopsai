import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
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
            rss = ET.parse(paths.root / "feed.xml")
            rss_items = rss.findall("./channel/item")
            self.assertEqual(feed["items"][0]["title"], "Unit supply-chain campaign")
            self.assertEqual(feed["items"][0]["authors"][0]["name"], "SecOpsAI Threat Research")
            self.assertEqual(feed["items"][0]["severity"], "critical")
            self.assertGreaterEqual(feed["items"][0]["reading_time_minutes"], 1)
            self.assertTrue(feed["items"][0]["url"].startswith("https://blog.secopsai.dev/posts/"))
            self.assertTrue(feed["items"][0]["summary"])
            self.assertEqual(len(rss_items), 1)
            self.assertTrue(rss_items[0].findtext("description"))
            index = (paths.root / "index.html").read_text(encoding="utf-8")
            latest = (paths.root / "posts" / "index.html").read_text(encoding="utf-8")
            json_landing = (paths.root / "json-feed.html").read_text(encoding="utf-8")
            post_html = Path(published["post_path"]).read_text(encoding="utf-8")
            self.assertIn("Featured Research", index)
            self.assertIn("Follow SecOpsAI advisories and research", index)
            self.assertIn("Traditional syndication", index)
            self.assertIn("Structured automation", index)
            self.assertIn("security workflow", index)
            self.assertIn("Intelligence Categories", index)
            self.assertIn("/posts/", index)
            self.assertIn("Latest posts", latest)
            self.assertIn("data-topic-filter", latest)
            self.assertIn("post-sort", latest)
            self.assertIn("post-search", latest)
            self.assertIn("data-nav-toggle", index)
            self.assertIn("#topics", index)
            self.assertIn("og:image", index)
            self.assertIn("summary_large_image", index)
            self.assertIn("Operator commands", post_html)
            self.assertIn("Affected Artifacts", post_html)
            self.assertIn("References", post_html)
            self.assertIn("data-nav-toggle", post_html)
            self.assertIn("/json-feed", post_html)
            self.assertIn("twitter:card", post_html)
            self.assertIn("article:published_time", post_html)
            self.assertIn("/feed.json?raw=1", json_landing)
            self.assertNotIn("Review Checklist", (paths.root / "feed.json").read_text(encoding="utf-8"))
            self.assertNotIn("Review Checklist", (paths.root / "feed.xml").read_text(encoding="utf-8"))
            self.assertTrue((paths.root / "assets" / "social" / "secopsai-blog.svg").exists())
            self.assertTrue((paths.root / "assets" / "social" / "unit-campaign-unit-supply-chain-campaign.svg").exists())

    def test_draft_campaign_creates_review_only_blog_post(self):
        campaign = {
            "campaign_id": "unit-cross-ecosystem-campaign",
            "title": "Unit cross-ecosystem supply-chain campaign",
            "summary": "Credential theft across package ecosystems.",
            "campaign_verdict": "likely_true_positive",
            "severity": "critical",
            "source_urls": ["https://example.com/research"],
            "iocs": {"domains": ["c2.example"]},
            "ecosystems": ["npm", "pypi"],
            "packages": [
                {
                    "ecosystem": "npm",
                    "package": "unit-pkg",
                    "version": "1.0.0",
                    "package_verdict": "likely_true_positive",
                    "environment_impact": {"status": "not_observed"},
                    "behavioral_indicators": ["credential harvesting"],
                }
            ],
            "recommended_mitigation": ["Block unit-pkg@1.0.0."],
            "references": ["https://example.com/research"],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            draft = blog.draft_campaign(campaign_data=campaign, paths=paths)
            post = draft["post"]
        self.assertEqual(post["review_status"], "needs_review")
        self.assertTrue(post["external_news"])
        self.assertIn("Affected Packages", post["body_markdown"])
        self.assertIn("unit-pkg", post["body_markdown"])
        self.assertNotIn("Review Checklist", post["body_markdown"])

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
            self.assertIn("Review Checklist", draft_text)
            self.assertIn("Source Metadata", draft_text)

    def test_news_security_extraction_and_severity_inference(self):
        item = {
            "title": "CISA KEV: BerriAI LiteLLM CVE-2026-42208 active exploitation",
            "summary": "SQL injection in litellm@1.85.0 leaks credentials from 83.142.209.194 and https://evil.example/payload.py",
            "category": "CISA KEV",
            "source_name": "CISA Known Exploited Vulnerabilities",
            "tags": ["Known Exploited Vulnerabilities", "PyPI"],
        }

        extracted = blog.extract_news_security_fields(item)
        severity, reason = blog.infer_news_severity(item, extracted)

        self.assertIn("CVE-2026-42208", extracted["cves"])
        self.assertIn("litellm@1.85.0", extracted["packages"])
        self.assertIn("83.142.209.194", extracted["ips"])
        self.assertIn("evil.example", extracted["domains"])
        self.assertIn("pypi", extracted["ecosystems"])
        self.assertEqual(severity, "high")
        self.assertIn("CISA KEV", reason)

    def test_news_draft_includes_enrichment_and_readiness(self):
        item = {
            "key": "unit-news",
            "title": "Compromised npm package @scope/pkg@1.2.3 steals GitHub Actions tokens",
            "canonical_url": "https://research.example/compromise",
            "summary": "Researchers report a compromised npm package that targets CI credentials.",
            "source_name": "Research Lab",
            "source_url": "https://research.example/feed",
            "trust_level": "external_research",
            "category": "Supply Chain",
            "tags": ["npm", "credential theft"],
            "published_at": "2026-05-14T00:00:00Z",
            "fetched_at": "2026-05-14T01:00:00Z",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            payload = blog._draft_from_news_item(item, paths=paths)
            draft = payload["post"]
            body = Path(payload["draft_path"]).read_text(encoding="utf-8")

        self.assertEqual(draft["source_trust_level"], "external_research")
        self.assertIn("@scope/pkg@1.2.3", draft["extracted"]["packages"])
        self.assertIn("npm", draft["affected_ecosystems"])
        self.assertIn("credential theft", [signal.lower() for signal in draft["extracted"]["severity_signals"]])
        self.assertGreaterEqual(draft["readiness_score"], 80)
        self.assertEqual(draft["readiness_status"], "ready_to_review")
        self.assertFalse(draft["readiness_blockers"])
        self.assertIn("Review Checklist", body)
        self.assertIn("What SecOpsAI Can Detect", body)
        self.assertIn("Operator Commands", body)

    def test_news_draft_extracts_source_page_image_candidates_when_feed_has_none(self):
        item = {
            "key": "source-image-news",
            "title": "Cloud vendor publishes OAuth security update",
            "canonical_url": "https://vendor.example/security/oauth-update",
            "summary": "A vendor security update without feed media metadata.",
            "source_name": "Vendor Security Blog",
            "source_url": "https://vendor.example/feed",
            "trust_level": "vendor",
            "category": "Threat Intelligence",
            "published_at": "2026-06-24T09:00:00Z",
            "fetched_at": "2026-06-25T12:22:09Z",
        }
        html = """
        <html>
          <head>
            <meta property="og:image" content="/assets/oauth-share.png">
            <meta name="twitter:image" content="https://cdn.vendor.example/oauth-card.png">
          </head>
          <body>Security update</body>
        </html>
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            with mock.patch.object(blog, "_fetch_text", return_value=html) as fetch_text:
                payload = blog._draft_from_news_item(item, paths=paths)
            draft = payload["post"]

        self.assertEqual(fetch_text.call_count, 1)
        self.assertEqual(len(draft["media_candidates"]), 2)
        self.assertEqual(draft["media_candidates"][0]["src"], "https://vendor.example/assets/oauth-share.png")
        self.assertEqual(draft["media_candidates"][0]["source_url"], item["canonical_url"])
        self.assertEqual(draft["media_candidates"][0]["kind"], "source-image")
        self.assertFalse(draft["media_candidates"][0]["approved"])

    def test_news_fetch_balances_primary_sources_before_aggregators(self):
        external_feed = (
            '<?xml version="1.0"?><rss version="2.0"><channel>'
            "<item><title>Aggregator story one</title><link>https://aggregator.example/a</link>"
            "<description>Aggregator summary.</description><pubDate>Wed, 13 May 2026 12:00:00 GMT</pubDate></item>"
            "<item><title>Aggregator story two</title><link>https://aggregator.example/b</link>"
            "<description>Aggregator summary.</description><pubDate>Wed, 13 May 2026 11:00:00 GMT</pubDate></item>"
            "</channel></rss>"
        )
        primary_feed = (
            '<?xml version="1.0"?><rss version="2.0"><channel>'
            "<item><title>Primary advisory</title><link>https://primary.example/advisory</link>"
            "<description>Primary source summary.</description><pubDate>Wed, 13 May 2026 09:00:00 GMT</pubDate></item>"
            "</channel></rss>"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            external_path = Path(temp_dir) / "external.xml"
            primary_path = Path(temp_dir) / "primary.xml"
            external_path.write_text(external_feed, encoding="utf-8")
            primary_path.write_text(primary_feed, encoding="utf-8")
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.data.mkdir(parents=True)
            paths.news_sources.write_text(
                json.dumps({
                    "sources": [
                        {
                            "name": "Aggregator",
                            "feed_url": str(external_path),
                            "type": "rss",
                            "category": "Security News",
                            "trust_level": "external_research",
                            "enabled": True,
                        },
                        {
                            "name": "Primary Source",
                            "feed_url": str(primary_path),
                            "type": "rss",
                            "category": "Threat Intelligence",
                            "trust_level": "government",
                            "enabled": True,
                        },
                    ]
                }),
                encoding="utf-8",
            )
            fetched = blog.news_fetch(limit=2, paths=paths)

        titles = {item["title"] for item in fetched["items"]}
        self.assertIn("Primary advisory", titles)
        self.assertEqual(fetched["created"], 2)

    def test_news_publish_approved_is_gated(self):
        ready_body = (
            "# External story\n\n"
            "## Executive Summary\n\n"
            "The source describes a confirmed security event with clear operator impact. "
            "SecOpsAI should treat this as an awareness item for exposed build systems, "
            "developer credentials, and dependency review queues. The draft summarizes the "
            "source in original language and links back to the primary reference for the "
            "claim details.\n\n"
            "## Why It Matters\n\n"
            "Security teams need to know whether the affected technology appears in their "
            "environment, whether the exposure changes dependency policy, and whether any "
            "credential rotation or monitoring action is required. This post keeps the "
            "claim scoped to the cited source and avoids adding unsupported conclusions.\n\n"
            "## What SecOpsAI Can Detect\n\n"
            "SecOpsAI can help operators check supply-chain advisory records, review current "
            "SOC findings, and create follow-up triage tasks for affected assets. Teams can "
            "also add source-backed package, IOC, or telemetry rules if the referenced report "
            "contains concrete indicators.\n\n"
            "## Recommended Actions\n\n"
            "Review the linked source, compare affected products against local inventories, "
            "open a triage task for exposed systems, and document any compensating controls "
            "or monitoring rules added after review. If the report is only informational, "
            "operators should still record that no direct exposure was identified.\n\n"
            "## IOCs\n\n"
            "None found deterministically; reviewer should add source-backed indicators if present.\n\n"
            "## References\n\n"
            "- https://example.com/story\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.drafts.mkdir(parents=True)
            draft = blog._base_post(
                title="External story",
                summary="External source reports a security event with operator impact.",
                categories=["Security News"],
                sources=["https://example.com/story"],
            )
            draft.update({
                "external_news": True,
                "review_status": "needs_review",
                "review_checklist": blog._review_checklist(),
                "body_markdown": "# External story\n\nNeeds review.",
            })
            draft_path = paths.drafts / "external-story.json"
            draft_path.write_text(json.dumps(draft), encoding="utf-8")
            blocked = blog.news_publish_approved(paths=paths)
            draft["review_status"] = "approved"
            draft_path.write_text(json.dumps(draft), encoding="utf-8")
            placeholder_blocked = blog.news_publish_approved(paths=paths)
            draft["body_markdown"] = ready_body
            draft_path.write_text(json.dumps(draft), encoding="utf-8")
            checklist_blocked = blog.news_publish_approved(paths=paths)
            blog.news_review_update("external-story", status="approved", note="reviewed source", paths=paths)
            approved = blog.news_publish_approved(paths=paths)
            post_json = json.loads((paths.posts / "external-story.json").read_text(encoding="utf-8"))
            post_html = (paths.posts / "external-story.html").read_text(encoding="utf-8")
            published_draft = json.loads(draft_path.read_text(encoding="utf-8"))
            repeated = blog.news_publish_approved(paths=paths)
            deployed = blog.news_mark_deployed(paths=paths)
            deployed_draft = json.loads(draft_path.read_text(encoding="utf-8"))

        self.assertEqual(blocked["total"], 0)
        self.assertEqual(placeholder_blocked["total"], 0)
        self.assertTrue(placeholder_blocked["blocked"])
        self.assertEqual(checklist_blocked["total"], 0)
        self.assertTrue(
            any("review checklist incomplete" in reason for item in checklist_blocked["blocked"] for reason in item["reasons"])
        )
        self.assertEqual(approved["total"], 1)
        self.assertEqual(published_draft["review_status"], "approved")
        self.assertEqual(published_draft["status"], "published")
        self.assertIn("published_url", published_draft)
        self.assertEqual(published_draft["published_post_path"], "blog/posts/external-story.json")
        self.assertNotIn(str(temp_dir), published_draft["published_post_path"])
        self.assertEqual(repeated["total"], 0)
        self.assertEqual(repeated["published"], [])
        self.assertEqual(repeated["ready_for_deploy"], ["https://blog.secopsai.dev/posts/external-story.html"])
        self.assertEqual(deployed["total"], 1)
        self.assertEqual(deployed["deployed"], ["https://blog.secopsai.dev/posts/external-story.html"])
        self.assertEqual(deployed_draft["review_status"], "deployed")
        self.assertEqual(deployed_draft["status"], "published")
        self.assertIn("published_url", deployed_draft)
        self.assertEqual(deployed_draft["published_post_path"], "blog/posts/external-story.json")
        self.assertNotIn(str(temp_dir), deployed_draft["published_post_path"])
        self.assertNotIn("Review Checklist", post_json["body_markdown"])
        self.assertNotIn("review_checklist", post_json)
        self.assertNotIn("Review Checklist", post_html)

    def test_approved_draft_with_existing_post_stays_approved_until_deploy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.drafts.mkdir(parents=True)
            paths.posts.mkdir(parents=True)
            draft = blog._base_post(
                title="Already public story",
                summary="Already public source-backed summary.",
                categories=["Security News"],
                sources=["https://example.com/already-public"],
                slug="already-public-story",
            )
            draft.update({
                "external_news": True,
                "extracted": {"products": ["Microsoft Microsoft"]},
                "review_status": "approved",
                "review_checklist": [{"label": "Main claim is supported by source", "status": "completed"}],
                "body_markdown": "# Already public story\n\nThis draft was already published in an earlier run.",
            })
            draft_path = paths.drafts / "already-public-story.json"
            draft_path.write_text(json.dumps(draft), encoding="utf-8")
            (paths.posts / "already-public-story.json").write_text(json.dumps({
                "slug": "already-public-story",
                "title": draft["title"],
                "summary": draft["summary"],
                "body_markdown": blog._public_post(draft)["body_markdown"],
                "status": "published",
            }), encoding="utf-8")

            listed = blog.news_review_list(paths=paths)
            approved = blog.news_review_list(status="approved", paths=paths)
            deployed = blog.news_review_list(status="deployed", paths=paths)
            payload = blog.news_publish_approved(paths=paths)
            stored_after_publish = json.loads(draft_path.read_text(encoding="utf-8"))
            deploy_payload = blog.news_mark_deployed(paths=paths)
            stored_after_deploy = json.loads(draft_path.read_text(encoding="utf-8"))

        self.assertEqual(listed["drafts"][0]["review_status"], "approved")
        self.assertEqual(approved["total"], 1)
        self.assertEqual(deployed["total"], 0)
        self.assertEqual(payload["total"], 0)
        self.assertEqual(payload["published"], [])
        self.assertEqual(payload["ready_for_deploy"], ["https://blog.secopsai.dev/posts/already-public-story.html"])
        self.assertEqual(stored_after_publish["review_status"], "approved")
        self.assertEqual(stored_after_publish["published_post_path"], "blog/posts/already-public-story.json")
        self.assertNotIn(str(temp_dir), stored_after_publish["published_post_path"])
        self.assertEqual(deploy_payload["total"], 1)
        self.assertEqual(deploy_payload["deployed"], ["https://blog.secopsai.dev/posts/already-public-story.html"])
        self.assertEqual(stored_after_deploy["review_status"], "deployed")
        self.assertEqual(stored_after_deploy["published_post_path"], "blog/posts/already-public-story.json")
        self.assertEqual(stored_after_deploy["extracted"]["products"], ["Microsoft Microsoft"])

    def test_approved_draft_with_newer_content_republishes_existing_post(self):
        ready_body = (
            "# Updated public story\n\n"
            "## Executive Summary\n\n"
            "This updated approved draft includes new source-backed analysis for operators. "
            "It explains the operational relevance in original language, keeps the claim scoped "
            "to the cited source, and adds practical SecOpsAI review context for the affected team.\n\n"
            "## Why It Matters\n\n"
            "Security teams need updated public guidance when the previously published article "
            "is stale. The new draft should replace the existing post only after it has been "
            "reviewed, approved, and checked against its references. Operators should not need "
            "to delete the previous post manually; the approved update should flow through the "
            "same controlled publication path and keep the review queue honest.\n\n"
            "## What SecOpsAI Can Detect\n\n"
            "SecOpsAI can link the source-backed signal to local triage findings, dependency "
            "records, and mitigation tasks so operators can validate exposure before acting. "
            "It can also preserve reviewer notes, source URLs, and response commands for the "
            "updated article without returning the old version to the approved queue.\n\n"
            "## IOCs\n\n"
            "None found deterministically; reviewer should add source-backed indicators if present.\n\n"
            "## Recommended Actions\n\n"
            "- Review the updated source material and confirm the original claim still applies.\n"
            "- Compare affected assets against local inventory and note any exposure changes.\n"
            "- Record any detections or compensating controls added after the updated review.\n"
            "- Publish the approved replacement once, then move the draft into deployed state.\n\n"
            "## References\n\n"
            "- https://example.com/updated\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.drafts.mkdir(parents=True)
            paths.posts.mkdir(parents=True)
            draft = blog._base_post(
                title="Updated public story",
                summary="Updated source-backed summary with operator impact.",
                categories=["Security News"],
                sources=["https://example.com/updated"],
                slug="updated-public-story",
            )
            draft.update({
                "external_news": True,
                "review_status": "approved",
                "review_checklist": blog._review_checklist(),
                "body_markdown": ready_body,
            })
            draft_path = paths.drafts / "updated-public-story.json"
            draft_path.write_text(json.dumps(draft), encoding="utf-8")
            (paths.posts / "updated-public-story.json").write_text(json.dumps({
                "slug": "updated-public-story",
                "title": "Updated public story",
                "summary": "Old summary",
                "body_markdown": "# Updated public story\n\nOld body.",
                "status": "published",
            }), encoding="utf-8")
            blog.news_review_update("updated-public-story", status="approved", note="updated", paths=paths)

            listed = blog.news_review_list(paths=paths)
            payload = blog.news_publish_approved(paths=paths)

        self.assertEqual(listed["drafts"][0]["review_status"], "approved")
        self.assertEqual(payload["total"], 1)
        self.assertEqual(payload["published"], ["https://blog.secopsai.dev/posts/updated-public-story.html"])

    def test_blog_ops_workflow_stages_draft_deletions(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "blog-ops.yml").read_text(
            encoding="utf-8"
        )

        self.assertIn("git add -A blog/drafts", workflow)
        self.assertIn("blog/assets/social", workflow)
        self.assertIn("blog/assets/posts", workflow)
        deploy_step = workflow.index("npx --yes wrangler@latest pages deploy blog")
        mark_step = workflow.index("python -m secopsai.cli blog news-mark-deployed --json")
        self.assertGreater(mark_step, deploy_step)

    def test_publish_with_approved_media_renders_hero_and_og_image(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.drafts.mkdir(parents=True)
            source_media = Path(temp_dir) / "alert.svg"
            source_media.write_text(
                '<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630"><rect width="1200" height="630" fill="#06251c"/></svg>',
                encoding="utf-8",
            )
            draft = blog._base_post(
                title="Media backed alert",
                summary="A SecOpsAI alert with approved local screenshot media.",
                categories=["Detection Engineering"],
                sources=["https://example.com/media"],
                slug="media-backed-alert",
            )
            draft["body_markdown"] = "# Media backed alert\n\n## Executive Summary\n\nApproved media renders safely."
            draft_path = paths.drafts / "media-backed-alert.json"
            draft_path.write_text(json.dumps(draft), encoding="utf-8")

            attached = blog.attach_media(
                "media-backed-alert",
                file_path=str(source_media),
                alt="SecOpsAI alert screenshot",
                caption="Redacted alert evidence.",
                paths=paths,
            )
            published = blog.publish("media-backed-alert", confirm=True, paths=paths)
            post_json = json.loads((paths.posts / "media-backed-alert.json").read_text(encoding="utf-8"))
            post_html = Path(published["post_path"]).read_text(encoding="utf-8")

        self.assertTrue(attached["media"]["src"].startswith("/assets/posts/media-backed-alert/"))
        self.assertIn('class="hero-image"', post_html)
        self.assertIn("SecOpsAI alert screenshot", post_html)
        self.assertIn('property="og:image"', post_html)
        self.assertIn("https://blog.secopsai.dev/assets/posts/media-backed-alert/", post_html)
        self.assertEqual(post_json["social_image"], post_json["images"][0]["src"])

    def test_attach_source_media_uses_draft_candidate_index(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.drafts.mkdir(parents=True)
            draft = blog._base_post(
                title="Source media draft",
                summary="A draft with source media candidates.",
                categories=["Security News"],
                sources=["https://example.com/story"],
                slug="source-media-draft",
            )
            draft.update({
                "external_news": True,
                "review_status": "approved",
                "review_checklist": blog._review_checklist(),
                "body_markdown": "# Source media draft\n\nCandidate image.",
                "media_candidates": [
                    {
                        "src": "https://cdn.example/story-card.png",
                        "alt": "Source card",
                        "caption": "Source-provided card.",
                        "source_name": "Example Source",
                        "source_url": "https://example.com/story",
                        "kind": "source-image",
                    }
                ],
            })
            draft_path = paths.drafts / "source-media-draft.json"
            draft_path.write_text(json.dumps(draft), encoding="utf-8")

            def write_fake_media(_url, destination, **_kwargs):
                destination.write_bytes(b"\x89PNG\r\n\x1a\n")

            with mock.patch.object(blog.urllib.request, "urlopen", side_effect=OSError("offline test")):
                with mock.patch.object(blog, "_download_source_media", side_effect=write_fake_media):
                    attached = blog.attach_source_media("source-media-draft", media_index=0, paths=paths)
            updated = json.loads(draft_path.read_text(encoding="utf-8"))

        self.assertEqual(attached["source_media_url"], "https://cdn.example/story-card.png")
        self.assertTrue(attached["media"]["src"].startswith("/assets/posts/source-media-draft/"))
        self.assertEqual(attached["media"]["source_url"], "https://example.com/story")
        self.assertEqual(attached["media"]["alt"], "Source card")
        self.assertEqual(updated["review_status"], "needs_review")

    def test_attach_source_media_rejects_local_metadata_and_svg_urls(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.drafts.mkdir(parents=True)
            draft = blog._base_post(
                title="Unsafe source media draft",
                summary="A draft that should not fetch unsafe source media.",
                categories=["Security News"],
                sources=["https://example.com/story"],
                slug="unsafe-source-media-draft",
            )
            draft.update({
                "external_news": True,
                "review_status": "approved",
                "review_checklist": blog._review_checklist(),
                "body_markdown": "# Unsafe source media draft\n\nCandidate image.",
            })
            (paths.drafts / "unsafe-source-media-draft.json").write_text(json.dumps(draft), encoding="utf-8")

            unsafe_urls = [
                "http://127.0.0.1/source.png",
                "http://localhost/source.png",
                "http://169.254.169.254/latest/meta-data.png",
                "https://cdn.example/source-card.svg",
            ]
            for unsafe_url in unsafe_urls:
                with self.subTest(unsafe_url=unsafe_url):
                    with self.assertRaisesRegex(ValueError, "source media URL"):
                        blog.attach_source_media(
                            "unsafe-source-media-draft",
                            url=unsafe_url,
                            alt="Unsafe source image",
                            paths=paths,
                        )

    def test_resolve_draft_rejects_existing_file_outside_drafts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.drafts.mkdir(parents=True)
            outside = Path(temp_dir) / "outside-draft.json"
            outside.write_text("{}", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "under blog/drafts"):
                blog._resolve_draft(str(outside), paths)

    def test_public_posts_remove_redundant_intro_and_split_references(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.drafts.mkdir(parents=True)
            draft = blog._base_post(
                title="CISA KEV: Microsoft Microsoft CVE-2026-42897",
                summary="Microsoft Exchange Server contains a cross-site scripting vulnerability.",
                categories=["Security News", "CISA KEV"],
                sources=[
                    "https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-42897 ; "
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-42897"
                ],
                slug="mobile-reference-test",
            )
            draft["body_markdown"] = (
                "# CISA KEV: Microsoft Microsoft CVE-2026-42897\n\n"
                "## Executive Summary\n\n"
                "Microsoft Exchange Server contains a cross-site scripting vulnerability.\n\n"
                "## Source Metadata\n\n"
                "- Canonical URL: https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-42897 ; "
                "https://nvd.nist.gov/vuln/detail/CVE-2026-42897\n\n"
                "## References\n\n"
                "- https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2026-42897 ; "
                "https://nvd.nist.gov/vuln/detail/CVE-2026-42897\n"
            )
            (paths.drafts / "mobile-reference-test.json").write_text(json.dumps(draft), encoding="utf-8")

            published = blog.publish("mobile-reference-test", confirm=True, paths=paths)
            post_html = Path(published["post_path"]).read_text(encoding="utf-8")
            post_json = json.loads((paths.posts / "mobile-reference-test.json").read_text(encoding="utf-8"))

        self.assertEqual(post_json["title"], "CISA KEV: Microsoft CVE-2026-42897")
        self.assertEqual(len(post_json["references"]), 2)
        self.assertEqual(post_html.count("<h1>"), 1)
        self.assertNotIn("<h2>Executive Summary</h2>", post_html)
        self.assertIn("Additional references", post_html)
        self.assertIn("class=\"inline-ref\"", post_html)

    def test_unsafe_media_paths_are_not_published(self):
        post = blog._base_post(
            title="Unsafe media",
            summary="Unsafe media should be ignored.",
            categories=["Security News"],
            sources=["https://example.com/source"],
            slug="unsafe-media",
        )
        post.update({
            "hero_image": "https://evil.example/image.png",
            "images": [
                {"src": "/Users/chrixchange/private.png", "alt": "private"},
                {"src": "javascript:alert(1)", "alt": "bad"},
                {"src": "/assets/posts/unsafe-media/safe.svg", "alt": "Safe local image"},
            ],
        })

        public = blog._public_post(post)

        self.assertEqual(public["images"], [{"src": "/assets/posts/unsafe-media/safe.svg", "alt": "Safe local image", "caption": "", "source_name": "", "source_url": "", "license": "", "kind": "image", "width": 1200, "height": 630, "approved": True}])
        self.assertNotIn("/Users/chrixchange", json.dumps(public))
        self.assertNotIn("javascript:", json.dumps(public))

    def test_news_draft_preserves_existing_rejected_draft(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.data.mkdir(parents=True)
            paths.drafts.mkdir(parents=True)
            item = {
                "key": "abc123",
                "title": "Rejected external story",
                "canonical_url": "https://example.com/rejected",
                "summary": "Rejected summary.",
                "source_name": "Fixture",
                "category": "Security News",
            }
            slug = blog.slugify(f"news-{item['key']}-{item['title']}")
            existing = paths.drafts / f"{slug}.json"
            existing.write_text(
                json.dumps({
                    "slug": slug,
                    "title": item["title"],
                    "external_news": True,
                    "review_status": "rejected",
                    "body_markdown": "Rejected draft should not be overwritten.",
                }),
                encoding="utf-8",
            )
            paths.news_cache.write_text(json.dumps({"items": [item]}), encoding="utf-8")

            payload = blog.news_draft(limit=1, paths=paths)
            preserved = json.loads(existing.read_text(encoding="utf-8"))
            cache = json.loads(paths.news_cache.read_text(encoding="utf-8"))

        self.assertEqual(payload["total"], 0)
        self.assertEqual(preserved["review_status"], "rejected")
        self.assertEqual(cache["items"][0]["review_status"], "existing")

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
                "review_checklist": blog._review_checklist(),
                "body_markdown": "# Review me\n\nNeeds review.",
                "media_candidates": [
                    {
                        "src": "https://cdn.example/review-card.png",
                        "source_url": "https://example.com/review",
                        "kind": "source-image",
                    }
                ],
                "images": [
                    {
                        "src": "/assets/posts/review-me/review-card.png",
                        "source_url": "https://example.com/review",
                        "alt": "Review image",
                    }
                ],
            })
            draft_path = paths.drafts / "review-me.json"
            draft_path.write_text(json.dumps(draft), encoding="utf-8")

            queue = blog.news_review_list(paths=paths)
            shown = blog.news_review_show("review-me", paths=paths)
            approved = blog.news_review_update("review-me", status="approved", note="looks good", paths=paths)

        self.assertEqual(queue["total"], 1)
        self.assertEqual(shown["title"], "Review me")
        self.assertIn("Needs review", shown["body_markdown"])
        self.assertEqual(shown["media_candidates"][0]["src"], "https://cdn.example/review-card.png")
        self.assertEqual(shown["images"][0]["alt"], "Review image")
        self.assertEqual(approved["review_status"], "approved")
        self.assertTrue(all(item["status"] == "completed" for item in approved["review_checklist"]))

    def test_news_review_show_backfills_source_page_media_for_existing_draft(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.drafts.mkdir(parents=True)
            draft = blog._base_post(
                title="Existing external draft",
                summary="Existing draft created before source media extraction.",
                categories=["Security News"],
                sources=["https://vendor.example/security/story"],
                slug="existing-external-draft",
            )
            draft.update({
                "external_news": True,
                "source_name": "Vendor Security Blog",
                "review_status": "needs_review",
                "review_checklist": blog._review_checklist(),
                "body_markdown": "# Existing external draft\n\nNeeds image candidates.",
                "primary_references": ["https://vendor.example/security/story"],
                "media_candidates": [],
            })
            draft_path = paths.drafts / "existing-external-draft.json"
            draft_path.write_text(json.dumps(draft), encoding="utf-8")
            html = '<meta property="og:image" content="https://cdn.vendor.example/story.png">'

            with mock.patch.object(blog, "_fetch_text", return_value=html):
                shown = blog.news_review_show("existing-external-draft", paths=paths)
            persisted = json.loads(draft_path.read_text(encoding="utf-8"))

        self.assertEqual(shown["media_candidates"][0]["src"], "https://cdn.vendor.example/story.png")
        self.assertEqual(shown["media_candidates"][0]["source_url"], "https://vendor.example/security/story")
        self.assertEqual(persisted["media_candidates"][0]["kind"], "source-image")

    def test_news_review_edit_updates_article_fields_and_resets_review(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            paths = blog.BlogPaths(Path(temp_dir) / "blog")
            paths.drafts.mkdir(parents=True)
            draft = blog._base_post(
                title="Old title",
                summary="Old summary with useful context.",
                categories=["Security News"],
                sources=["https://example.com/original"],
                slug="edit-me",
            )
            draft.update({
                "external_news": True,
                "review_status": "approved",
                "body_markdown": "# Old title\n\nThis old body has enough words to pass the save guard but needs an analyst rewrite before publication.",
            })
            (paths.drafts / "edit-me.json").write_text(json.dumps(draft), encoding="utf-8")

            updated = blog.news_review_edit(
                "edit-me",
                title="Edited CISA KEV CVE-2026-42208 analysis",
                summary="Edited source-backed summary that is different from the title.",
                severity="high",
                categories="Security News, CISA KEV, Threat Intelligence",
                references="https://example.com/source\nhttps://example.com/vendor",
                body_markdown=(
                    "# Edited CISA KEV CVE-2026-42208 analysis\n\n"
                    "## Executive Summary\n\n"
                    "This edited body adds SecOpsAI context for CVE-2026-42208 and LiteLLM exposure. "
                    "It explains why operators should inventory affected services, check local findings, "
                    "and verify source-backed mitigation steps before publishing.\n\n"
                    "## What SecOpsAI Can Detect\n\n"
                    "SecOpsAI can track CVE references, affected package mentions, advisory matches, and "
                    "SOC findings related to LiteLLM.\n\n"
                    "## Recommended Actions\n\n"
                    "- Inventory affected services.\n- Patch or mitigate the component.\n- Review local telemetry."
                ),
                note="Edited in dashboard",
                paths=paths,
            )

        self.assertEqual(updated["title"], "Edited CISA KEV CVE-2026-42208 analysis")
        self.assertEqual(updated["review_status"], "needs_review")
        self.assertEqual(updated["severity"], "high")
        self.assertIn("CVE-2026-42208", updated["extracted"]["cves"])
        self.assertIn("https://example.com/source", updated["references"])
        self.assertGreaterEqual(updated["readiness_score"], 80)


if __name__ == "__main__":
    unittest.main()
