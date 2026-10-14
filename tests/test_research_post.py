import csv
import io
import json

import pytest
from pathlib import Path

from secopsai import blog, research_post


def _case(**overrides):
    case = {
        "case_id": "RC-TEST",
        "title": "Hijacked release of left-padder steals npm tokens",
        "summary": "Version 2.3.1 of left-padder added a postinstall script that reads .npmrc and posts it to a Discord webhook.",
        "case_type": "package_compromise",
        "severity": "high",
        "confidence": 92,
        "disclosure_status": "reported",
        "created_at": "2026-10-09T10:00:00Z",
        "subjects": [
            {"subject_type": "package", "ecosystem": "npm", "name": "left-padder", "version": "2.3.1", "publisher": "mallory",
             "status": "active", "registry_state": "removed", "state_checked_at": "2026-10-10T08:00:00Z"},
            {"subject_type": "package", "ecosystem": "npm", "name": "left-padder", "version": "2.3.2", "publisher": "mallory",
             "status": "active", "registry_state": "available", "state_checked_at": "2026-10-10T08:00:00Z"},
        ],
        "evidence": [
            {"evidence_type": "static_analysis", "title": "postinstall downloads stage two", "notes": "child_process runs curl to fetch a payload, base64 encoded", "status": "active"},
        ],
        "iocs": [
            {"ioc_type": "url", "value": "https://discord.com/api/webhooks/1/abc", "confidence": 95, "first_seen": "2026-10-09T09:00:00Z", "tags": ["exfil"], "status": "active"},
            {"ioc_type": "sha256", "value": "A" * 64, "confidence": 100, "tags": [], "status": "active"},
            {"ioc_type": "domain", "value": "it's-evil.example", "confidence": 80, "tags": [], "status": "active"},
        ],
        "verdicts": [{"verdict": "credible", "confidence": 95, "rationale": "Reviewer confirmed the exfiltration code.", "created_at": "2026-10-09T12:00:00Z"}],
        "disclosures": [{"recipient": "npm security", "status": "sent", "sent_at": "2026-10-09T13:00:00Z", "created_at": "2026-10-09T12:30:00Z"}],
        "rules": [{"rule_type": "yara", "name": "SecOpsAI_Npmrc_Exfil"}],
        "findings": [],
        "metadata": {},
    }
    case.update(overrides)
    return case


def test_confirmed_grade_needs_a_recorded_malicious_verdict():
    assert research_post.confidence_grade(_case())["label"] == "High confidence"
    assert research_post.confidence_grade(_case(research_assurance={"confirmed_observation": True, "technical_review_current": True}))["label"] == "Confirmed"
    assert research_post.confidence_grade(_case(verdicts=[]))["label"] == "High confidence"
    assert research_post.confidence_grade(_case(confidence=60))["label"] == "Moderate confidence"
    assert research_post.confidence_grade(_case(confidence=10))["label"] == "Low confidence"


def test_attack_mapping_cites_the_evidence_behind_each_technique():
    assert not research_post.attack_mapping(_case()), "keywords cannot create a public behavioral assertion"
    reviewed = {"technique": "T1552.001", "statement": "Static code reads a credential file", "rationale": "Reviewed exact code", "references": [{"evidence_id": "E-1"}]}
    mapping = research_post.attack_mapping(_case(research_assurance={"behavior_mappings": [reviewed]}))
    assert len(mapping) == 1 and mapping[0]["technique"] == "T1552.001"


def test_takedown_tracker_and_status_reflect_registry_and_disclosure():
    rows = research_post.takedown_rows(_case())
    events = [row["event"] for row in rows]
    assert events[0] == "Investigation opened by SecOpsAI" and "Reported to npm security" in events
    assert any("Removed from the registry: left-padder@2.3.1" in event for event in events)
    assert any(row["status"] == "open" and "2.3.2" in row["event"] for row in rows)
    assert research_post.takedown_summary(_case()) == "1 of 2 affected package versions are still live on the registry; takedown requested."


def test_ioc_exports_are_valid_and_complete():
    exports = research_post.ioc_exports(_case(), generated_at="2026-10-10T12:00:00Z", post_url="https://blog.example/posts/x.html")
    payload = json.loads(exports["json"])
    assert payload["confidence"] == "High confidence" and len(payload["indicators"]) == 5
    rows = list(csv.DictReader(io.StringIO(exports["csv"])))
    assert {row["type"] for row in rows} == {"url", "sha256", "domain", "npm-package"}
    bundle = json.loads(exports["stix.json"])
    indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
    assert len(indicators) == 5
    patterns = {obj["pattern"] for obj in indicators}
    assert "[file:hashes.'SHA-256' = '" + "a" * 64 + "']" in patterns
    assert "[domain-name:value = 'it\\'s-evil.example']" in patterns, "quotes are escaped in STIX patterns"
    assert "[software:name = 'left-padder' AND software:version = '2.3.1']" in patterns
    report = next(obj for obj in bundle["objects"] if obj["type"] == "report")
    assert set(report["object_refs"]) == {obj["id"] for obj in indicators}
    again = research_post.ioc_exports(_case(), generated_at="2026-10-11T00:00:00Z")
    assert {o["id"] for o in json.loads(again["stix.json"])["objects"] if o["type"] == "indicator"} == {obj["id"] for obj in indicators}, "ids are stable across re-renders"


def test_draft_and_publish_render_the_template_and_ioc_files(tmp_path):
    paths = blog.BlogPaths(root=tmp_path / "blog")
    payload = blog.draft_research_case(_case(), paths=paths)
    body = payload["post"]["body_markdown"]
    for heading in ("## TL;DR", "## Affected Packages", "## Status and Takedown Tracker", "## Our Assessment", "## MITRE ATT&CK Mapping", "## Indicators of Compromise", "## Recommended Actions", "## Disclosure"):
        assert heading in body
    assert "`npm ls left-padder`" in body
    assert payload["post"]["confidence_grade"] == "High confidence"
    page = blog._render_post_html(payload["post"])
    assert '<section class="tldr"' in page and 'class="card ioc-card"' in page
    assert "a" * 64 in page
    with pytest.raises(ValueError):
        blog.publish(payload["draft_path"], confirm=True, paths=paths, db_path=str(tmp_path / "empty.db"))
    assert not list(paths.posts.glob("*.json")), "an unregistered case cannot publish"
