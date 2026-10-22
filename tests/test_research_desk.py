"""Vulnerability research desk: ranking, inferred links, claim checks, solo mode.

Fixtures reproduce the shapes collected on 2026-10-22 (PHP2Shell, the GitLab
regex RCE, the Node.js Brotli release, a CISA KEV entry, a GHSA advisory).
"""
import json
from datetime import datetime, timezone

import pytest

import soc_store
from secopsai import research_desk as desk
from secopsai.research_assurance import register_person
from secopsai.research_operation_store import transaction

NOW = datetime(2026, 10, 22, 12, tzinfo=timezone.utc)
SOURCES = {
    "php": ("PHP Security Advisories", "vendor", "rss"),
    "node": ("Node.js Security Releases", "vendor", "rss"),
    "thn": ("The Hacker News", "aggregator", "rss"),
    "kev": ("CISA Known Exploited Vulnerabilities", "government", "cisa_kev"),
    "ghsa": ("GitHub Security Advisories", "registry", "github_advisories"),
}


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_PRIMARY_INTEL", "0")
    path = str(tmp_path / "desk.db")
    soc_store.init_db(path)
    with transaction(path) as conn:
        for key, (name, source_class, parser) in SOURCES.items():
            config = {"source_id": key, "name": name, "url": f"https://{key}.example/feed", "parser": parser,
                      "source_class": source_class, "sharing": "public", "license": "unknown", "interval_seconds": 3600, "enabled": True}
            conn.execute("INSERT INTO research_intel_sources(source_id,config_json) VALUES (?,?)", (key, json.dumps(config)))
            conn.execute("INSERT INTO research_source_snapshots VALUES (?,?,?,?,?,?,?)", (f"snap-{key}", key, "0" * 64, "x", NOW.isoformat(), "1", b"{}"))
    return path


def add(db, event_id, source, title, excerpt="", *, published="2026-10-21T14:00:00Z", **payload):
    body = {"title": title, "excerpt": excerpt or title, "url": f"https://{source}.example/{event_id}", "published_at": published, **payload}
    with transaction(db) as conn:
        conn.execute("INSERT INTO research_intel_events VALUES (?,?,?,?,?,?,?,?)",
                     (event_id, source, event_id, f"snap-{source}", published, NOW.isoformat(), NOW.isoformat(), json.dumps(body)))


def week(db):
    add(db, "php-adv", "php", "Security advisory: Critical remote code execution vulnerabilities, update now",
        "Two critical issues, CVE-2026-109618 and CVE-2026-109619, allow remote code execution. Fixed in 8.5.12.")
    add(db, "thn-php", "thn", "PHP Issues Emergency Patches for Two Critical PHP2Shell RCE Flaws as Exploit Attempts Emerge",
        "PHP fixed two critical flaws letting an attacker without an account run code (CVSS 9.2).", published="2026-10-22T08:00:00Z")
    add(db, "thn-gitlab", "thn", "Critical GitLab Flaw (CVSS 10.0) Could Allow Unauthenticated Remote Code Execution",
        "GitLab patched an integer overflow in its regex compiler.")
    add(db, "node-rel", "node", "Wednesday, October 21, 2026 Security Releases", "Wednesday, October 21, 2026 Security Releases")
    add(db, "thn-node", "thn", "Node.js Brotli Decoder Bug Could Allow Remote Code Execution in All Supported Versions",
        "Node.js fixed 10 flaws.", published="2026-10-22T06:00:00Z")
    add(db, "kev-old", "kev", "CVE-2021-22175: GitLab SSRF", "old catalog entry", published=None, catalog_added_at="2021-11-01T00:00:00Z")
    add(db, "kev-new", "kev", "CVE-2026-110936: Siemens Software Center Uncontrolled Search Path Element",
        "Siemens Software Center contains an uncontrolled search path element.", published=None, catalog_added_at="2026-10-20T00:00:00Z")
    add(db, "ghsa-pillow", "ghsa", "Pillow: Argument Injection in Ghostscript call", "High severity argument injection.",
        external_id="GHSA-w889-685w-c8fh", affected_versions=[{"package": {"ecosystem": "pip", "name": "Pillow"}}])
    add(db, "ghsa-requests", "ghsa", "Requests: header injection", "High severity header injection.",
        external_id="GHSA-9hjg-9r4m-mvj7", affected_versions=[{"package": {"ecosystem": "pip", "name": "requests"}}])


def by_label(items):
    return {item["label"]: item for item in items}


def test_php2shell_ranks_first_with_both_cves_and_inferred_news_link(db):
    week(db)
    items = desk.clusters(db_path=db, now=NOW)
    top = items[0]
    assert top["cves"] == ["CVE-2026-109618", "CVE-2026-109619"], "one report listing two CVEs is one item"
    assert top["primary_source"] and top["reported_exploited"] and not top["kev"]
    assert top["linked"] and top["linked"][0]["linked_by"].endswith("(inferred)")
    assert any("exploitation reported (not confirmed by CISA KEV)" == reason for reason in top["score_reasons"])


def test_reports_without_cves_still_surface(db):
    week(db)
    labels = by_label(desk.clusters(db_path=db, now=NOW))
    gitlab = next(item for label, item in labels.items() if label.startswith("GitLab security issue"))
    assert gitlab["reported_cvss"] == 10.0 and gitlab["unauthenticated"]
    node = next(item for label, item in labels.items() if label.startswith("Node.js security issue"))
    assert set(node["sources"]) == {"Node.js Security Releases", "The Hacker News"}, "vendor release and news merge"
    assert node["deployment_exposure"] == ["Node.js"]


def test_old_catalog_history_is_outside_the_window_and_kev_is_confirmation(db):
    week(db)
    labels = by_label(desk.clusters(db_path=db, now=NOW))
    assert "CVE-2021-22175" not in labels, "years-old KEV entries collected today are not new"
    assert labels["CVE-2026-110936"]["kev"]


def test_registry_advisories_get_exposure_only_from_our_dependencies(db):
    week(db)
    labels = by_label(desk.clusters(db_path=db, now=NOW))
    assert labels["GHSA-w889-685w-c8fh"]["deployment_exposure"] == [], "Pillow is not a SecOpsAI dependency"
    assert labels["GHSA-9hjg-9r4m-mvj7"]["deployment_exposure"] == ["depends on requests (pip)"]
    assert labels["GHSA-9hjg-9r4m-mvj7"]["technologies"] == [], "the ecosystem name is not a technology match"


def fake_fetch(records):
    def fetch(url):
        for key, value in records.items():
            if key in url:
                if value == 404:
                    raise ValueError("registry returned HTTP 404")
                return json.dumps(value).encode()
        raise ValueError("registry returned HTTP 503")
    return fetch


def test_claim_check_confirms_flags_mismatch_and_wrong_ids(db):
    published = {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {
        "descriptions": [{"lang": "en", "value": "PHP uses longjmp() for OOM errors."}],
        "metrics": [{"cvssV4_0": {"baseScore": 9.2}}]}}}
    fetch = fake_fetch({"cveawg.mitre.org/api/cve/CVE-2026-109618": published,
                        "cveawg.mitre.org/api/cve/CVE-2026-000001": 404,
                        "nvd": {"vulnerabilities": []}})
    good = desk.check_claims({"cves": ["CVE-2026-109618"], "reported_cvss": 9.2, "sources": ["The Hacker News"], "reported_exploited": True}, fetch)
    statuses = {claim["claim"]: claim["status"] for claim in good["claims"]}
    assert statuses == {"CVE-2026-109618 exists": "confirmed", "CVSS 9.2": "confirmed", "exploited in the wild": "reported"}
    assert good["official_description"].startswith("PHP uses longjmp()")
    wrong = desk.check_claims({"cves": ["CVE-2026-109618"], "reported_cvss": 9.8, "sources": []}, fetch)
    assert {claim["claim"]: claim["status"] for claim in wrong["claims"]}["CVSS 9.8"] == "mismatch"
    missing = desk.check_claims({"cves": ["CVE-2026-000001"], "sources": []}, fetch)
    assert missing["claims"][0]["status"] == "not_found" and missing["needs_attention"]
    unavailable = desk.check_claims({"cves": ["CVE-2026-777777"], "sources": []}, fetch)
    assert unavailable["claims"][0]["status"] == "unavailable"


def test_claim_checks_are_cached_and_shown_in_the_projection(db):
    week(db)
    calls = []
    record = {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {"metrics": [{"cvssV3_1": {"baseScore": 9.2}}]}}}

    def fetch(url):
        calls.append(url)
        return json.dumps(record if "cveawg" in url else {"vulnerabilities": []}).encode()

    first = desk.run_claim_checks(fetch, db_path=db, now=NOW)
    assert "CVE-2026-109618" in first["checked"]
    calls.clear()
    assert desk.run_claim_checks(fetch, db_path=db, now=NOW)["checked"] == [], "fresh checks are not repeated"
    view = desk.projection(db_path=db, now=NOW)
    top = view["items"][0]
    assert top["cves"] == ["CVE-2026-109618", "CVE-2026-109619"]
    assert any(claim["status"] == "confirmed" for claim in top["claims"])
    assert len(json.dumps(view)) < 40000


def test_solo_operation_lets_one_named_human_hold_every_duty(db):
    from secopsai.research_coverage import readiness_report
    from secopsai.research_editorial import configure_roster
    from secopsai.research_governance import operational_requirement, solo_operator

    register_person({"person_id": "operator.owner", "display_name": "Owner", "roles": ["operator", "author", "editor", "technical_reviewer"],
                     "qualification": "Synthetic solo operator"}, actor="operator.owner", db_path=db)
    shift = {"author_id": "operator.owner", "editor_id": "operator.owner", "backup_id": "operator.owner"}
    with pytest.raises(ValueError, match="distinct"):
        configure_roster({"days": {str(d): dict(shift) for d in range(7)}}, actor="operator.owner", db_path=db)
    operational_requirement({"kind": "solo_operation", "status": "accepted", "operator_id": "operator.owner", "responsible_person": "Owner",
                             "scope": "vulnerability research notes and daily briefs", "reference": "operator decision 2026-10-22",
                             "recorded_at": "2026-10-22T12:00:00Z", "limitations": "single reviewer; drafts come from the automated desk"},
                            actor="operator.owner", db_path=db)
    assert solo_operator(db_path=db) == "operator.owner"
    configure_roster({"days": {str(d): dict(shift) for d in range(7)}}, actor="operator.owner", db_path=db)
    report = readiness_report(db_path=db)
    assert report["requirements"]["named_seven_day_roster"]
    assert "partner_telemetry_access" not in report["missing_requirements"]
    assert report["solo_operation"] == {"active": True, "operator_id": "operator.owner", "not_applicable": ["partner_telemetry_access"]}
    register_person({"person_id": "someone.else", "display_name": "Other", "roles": ["editor"], "qualification": "Synthetic editor"},
                    actor="operator.owner", db_path=db)
    with pytest.raises(ValueError, match="distinct"):  # solo means one person for every duty, not a partial pair
        mixed = {"author_id": "operator.owner", "editor_id": "operator.owner", "backup_id": "someone.else"}
        configure_roster({"days": {str(d): dict(mixed) for d in range(7)}}, actor="operator.owner", db_path=db)


def test_research_note_maps_detections_claims_and_exposure(db):
    week(db)
    assert [r["rule_id"] for r in desk.detections_for({"cves": ["CVE-2026-109618"], "names": []})] == ["RULE-311"]
    assert [r["rule_id"] for r in desk.detections_for({"cves": [], "names": ["PHP2Shell"]})] == ["RULE-311"]
    record = {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {"metrics": [{"cvssV3_1": {"baseScore": 9.2}}]}}}
    desk.run_claim_checks(lambda url: json.dumps(record if "cveawg" in url else {"vulnerabilities": []}).encode(), db_path=db, now=NOW)
    note = "\n".join(desk.research_note("php-adv", db_path=db, now=NOW))
    assert "| CVE-2026-109618 exists | confirmed |" in note
    assert "SecOpsAI detection: RULE-311" in note
    node = "\n".join(desk.research_note("node-rel", db_path=db, now=NOW))
    assert "no SecOpsAI rule covers this yet" in node and "SecOpsAI deployment exposure: Node.js." in node
    assert desk.research_note("not-an-event", db_path=db, now=NOW) == []


def test_html_scores_vectors_and_non_advisories(db):
    gitlab = desk.signals("GitLab Patch Release: 19.5.1",
                          '<strong>CVSS</strong> 10.0 (<a href="x#explain=CVSS:3.1/AV:N/AC:L">'
                          "<code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</code></a>)")
    assert gitlab["reported_cvss"] == 10.0, "the vector's version is not a score"
    assert desk.signals("x", "CVSS:3.1/AV:N/AC:L/PR:N")["reported_cvss"] is None
    assert desk.signals("x", "rated CVSS v3.1 9.8 by NVD")["reported_cvss"] == 9.8
    add(db, "ovsx-gemdb", "ghsa", "gemtalksystems/gemdb 1.8.0",
        "Python with built-in transactional persistence. When you have critical, complex data, use GemDB.")
    assert not [item for item in desk.clusters(db_path=db, now=NOW) if "ovsx-gemdb" in item["event_ids"]], "a release listing is not an advisory"
