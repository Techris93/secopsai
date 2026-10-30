"""Automated verification under the operator's policy, on items shaped like the 2026-10-24 queue."""
import json
from datetime import datetime, timedelta, timezone

import pytest

import soc_store
from secopsai import research_auto_verify as auto
from secopsai.research_assurance import register_person
from secopsai.research_governance import operational_requirement
from secopsai.research_operation_store import records, transaction

NOW = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
OPERATOR = "operator.owner"
SOURCES = {
    "php": ("PHP Security Advisories", "vendor"),
    "gitlab": ("GitLab Security Releases", "vendor"),
    "kev": ("CISA Known Exploited Vulnerabilities", "government"),
    "thn": ("The Hacker News", "aggregator"),
}


@pytest.fixture
def db(tmp_path):
    path = str(tmp_path / "auto.db")
    soc_store.init_db(path)
    with transaction(path) as conn:
        for key, (name, source_class) in SOURCES.items():
            config = {"source_id": key, "name": name, "url": f"https://{key}.example/feed", "parser": "cisa_kev" if key == "kev" else "rss",
                      "source_class": source_class, "sharing": "public", "license": "unknown", "interval_seconds": 3600, "enabled": True}
            conn.execute("INSERT INTO research_intel_sources(source_id,config_json) VALUES (?,?)", (key, json.dumps(config)))
            conn.execute("INSERT INTO research_source_snapshots VALUES (?,?,?,?,?,?,?)",
                         (f"snap-{key}", key, __import__("hashlib").sha256(b"{}").hexdigest(), "x", NOW.isoformat(), "1", b"{}"))
    register_person({"person_id": OPERATOR, "display_name": "Owner", "roles": ["operator", "author", "editor", "technical_reviewer"],
                     "qualification": "Synthetic solo operator"}, actor=OPERATOR, db_path=path)
    return path


RECENT = (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")


def add(db, event_id, source, title, excerpt, *, url=None, observed="2026-10-24T10:00:00Z", **payload):
    body = {"title": title, "excerpt": excerpt, "url": url or f"https://{source}.example/{event_id}", "published_at": RECENT, **payload}
    with transaction(db) as conn:
        conn.execute("INSERT INTO research_intel_events VALUES (?,?,?,?,?,?,?,?)",
                     (event_id, source, event_id, f"snap-{source}", body["published_at"], observed, observed, json.dumps(body)))


def queue(db):
    add(db, "php-adv", "php", "Security advisory: Critical remote code execution vulnerabilities, update now",
        "<p>PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35 fix two critical vulnerabilities that can allow unauthenticated remote code execution.</p>"
        " RCE via OOM corruption, CVE-2026-109618, and CVE-2026-109619.", url="https://www.php.net/archive/2026.php#2026-10-21-5")
    add(db, "php-rel", "php", "PHP 8.5.12 Released!",
        "This is a security release fixing two critical vulnerabilities (CVE-2026-109618, CVE-2026-109619).", url="https://www.php.net/archive/2026.php#2026-10-21-4")
    add(db, "php-info", "php", "Informational advisory: Session upload progress",
        "We suggest you set <code>session.upload_progress.enabled=0</code> until the next regular bugfix release, to fully protect from an unlikely RCE vector."
        " This setting was already listed as a mitigation in the advisory for CVE-2026-109619.",
        url="https://www.php.net/archive/2026.php#2026-10-23-1")
    gitlab = "https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/"
    add(db, "gl-1", "gitlab", "GitLab Critical Patch Release: 19.5.1, 19.4.3, 19.3.6", "Fixes CVE-2026-110264.", url=gitlab)
    add(db, "gl-2", "gitlab", "GitLab Critical Patch Release: 19.5.1, 19.4.3, 19.3.6", "Fixes CVE-2026-110264.", url=gitlab, observed="2026-10-24T11:00:00Z")
    add(db, "kev-ivanti", "kev", "CVE-2026-104935: Ivanti Connect Secure Authentication Bypass",
        "Ivanti Connect Secure contains an authentication bypass.", catalog_added_at="2026-10-23T00:00:00Z", required_action="Apply mitigations per vendor instructions or discontinue use.")
    add(db, "thn-brick", "thn", "Attackers Exploit CVSS 10.0 Bricksforge WordPress Flaw", "CVE-2026-85097 exploited.")
    add(db, "php-fake", "php", "Security advisory: session handler", "CVE-2026-115560 (CVSS 9.2) allows remote code execution and is fixed in 8.5.13.")
    add(db, "php-nofix", "php", "Security advisory: heads-up", "A remote code execution vulnerability CVE-2026-109619 (CVSS 9.2) is being investigated.")


def cve_fetch(url):
    if "115560" in url:
        raise ValueError("registry returned HTTP 404")
    if "cveawg" in url:
        cve = url.rsplit("/", 1)[1]
        return json.dumps({"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {
            "descriptions": [{"lang": "en", "value": f"Official description of {cve}. More detail."}],
            "metrics": [{"cvssV3_1": {"baseScore": 9.2}}]}}}).encode()
    return json.dumps({"vulnerabilities": []}).encode()


def delegate(db):
    operational_requirement({"kind": "automated_verification", "status": "accepted", "operator_id": OPERATOR, "responsible_person": "Owner",
                             "scope": "routine primary-source items", "reference": "dashboard 2026-10-24", "recorded_at": "2026-10-24T12:00:00Z",
                             "limitations": "rules only; disputes stay manual"}, actor=OPERATOR, db_path=db)


def decisions(db):
    return {r["payload"]["event_id"]: r["payload"] for r in reversed(records("intel_verification", db_path=db, limit=100))}


def test_nothing_happens_without_the_operators_delegation(db):
    queue(db)
    assert auto.run(cve_fetch, db_path=db)["status"] == "disabled"
    assert decisions(db) == {}


def test_routine_items_are_decided_and_disputes_stay_with_the_human(db):
    queue(db)
    delegate(db)
    outcome = auto.run(cve_fetch, db_path=db)
    got = decisions(db)
    assert got["php-adv"]["decision"] == "verified"
    assert "8.5.12, 8.4.27, 8.3.36, 8.2.35" in got["php-adv"]["defensive_action"]
    assert "RULE-311" in got["php-adv"]["defensive_action"], "the matching detection is named"
    assert "Official description of CVE-2026-109618" in got["php-adv"]["summary"]
    assert got["php-adv"]["automation"]["checks"]["CVE-2026-109618"][0] == "confirmed"
    assert got["php-info"]["decision"] == "verified" and "session.upload_progress.enabled=0" in got["php-info"]["defensive_action"]
    assert got["php-rel"]["decision"] == "rejected", "release note for an already verified advisory"
    assert got["gl-2"]["decision"] == "verified" and got["gl-1"]["decision"] == "rejected", "the newest copy is kept"
    assert "duplicate of gl-2" in got["gl-1"]["rationale"]
    assert got["kev-ivanti"]["decision"] == "verified" and "discontinue use" in got["kev-ivanti"]["defensive_action"]
    assert got["thn-brick"]["decision"] == "needs_review", "news reports never verified automatically"
    assert got["php-fake"]["decision"] == "needs_review" and "not found" in got["php-fake"]["rationale"]
    assert got["php-nofix"]["decision"] == "needs_review" and "no fixed version" in got["php-nofix"]["rationale"]
    assert outcome["verified"] == 4 and outcome["needs_review"] == 3
    assert all(value["reviewer_id"] == OPERATOR for value in got.values())


def test_a_second_run_does_not_redecide_and_brief_discloses_automation(db):
    from secopsai.research_editorial import configure_roster, create_daily_brief
    from secopsai.research_governance import operational_requirement as requirement

    queue(db)
    delegate(db)
    auto.run(cve_fetch, db_path=db)
    count = len(records("intel_verification", db_path=db, limit=100))
    auto.run(cve_fetch, db_path=db)
    assert len(records("intel_verification", db_path=db, limit=100)) == count
    requirement({"kind": "solo_operation", "status": "accepted", "operator_id": OPERATOR, "responsible_person": "Owner", "scope": "briefs",
                 "reference": "test", "recorded_at": "2026-10-24T12:00:00Z", "limitations": "single reviewer"}, actor=OPERATOR, db_path=db)
    configure_roster({"days": {str(d): {"author_id": OPERATOR, "editor_id": OPERATOR, "backup_id": OPERATOR} for d in range(7)}}, actor=OPERATOR, db_path=db)
    today = datetime.now(__import__("zoneinfo").ZoneInfo("Europe/Istanbul")).date().isoformat()
    brief = create_daily_brief(date=today, db_path=db)
    assert {item["verification"] for item in brief["draft"]["items"]} == {"automated"}
    assert "Verified automatically by SecOpsAI rules" in brief["draft"]["body_markdown"]


def test_only_the_reviewer_can_delegate_and_a_revoked_policy_stops_automation(db):
    register_person({"person_id": "someone.else", "display_name": "Other", "roles": ["operator"], "qualification": "x"}, actor=OPERATOR, db_path=db)
    with pytest.raises(ValueError, match="only the reviewer themselves"):
        operational_requirement({"kind": "automated_verification", "status": "accepted", "operator_id": OPERATOR, "responsible_person": "x",
                                 "scope": "x", "reference": "x", "recorded_at": "2026-10-24T12:00:00Z", "limitations": "x"},
                                actor="someone.else", db_path=db)
    queue(db)
    delegate(db)
    operational_requirement({"kind": "automated_verification", "status": "revoked", "operator_id": OPERATOR, "responsible_person": "Owner",
                             "scope": "x", "reference": "x", "recorded_at": "2026-10-24T13:00:00Z", "limitations": "x"}, actor=OPERATOR, db_path=db)
    assert auto.run(cve_fetch, db_path=db)["status"] == "disabled"


def test_unranked_registry_items_are_left_alone_and_earlier_auto_verifications_withdrawn(db):
    queue(db)
    add(db, "ghsa-noise", "php", "Some library: minor issue", "A minor issue fixed in 1.2.3.", url="https://php.example/noise")
    delegate(db)
    from secopsai.research_primary_intel import verify_event
    delegation = auto.policy(db_path=db)
    verify_event("ghsa-noise", {"decision": "verified", "rationale": "Automated verification: old rule", "summary": "x", "defensive_action": "Upgrade to 1.2.3.",
                                "limitations": "x", "primary_url": "https://php.example/noise", "primary_event_id": "ghsa-noise", "attribution": "source_reported"},
                 actor=OPERATOR, db_path=db, automation={"policy_record_id": delegation["record_id"], "rule": "old", "checks": {}})
    outcome = auto.run(cve_fetch, db_path=db)
    assert outcome["withdrawn"] == 1
    assert decisions(db)["ghsa-noise"]["decision"] == "needs_review", "unranked item withdrawn from the brief"
    assert decisions(db)["php-adv"]["decision"] == "verified", "ranked items are still handled"


def test_the_newest_copy_with_the_corrected_citation_is_kept(db):
    old = "Informational advisory: Session upload progress"
    text = ("We suggest you set session.upload_progress.enabled=0 until the next regular bugfix release, to fully protect from an "
            "unlikely RCE vector. This setting was already listed as a mitigation in the advisory for CVE-2026-109619.")
    queue(db)
    with transaction(db) as conn:
        conn.execute("DELETE FROM research_intel_events WHERE event_id='php-info'")
    add(db, "php-info-old", "php", old, text, url="https://www.php.net/index.php", observed="2026-10-24T09:00:00Z")
    add(db, "php-info-new", "php", old, text, url="https://www.php.net/index.php#2026-10-23-1", observed="2026-10-24T11:00:00Z")
    delegate(db)
    auto.run(cve_fetch, db_path=db)
    got = decisions(db)
    assert got["php-info-new"]["decision"] == "verified", got["php-info-new"]["rationale"]
    assert got["php-info-new"]["primary_url"].endswith("#2026-10-23-1")
    assert got["php-info-old"]["decision"] == "rejected" and "duplicate of php-info-new" in got["php-info-old"]["rationale"]


def test_cisa_entries_sharing_the_catalog_url_are_not_duplicates_and_wrong_rejections_are_redone(db):
    feed = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    queue(db)
    for event_id, cve in (("kev-a", "CVE-2026-110936"), ("kev-b", "CVE-2026-110447")):
        add(db, event_id, "kev", f"{cve}: Vendor product remote code execution", f"{cve} allows remote code execution.", url=feed,
            catalog_added_at="2026-10-23T00:00:00Z", required_action="Apply mitigations per vendor instructions or discontinue use.")
    delegate(db)
    from secopsai.research_primary_intel import verify_event
    delegation = auto.policy(db_path=db)
    verify_event("kev-b", {"decision": "rejected", "rationale": "Automated verification: duplicate of kev-a (same citation)", "limitations": "x",
                           "primary_url": feed, "primary_event_id": "kev-b", "attribution": "source_reported"}, actor=OPERATOR, db_path=db,
                 automation={"policy_record_id": delegation["record_id"], "rule": "duplicate of kev-a (same citation)", "checks": {}})
    auto.run(cve_fetch, db_path=db)
    got = decisions(db)
    assert got["kev-a"]["decision"] == "verified"
    assert got["kev-b"]["decision"] == "verified", "the URL-only rejection is decided again"


def test_an_item_is_never_a_duplicate_of_itself_and_the_redo_settles(db):
    feed = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    queue(db)
    add(db, "kev-x", "kev", "CVE-2026-110936: Vendor product remote code execution", "CVE-2026-110936 allows remote code execution.", url=feed,
        catalog_added_at="2026-10-23T00:00:00Z", required_action="Apply mitigations per vendor instructions or discontinue use.")
    delegate(db)
    from secopsai.research_primary_intel import verify_event
    delegation = auto.policy(db_path=db)
    common = {"limitations": "x", "primary_url": feed, "primary_event_id": "kev-x", "attribution": "source_reported"}
    verify_event("kev-x", {"decision": "verified", "rationale": "Automated verification: ok", "summary": "s", "defensive_action": "Apply.", **common},
                 actor=OPERATOR, db_path=db, automation={"policy_record_id": delegation["record_id"], "rule": "ok", "checks": {}})
    verify_event("kev-x", {"decision": "rejected", "rationale": "Automated verification: duplicate of kev-x (same citation)", **common},
                 actor=OPERATOR, db_path=db, automation={"policy_record_id": delegation["record_id"], "rule": "duplicate of kev-x (same citation)", "checks": {}})
    auto.run(cve_fetch, db_path=db)
    assert decisions(db)["kev-x"]["decision"] == "verified", decisions(db)["kev-x"]["rationale"]
    count = len(records("intel_verification", db_path=db, limit=1000))
    auto.run(cve_fetch, db_path=db)
    assert len(records("intel_verification", db_path=db, limit=1000)) == count, "no decision churn on the next run"


def test_a_release_headline_score_does_not_block_its_other_cves(db):
    queue(db)
    add(db, "gl-multi", "gitlab", "GitLab Critical Patch Release: 19.5.1, 19.4.3",
        "We released 19.5.1 and 19.4.3. CVE-2026-110264 (CVSS 10.0) and CVE-2026-105711 are fixed in these versions.")
    delegate(db)

    def fetch(url):
        score = 10.0 if "110264" in url else 6.5
        if "cveawg" in url:
            return json.dumps({"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {"metrics": [{"cvssV3_1": {"baseScore": score}}]}}}).encode()
        return json.dumps({"vulnerabilities": []}).encode()

    auto.run(fetch, db_path=db)
    assert decisions(db)["gl-multi"]["decision"] == "verified", decisions(db)["gl-multi"]["rationale"]


def test_an_old_cvss_mismatch_decision_is_decided_again_once(db):
    queue(db)
    delegate(db)
    from secopsai.research_primary_intel import verify_event
    delegation = auto.policy(db_path=db)
    rule = "official records disagree: CVSS 9.2: mismatch"
    verify_event("php-adv", {"decision": "needs_review", "rationale": "Automated verification: " + rule, "limitations": rule,
                             "primary_url": "https://www.php.net/archive/2026.php#2026-10-21-5", "attribution": "source_reported"},
                 actor=OPERATOR, db_path=db, automation={"policy_record_id": delegation["record_id"], "rule": rule, "checks": {}})
    auto.run(cve_fetch, db_path=db)
    assert decisions(db)["php-adv"]["decision"] == "verified"
    count = len(records("intel_verification", db_path=db, limit=1000))
    auto.run(cve_fetch, db_path=db)
    assert len(records("intel_verification", db_path=db, limit=1000)) == count


def test_a_mentioned_cve_is_not_described_as_the_items_own():
    event = {"event_id": "kev", "source_id": "kev", "source": {"name": "CISA Known Exploited Vulnerabilities", "source_class": "government"},
             "payload": {"title": "CVE-2026-46300: Linux Kernel Missing Initialization", "published_at": None, "required_action": "Apply mitigations.",
                         "excerpt": "Linux Kernel flaw. Can be chained with CVE-2026-109618 and CVE-2026-109619."}}
    checks = {cve: {"cve": cve, "official_cvss": [7.8, 9.2], "official_description": f"Official text of {cve}.", "claims": []}
              for cve in ("CVE-2026-46300", "CVE-2026-109618", "CVE-2026-109619")}
    result = auto._decide(event, checks, {})
    assert result["cves"] == ["CVE-2026-46300"]
    assert "Official text of CVE-2026-46300" in result["summary"]
    assert "Official text of CVE-2026-109618" not in result["summary"]
    assert "also mentions CVE-2026-109618, CVE-2026-109619" in result["summary"]
    assert "official CVSS 7.8 and 9.2" in result["summary"]


def test_a_github_advisory_is_about_its_own_cve_not_the_prior_art_it_cites():
    source = {"name": "GitHub Security Advisories", "source_class": "vendor"}
    excerpt = "Similar to CVE-2018-1193 and CVE-2025-41235. Fixed in echo 4.16.0."
    event = {"event_id": "ghsa", "source_id": "gh", "source": source,
             "payload": {"title": "Echo: HTTPS Redirect Bypass", "excerpt": excerpt, "external_id": "GHSA-2ffq-g2xg-c22p", "cve_id": "CVE-2026-118657",
                         "affected_versions": [{"package": {"name": "echo"}, "first_patched_version": "4.16.0"}], "published_at": RECENT}}
    assert auto._decide(event, {}, {})["unchecked"] == ["CVE-2026-118657"]
    without = {**event, "payload": {key: value for key, value in event["payload"].items() if key != "cve_id"}}
    result = auto._decide(without, {}, {})
    assert result["cves"] == [] and "CVE-2018-1193" not in result["summary"].split("also mentions")[0]


def test_an_old_advisory_is_not_news_unless_it_is_being_exploited():
    source = {"name": "GitHub Security Advisories", "source_class": "vendor"}
    old = {"event_id": "old", "source_id": "gh", "source": source,
           "payload": {"title": "LangChain Experimental code execution", "excerpt": "Fixed in 0.0.52.", "external_id": "GHSA-v8vj-cv27-hjv8",
                       "published_at": "2024-02-26T18:30:31Z", "source_updated_at": RECENT}}
    assert auto._decide(old, {}, {})["decision"] == "rejected"
    exploited = {**old, "payload": {**old["payload"], "excerpt": "Actively exploited in the wild. Upgrade to fixed release 0.0.52."}}
    assert auto._decide(exploited, {}, {})["decision"] != "rejected"
    listed = {**old, "payload": {**old["payload"], "catalog_added_at": RECENT}}
    assert auto._decide(listed, {}, {})["decision"] != "rejected"


def test_an_earlier_automated_verification_is_decided_again_once(db):
    queue(db)
    delegate(db)
    auto.run(cve_fetch, db_path=db)
    from secopsai.research_primary_intel import verify_event
    delegation = auto.policy(db_path=db)
    current = decisions(db)["kev-ivanti"]
    verify_event("kev-ivanti", {"decision": "verified", "rationale": "old rule", "summary": "Text from the old rule.",
                                "defensive_action": current["defensive_action"], "limitations": current["limitations"],
                                "primary_url": current["primary_url"], "attribution": "source_reported"},
                 actor=OPERATOR, db_path=db, automation={"policy_record_id": delegation["record_id"], "rule": "old", "checks": {}})
    auto.run(cve_fetch, db_path=db)
    assert "Text from the old rule." not in decisions(db)["kev-ivanti"]["summary"]
    count = len(records("intel_verification", db_path=db, limit=1000))
    auto.run(cve_fetch, db_path=db)
    assert len(records("intel_verification", db_path=db, limit=1000)) == count


def test_age_out_reports_first_then_archives_and_brings_back_what_the_desk_ranks(db):
    from secopsai.research_primary_intel import age_out_reviews, pending_public_reviews

    add(db, "old-quiet", "gitlab", "Old advisory", "Fixed in 1.2.3.", published_at="2024-01-01T00:00:00Z")
    add(db, "old-hot", "gitlab", "Old but hot", "Actively exploited in the wild.", published_at="2024-01-01T00:00:00Z")
    add(db, "old-kev", "kev", "CVE-2020-1234: Old KEV", "Listed.", published_at=None, catalog_added_at="2024-01-01T00:00:00Z")
    add(db, "old-ranked", "gitlab", "Old ranked", "Fixed in 1.2.3.", published_at="2024-01-01T00:00:00Z")
    add(db, "new", "gitlab", "New advisory", "Fixed in 1.2.3.")
    with transaction(db) as conn:
        for event_id in ("old-quiet", "old-hot", "old-kev", "old-ranked", "new"):
            conn.execute("INSERT INTO research_operation_queue(job_id,kind,event_id,payload_json,state,retry_at,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
                         (f"Q-{event_id}", "verify_intel", event_id, "{}", "awaiting_review", RECENT, RECENT, RECENT))

    report = age_out_reviews(keep={"old-ranked"}, db_path=db)
    assert (report["status"], report["would_archive"], report["archived"]) == ("report_only", 1, 0)
    assert (report["kept_exploited"], report["kept_ranked_or_held"], report["kept_recent"]) == (2, 1, 1)
    assert report["by_source"] == {"GitLab Security Releases": 1}
    assert "old-quiet" in {item["event_id"] for item in pending_public_reviews(db_path=db, limit=50)}

    assert age_out_reviews(keep={"old-ranked"}, enforce=True, db_path=db)["archived"] == 1
    assert "old-quiet" not in {item["event_id"] for item in pending_public_reviews(db_path=db, limit=50)}
    assert age_out_reviews(keep={"old-quiet", "old-ranked"}, enforce=True, db_path=db)["restored"] == 1
    assert "old-quiet" in {item["event_id"] for item in pending_public_reviews(db_path=db, limit=50)}


def test_a_full_brief_keeps_reviewer_items_and_exploited_flaws_over_older_routine_ones():
    from secopsai.research_editorial import MAX_BRIEF_ITEMS, _brief_selection

    def item(name, source, day, verification="automated"):
        return {"title": name, "source": source, "first_observed_at": f"2026-10-{day}T00:00:00Z", "verification": verification}

    routine = [item(f"advisory-{day}", "GitHub Security Advisories", day) for day in range(10, 25)]
    chosen = [entry["title"] for entry in _brief_selection(routine + [
        item("late-kev", "CISA Known Exploited Vulnerabilities", 9),
        item("reviewed", "Socket Blog", 8, verification="human"),
    ])]
    assert len(chosen) == MAX_BRIEF_ITEMS
    assert chosen[:3] == ["reviewed", "late-kev", "advisory-24"]
    assert "advisory-10" not in chosen, "the oldest routine item gives way"


def test_a_reviewer_item_reports_the_cves_it_names_not_its_clusters():
    from secopsai.research_editorial import _item_cves

    assert _item_cves({"summary": "Tracked as cve-2026-115560 and CVE-2026-115560."}) == ["CVE-2026-115560"]
    assert _item_cves({"summary": "No identifier yet."}) == []
    assert _item_cves({"summary": "Mentions CVE-2026-1111.", "automation": {"checks": {"CVE-2026-2222": ["confirmed"]}}}) == ["CVE-2026-2222"]


def test_only_a_socket_card_title_is_shortened():
    from secopsai.research_editorial import _display_title

    card = "Latest Cursor Removes Malicious Extension From Its Marketplace Threat Research Security News Oct 30, 2026"
    assert _display_title(card, "Socket Blog") == "Cursor Removes Malicious Extension From Its Marketplace"
    assert _display_title("Latest Thing", "Socket Blog") == "Latest Thing", "no date, not a card"
    assert _display_title(card, "The Hacker News") == card


def test_cisa_action_loses_the_pointer_to_notes_the_brief_does_not_carry():
    action = auto._defensive_action("t", "", {"required_action": "Follow BOD 26-04 (see URL in Notes) guidance and triage (see URL in Notes)."}, [])
    assert action == "Follow BOD 26-04 guidance and triage."
