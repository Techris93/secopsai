import json
import subprocess
import sys
from pathlib import Path

import pytest

from secopsai import blog, research_cases, research_osv

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_research_post import _case  # noqa: E402


def _eligible(**overrides):
    return _case(**{"publication_reviews": [{"status": "approved"}], "embargo_until": None, **overrides})


@pytest.fixture()
def real_case(tmp_path, monkeypatch):
    db_path = str(tmp_path / "soc.db")
    created = research_cases.create_case(title="Hijacked release of left-padder steals npm tokens", db_path=db_path)
    case = _eligible(case_id=created["case_id"])
    monkeypatch.setattr(research_osv, "_case", lambda case_id, db_path: case)
    return case, db_path


def test_eligibility_needs_credible_verdict_approval_and_no_embargo():
    assert research_osv.eligibility(_eligible()) == []
    assert any("credible" in item for item in research_osv.eligibility(_eligible(verdicts=[{"verdict": "likely", "created_at": "2026-10-10"}])))
    assert any("review" in item for item in research_osv.eligibility(_case()))
    assert any("embargoed" in item for item in research_osv.eligibility(_eligible(embargo_until="2999-01-01T00:00:00Z")))


def test_mal_reports_follow_the_upstream_contribution_rules():
    reports = research_osv.build_mal_reports(_eligible(), "SECOPSAI-2026-0001", advisory_url="https://blog.secopsai.dev/advisories/SECOPSAI-2026-0001.html")
    assert len(reports) == 1, "two versions of one package are one report"
    report = reports[0]
    assert research_osv.validate_mal_report(report) == []
    assert "id" not in report and "summary" not in report
    assert report["affected"][0]["package"] == {"ecosystem": "npm", "name": "left-padder"}
    assert report["affected"][0]["versions"] == ["2.3.1", "2.3.2"]
    assert report["aliases"] == ["SECOPSAI-2026-0001"]
    iocs = report["database_specific"]["iocs"]
    assert iocs["urls"] == ["https://discord.com/api/webhooks/1/abc"] and iocs["files"][0]["digests"] == {"sha256": "a" * 64}
    assert "Trigger: runs automatically when the package is installed." in report["details"]
    assert research_osv.mal_report_path(report, "SECOPSAI-2026-0001") == "osv/malicious/npm/left-padder/MAL-0000-secopsai-secopsai-2026-0001.json"
    assert research_osv.validate_mal_report({**report, "id": "MAL-1"}) == ["id and summary must not be set"]


def test_advisory_ids_are_stable_and_sequential(real_case, tmp_path):
    case, db_path = real_case
    first = research_osv.assign_advisory_id(case["case_id"], db_path=db_path, year=2026)
    assert first == "SECOPSAI-2026-0001"
    assert research_osv.assign_advisory_id(case["case_id"], db_path=db_path, year=2026) == first
    other = research_cases.create_case(title="Second case", db_path=db_path)
    assert research_osv.assign_advisory_id(other["case_id"], db_path=db_path, year=2026) == "SECOPSAI-2026-0002"


def test_publish_renders_pages_and_feed(real_case, tmp_path):
    case, db_path = real_case
    paths = blog.BlogPaths(root=tmp_path / "blog")
    result = research_osv.publish_advisory(case["case_id"], db_path=db_path, paths=paths)
    advisory_id = result["advisory_id"]
    doc = json.loads((paths.root / "advisories" / f"{advisory_id}.json").read_text())
    assert doc["id"] == advisory_id and doc["affected"][0]["versions"] == ["2.3.1", "2.3.2"]
    page = (paths.root / "advisories" / f"{advisory_id}.html").read_text()
    assert "left-padder" in page and "removed" in page and "available" in page and "a" * 64 in page
    assert advisory_id in (paths.root / "advisories" / "index.html").read_text()
    assert json.loads((paths.root / "advisories" / "index.json").read_text())[0]["id"] == advisory_id
    assert f"/advisories/{advisory_id}.html" in (paths.root / "sitemap.xml").read_text()


def test_submit_is_a_dry_run_without_confirm_and_records_the_pr(real_case, tmp_path, monkeypatch):
    case, db_path = real_case
    monkeypatch.chdir(tmp_path)
    plan = research_osv.submit_osv(case["case_id"], db_path=db_path)
    assert plan["submitted"] is False and plan["files"][0].startswith("osv/malicious/npm/left-padder/")
    calls = []

    def runner(args, **_kwargs):
        calls.append(args)
        out = {"api": "operator\n", "pr": "https://github.com/ossf/malicious-packages/pull/1\n"}.get(args[1], "")
        return subprocess.CompletedProcess(args, 0, out, "")

    result = research_osv.submit_osv(case["case_id"], confirm=True, db_path=db_path, runner=runner)
    assert result["pull_request"] == "https://github.com/ossf/malicious-packages/pull/1"
    assert ["gh", "repo", "fork", "ossf/malicious-packages", "--clone=false"] in calls
    assert any(args[:3] == ["gh", "pr", "create"] for args in calls)


def test_recorded_osv_ids_feed_the_tracker(real_case):
    case, db_path = real_case
    research_osv.assign_advisory_id(case["case_id"], db_path=db_path)
    with pytest.raises(ValueError):
        research_osv.record_osv_ids(case["case_id"], ["GHSA-x"], db_path=db_path)
    result = research_osv.record_osv_ids(case["case_id"], ["MAL-2026-1234"], db_path=db_path)
    assert result["osv_ids"] == ["MAL-2026-1234"]
    stored = research_cases.get_case(case["case_id"], db_path=db_path)
    assert stored["metadata"]["osv_id"] == "MAL-2026-1234"
