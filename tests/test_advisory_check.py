import json
from datetime import datetime, timedelta, timezone

import pytest

import soc_store
from secopsai import advisory_check as check


def osv(advisory, ecosystem, name, events, versions=None):
    affected = {"package": {"ecosystem": ecosystem, "name": name}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}
    if versions is not None:
        affected["versions"] = versions
    return {"id": advisory, "affected": [affected]}


BANKS = osv("GHSA-64vx-6h2c-rjh7", "PyPI", "banks", [{"introduced": "0"}, {"fixed": "2.4.3"}], ["2.4.1", "2.4.2"])
DCMJS = osv("GHSA-px68-xx5g-48q5", "npm", "dcmjs", [{"introduced": "0"}, {"fixed": "0.52.0"}])
LXD = osv("GHSA-fmc8-p6q7-75cc", "Go", "github.com/canonical/lxd", [{"introduced": "0"}, {"fixed": "0.0.0-20260630083100-c5184be310b1"}])


@pytest.fixture
def db(tmp_path, monkeypatch):
    path = tmp_path / "soc.db"
    monkeypatch.setenv("SECOPSAI_DB_PATH", str(path))
    soc_store.init_db(str(path))
    return str(path)


def fetcher(*records, calls=None):
    by_id = {record["id"]: record for record in records}

    def fetch(url):
        if calls is not None:
            calls.append(url)
        advisory = url.rsplit("/", 1)[1]
        if advisory not in by_id:
            raise ValueError("HTTP 404")
        return json.dumps(by_id[advisory]).encode()
    return fetch


@pytest.mark.parametrize("ecosystem,lower,higher", [
    ("pypi", "2.4.2", "2.4.3"), ("pypi", "2.4.3rc1", "2.4.3"), ("pypi", "2.4.3.dev0", "2.4.3rc1"),
    ("pypi", "2.4.3", "2.4.3.post1"), ("pypi", "2.4", "2.4.0.1"), ("pypi", "1.9.9", "1.10"),
    ("npm", "0.51.3", "0.52.0"), ("npm", "1.0.0-beta.2", "1.0.0-beta.11"), ("npm", "1.0.0-rc.1", "1.0.0"),
    ("go", "0.0.0-20250101000000-abcdef", "0.0.0-20260630083100-c5184be310b1"), ("go", "0.0.0-0", "0.0.0-20250101000000-abcdef"),
])
def test_versions_order_as_each_ecosystem_does(ecosystem, lower, higher):
    assert check.version_key(ecosystem, lower) < check.version_key(ecosystem, higher)
    assert check.version_key("pypi", "2.4.0") == check.version_key("pypi", "2.4")


def test_a_record_passes_its_test_and_flags_only_affected_versions():
    for record in (BANKS, DCMJS, LXD):
        assert check.self_test(record)["ok"], record["id"]
    banks = check.packages(BANKS)[0]
    assert check.is_affected(banks, "2.4.2") and check.is_affected(banks, "1.0")
    assert not check.is_affected(banks, "2.4.3") and not check.is_affected(banks, "3.0.0")
    lxd = check.packages(LXD)[0]
    assert check.is_affected(lxd, "0.0.0-20250101000000-abcdefabcdef")
    assert not check.is_affected(lxd, "0.0.0-20260701000000-abcdefabcdef")


def test_a_record_the_check_cannot_stand_behind_is_not_published():
    no_fix = osv("GHSA-aaaa-bbbb-cccc", "PyPI", "pkg", [{"introduced": "1.0"}])
    assert check.self_test(no_fix) == {"ok": False, "reason": "pkg: the record names no fixed release"}
    disagree = osv("GHSA-aaaa-bbbb-cccc", "PyPI", "pkg", [{"introduced": "1.0"}, {"fixed": "1.2"}], ["1.1", "1.5"])
    assert "listed version 1.5 falls outside" in check.self_test(disagree)["reason"]
    other = osv("GHSA-aaaa-bbbb-cccc", "Maven", "org.x:y", [{"introduced": "0"}, {"fixed": "2"}])
    assert check.self_test(other)["ok"] is False
    last = osv("GHSA-aaaa-bbbb-cccc", "npm", "pkg", [{"introduced": "1.0.0"}, {"last_affected": "1.4.0"}, {"fixed": "1.5.0"}])
    package = check.packages(last)[0]
    assert check.is_affected(package, "1.4.0") and not check.is_affected(package, "1.4.1") and not check.is_affected(package, "0.9.0")


def test_pinned_versions_are_read_from_manifests_and_lockfiles(tmp_path):
    (tmp_path / "requirements-dev.txt").write_text("Banks[extra]==2.4.2  # pinned\ngitpython>=3\n", encoding="utf-8")
    (tmp_path / "poetry.lock").write_text('[[package]]\nname = "GitPython"\nversion = "3.1.40"\n', encoding="utf-8")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package-lock.json").write_text(json.dumps({"packages": {"": {}, "node_modules/dcmjs": {"version": "0.51.3"},
                                                                                "node_modules/a/node_modules/dcmjs": {"version": "0.52.1"}}}), encoding="utf-8")
    (tmp_path / "go.mod").write_text("module x\n\nrequire github.com/canonical/lxd v0.0.0-20250101000000-abcdef\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/dcmjs": {"version": "0.1.0"}}}), encoding="utf-8")
    found = {(item["ecosystem"], item["name"], item["version"], item["file"]) for item in check.installed_versions(tmp_path)}
    assert found == {("pypi", "banks", "2.4.2", "requirements-dev.txt"), ("pypi", "gitpython", "3.1.40", "poetry.lock"),
                     ("npm", "dcmjs", "0.51.3", "web/package-lock.json"), ("npm", "dcmjs", "0.52.1", "web/package-lock.json"),
                     ("go", "github.com/canonical/lxd", "0.0.0-20250101000000-abcdef", "go.mod")}


def test_scan_reports_affected_pins_and_leaves_fixed_ones(tmp_path):
    (tmp_path / "requirements.txt").write_text("banks==2.4.2\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(json.dumps({"packages": {"node_modules/dcmjs": {"version": "0.52.0"}}}), encoding="utf-8")
    result = check.scan(tmp_path, ["GHSA-64vx-6h2c-rjh7", "GHSA-px68-xx5g-48q5"], fetcher(BANKS, DCMJS))
    assert [(f["name"], f["version"], f["fixed"]) for f in result["findings"]] == [("banks", "2.4.2", ["2.4.3"])]
    assert result["packages_read"] == 2


def test_the_brief_names_a_check_only_after_its_test_passed(db):
    now = datetime(2026, 11, 9, 12, tzinfo=timezone.utc)
    calls = []
    fetch = fetcher(BANKS, calls=calls)
    assert check.run_checks(fetch, ["GHSA-64vx-6h2c-rjh7", "GHSA-23mf-xhv8-69c2"], db_path=db, now=now)["checked"] == [
        "GHSA-64vx-6h2c-rjh7", "GHSA-23mf-xhv8-69c2"]
    line = check.brief_line("https://github.com/advisories/GHSA-64vx-6h2c-rjh7", db_path=db)
    assert line == ["SecOpsAI detection: `secopsai supply-chain advisory-check --advisory GHSA-64vx-6h2c-rjh7 PATH` "
                    "flags banks before 2.4.3 in a project's manifests and lockfiles."]
    assert check.brief_line("https://github.com/advisories/GHSA-23mf-xhv8-69c2", db_path=db) == [], "an unavailable record is never named"
    assert check.brief_line("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", db_path=db) == []
    calls.clear()
    check.run_checks(fetch, ["GHSA-64vx-6h2c-rjh7", "GHSA-23mf-xhv8-69c2"], db_path=db, now=now + timedelta(hours=1))
    assert calls == ["https://api.osv.dev/v1/vulns/GHSA-23mf-xhv8-69c2"], "a passed check is cached; an unavailable one is retried"
