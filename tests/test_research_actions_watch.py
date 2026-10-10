import io
import json
import tarfile

import pytest

import soc_store
from secopsai import research_actions_watch as watch
from secopsai.research_intake import SafeFetcher

pytest.importorskip("yara_x")


def test_classify_separates_attacks_from_normal_tag_moves():
    previous = {"v1.2.3": ("aaa", "commit"), "v1": ("aaa", "commit"), "v35": ("ccc", "commit")}
    current = {"v1.2.3": ("bad", "commit"), "v1": ("ddd", "commit"), "v1.3.0": ("ddd", "commit"), "v35": ("evil", "commit")}
    changes = {item["tag"]: item for item in watch.classify(previous, current)}
    assert changes["v1.2.3"]["change"] == "version_tag_moved" and changes["v1.2.3"]["severity"] == "high"
    assert "v1" not in changes, "floating tag moved to a released commit is normal"
    assert changes["v35"]["change"] == "floating_tag_moved_off_release" and changes["v35"]["severity"] == "medium"
    assert changes["v1.3.0"]["change"] == "new_release" and changes["v1.3.0"]["severity"] == ""


def _tgz(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_repointed_tag_is_scanned_and_alerted(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_GITHUB_TOKEN", "test-token")
    db_path = str(tmp_path / "soc.db")
    soc_store.init_db(db_path)
    state = {"refs": [{"ref": "refs/tags/v35.0.0", "object": {"sha": "good", "type": "commit"}}]}
    payload = _tgz({"repo-evil/dist/index.js": b"const m=require('fs').readFileSync(`/proc/${pid}/mem`);console.log(Buffer.from(m).toString('base64'))"})

    def fetch(url, _max):
        if "matching-refs" in url:
            return 200, {"content-type": "application/json"}, json.dumps(state["refs"]).encode()
        if url.startswith("https://codeload.github.com/acme/changed-files/tar.gz/evil"):
            return 200, {"content-type": "application/gzip"}, payload
        raise AssertionError(url)

    fetcher = SafeFetcher(fetch=fetch)
    first = watch.run(db_path=db_path, fetcher=fetcher, repos=["acme/changed-files"])
    assert first["baselined"] == 1 and first["alerts"] == 0
    state["refs"] = [{"ref": "refs/tags/v35.0.0", "object": {"sha": "evil", "type": "commit"}}]
    second = watch.run(db_path=db_path, fetcher=fetcher, repos=["acme/changed-files"])
    assert second["changes"] == 1 and second["hits"] == 1 and second["alerts"] == 1
    with soc_store.connect(db_path) as connection:
        alert = connection.execute("SELECT severity, evidence_json FROM research_alerts").fetchone()
    evidence = json.loads(alert["evidence_json"])
    assert alert["severity"] == "high" and evidence["change"] == "version_tag_moved"
    assert "BEH_ACTIONS_RUNNER_MEMORY" in evidence["scan"]["rules_matched"]
    assert watch.run(db_path=db_path, fetcher=fetcher, repos=["acme/changed-files"])["changes"] == 0


def test_no_token_disables_the_watch(monkeypatch):
    monkeypatch.delenv("SECOPSAI_GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert watch.run()["enabled"] is False


def test_watchlist_is_valid():
    names = watch.watchlist()
    assert "tj-actions/changed-files" in names and "actions/checkout" in names and len(names) == len(set(names))


def test_watch_is_rate_limited(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_GITHUB_TOKEN", "t")
    monkeypatch.setattr(watch, "watchlist", lambda: ["acme/a"])
    db_path = str(tmp_path / "soc.db")
    soc_store.init_db(db_path)
    fetcher = SafeFetcher(fetch=lambda url, _max: (200, {"content-type": "application/json"}, b"[]"))
    assert watch.run(db_path=db_path, fetcher=fetcher)["repos"] == 1
    assert "skipped" in watch.run(db_path=db_path, fetcher=fetcher)
