from datetime import datetime, timedelta, timezone

from secopsai import stream_scan as ss

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)


def _iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class Feeds:
    def __init__(self):
        self.npm_docs = {
            "left-pad": {"time": {"created": "x", "modified": "x", "1.0.0": _iso(NOW - timedelta(days=9)),
                                  "1.1.0": _iso(NOW - timedelta(minutes=3))}, "versions": {"1.0.0": {}, "1.1.0": {}}},
            "@scope/thing": {"time": {"2.0.0": _iso(NOW - timedelta(minutes=2))}, "versions": {"2.0.0": {}}},
        }
        self.changes = [{"seq": 11, "id": "left-pad"}, {"seq": 12, "id": "@scope/thing"}, {"seq": 13, "id": "gone", "deleted": True},
                        {"seq": 14, "id": "left-pad"}]
        self.pypi = [["requests", "3.0.0", int((NOW - timedelta(minutes=4)).timestamp()), "new release", 501],
                     ["requests", "3.0.0", int((NOW - timedelta(minutes=4)).timestamp()), "add py3 file x.whl", 502]]

    def fetch_json(self, url):
        if url == "https://replicate.npmjs.com/":
            return {"update_seq": 10}
        if url.startswith(ss.NPM_CHANGES):
            return {"results": self.changes, "last_seq": 14}
        name = url[len(ss.NPM_REGISTRY):].replace("%2F", "/")
        return self.npm_docs[name]


def _run(state, stats, feeds, scan, escalate=lambda target, result: {"alerted": True}, budget=900, clock=None):
    return ss.run(state=state, stats=stats, fetch_json=feeds.fetch_json, pypi_changelog=lambda serial: feeds.pypi,
                  pypi_last_serial=lambda: 500, scan=scan, escalate=escalate, budget_seconds=budget, workers=2,
                  now=lambda: NOW, clock=clock or (lambda: 0.0))


def test_first_run_only_sets_the_cursors():
    state, stats, scanned = {}, {}, []
    summary = _run(state, stats, Feeds(), lambda target: scanned.append(target) or {"status": "clean"})
    assert state["npm_seq"] == "10" and state["pypi_serial"] == 500 and scanned == []
    assert summary["discovered"] == {}


def test_every_new_release_is_prescanned_once_and_hits_are_escalated():
    state = {"npm_seq": "10", "pypi_serial": 500, "npm_since": _iso(NOW - timedelta(minutes=30))}
    stats, escalated = {}, []

    def scan(target):
        return {"status": "hit", "level": "warning"} if target["package"] == "@scope/thing" else {"status": "clean", "level": "none"}

    summary = _run(state, stats, Feeds(), scan, escalate=lambda target, result: escalated.append(target["package"]) or {"alerted": True})
    assert summary["discovered"] == {"npm": 2, "pypi": 1}, "the old left-pad version and the deleted package are not new"
    assert summary["scanned"] == 3 and summary["hits"] == 1 and summary["alerts"] == 1 and escalated == ["@scope/thing"]
    assert state["npm_seq"] == "14" and state["pypi_serial"] == 502 and state["backlog"] == []
    again = _run(state, stats, Feeds(), scan)
    assert again["discovered"] == {} and again["scanned"] == 0, "a release is never scanned twice"
    coverage = ss.coverage_from_stats(stats, now=NOW + timedelta(hours=2, minutes=5))
    assert coverage["ecosystems"]["npm"]["coverage"] == 1.0 and coverage["ecosystems"]["pypi"]["published"] == 1
    assert coverage["ecosystems"]["npm"]["p50_minutes"] in (2.0, 3.0) and coverage["all"]["scanned"] == 3


def test_releases_beyond_the_budget_wait_in_the_backlog_and_count_as_unscanned():
    state = {"npm_seq": "10", "pypi_serial": 500, "npm_since": _iso(NOW - timedelta(minutes=30))}
    stats = {}
    ticks = iter([0.0] + [1000.0] * 50)  # the budget is spent after the first check
    summary = _run(state, stats, Feeds(), lambda target: {"status": "clean"}, budget=10, clock=lambda: next(ticks))
    assert summary["scanned"] == 0 and len(state["backlog"]) == 3
    coverage = ss.coverage_from_stats(stats, now=NOW + timedelta(hours=2, minutes=5))
    assert coverage["all"]["published"] == 3 and coverage["all"]["coverage"] == 0.0, "unscanned releases are not hidden"
    feeds = Feeds()
    feeds.changes, feeds.pypi = [], []
    later = _run(state, stats, feeds, lambda target: {"status": "clean"})
    assert later["scanned"] == 3 and state["backlog"] == []


def test_scan_errors_are_counted_and_do_not_stop_the_stream():
    state = {"npm_seq": "10", "pypi_serial": 500, "npm_since": _iso(NOW - timedelta(minutes=30))}
    stats = {}

    def scan(target):
        if target["ecosystem"] == "pypi":
            raise RuntimeError("tarball 404")
        return {"status": "clean"}

    summary = _run(state, stats, Feeds(), scan)
    assert summary["scanned"] == 2 and summary["errors"] == 1
    coverage = ss.coverage_from_stats(stats, now=NOW + timedelta(hours=2, minutes=5))
    assert coverage["ecosystems"]["pypi"]["coverage"] == 0.0 and coverage["ecosystems"]["pypi"]["errors"] == 1


def test_unsettled_hours_are_left_out_of_coverage():
    stats = {}
    ss.record_published(stats, [{"ecosystem": "npm", "published_at": _iso(NOW - timedelta(minutes=5))}])
    assert ss.coverage_from_stats(stats, now=NOW)["all"]["published"] == 0
    ss.prune_stats(stats, NOW + timedelta(hours=60))
    assert stats["hours"] == {}


def test_a_takeover_signal_escalates_even_a_clean_prescan():
    feeds = Feeds()
    trusted = {"name": "GitHub Actions", "trustedPublisher": {"id": "github"}}
    feeds.npm_docs["left-pad"]["versions"] = {"1.0.0": {"_npmUser": trusted, "dist": {"attestations": {"url": "x"}}},
                                              "1.1.0": {"_npmUser": {"name": "mallory"}, "dist": {}, "scripts": {"postinstall": "node x"}}}
    state = {"npm_seq": "10", "pypi_serial": 500, "npm_since": _iso(NOW - timedelta(minutes=30))}
    stats, escalated = {}, []
    summary = _run(state, stats, feeds, lambda target: {"status": "clean", "level": "none"},
                   escalate=lambda target, result: escalated.append(target["package"]) or {"alerted": True})
    assert escalated == ["left-pad"] and summary["takeover_flags"] == 1
    assert stats["takeover_flagged"][0]["package"] == "left-pad" and "trusted_publishing_lost" in stats["takeover_flagged"][0]["signals"]


def test_pypi_owner_additions_are_remembered_for_later_releases():
    feeds = Feeds()
    stamp = int((NOW - timedelta(days=1)).timestamp())
    feeds.pypi = [["requests", None, stamp, "add Owner mallory", 499]] + feeds.pypi
    state = {"npm_seq": "10", "pypi_serial": 500, "npm_since": _iso(NOW - timedelta(minutes=30))}
    seen = []
    _run(state, {}, feeds, lambda target: seen.append(target) or {"status": "clean"})
    assert "requests" in state["pypi_roles"]
    assert next(target for target in seen if target["ecosystem"] == "pypi")["role_added_at"].startswith((NOW - timedelta(days=1)).strftime("%Y-%m-%d"))


def _mcp_page(published):
    meta = lambda when: {"io.modelcontextprotocol.registry/official": {"publishedAt": _iso(when)}}  # noqa: E731
    return {"servers": [
        {"server": {"name": "io.github.x/files", "version": "1.2.0",
                    "packages": [{"registryType": "npm", "identifier": "@x/files-mcp", "version": "1.2.0"}]}, "_meta": meta(published)},
        {"server": {"name": "io.github.x/py", "version": "0.4.0",
                    "packages": [{"registryType": "pypi", "identifier": "x-mcp"}, {"registryType": "oci", "identifier": "ghcr.io/x"}]},
         "_meta": meta(published)},
        {"server": {"name": "ad.example/remote", "version": "1.0.0", "remotes": [{"type": "streamable-http", "url": "https://x"}]},
         "_meta": meta(published)},
        {"server": {"name": "io.github.x/old", "version": "0.1.0", "packages": [{"registryType": "npm", "identifier": "old"}]},
         "_meta": meta(published - timedelta(days=3))},
    ], "metadata": {}}


def test_mcp_servers_are_scanned_through_their_packages_and_remote_ones_counted():
    page = _mcp_page(NOW - timedelta(minutes=5))
    targets, unscannable, cursor = ss.mcp_new_servers(lambda url: page, _iso(NOW - timedelta(hours=1)))
    assert [t["package"] for t in targets] == ["io.github.x/files", "io.github.x/py"]
    assert targets[1]["packages"] == [{"ecosystem": "pypi", "package": "x-mcp", "version": "0.4.0"}], "a package without a version runs the server's"
    assert [(t["package"], t["kinds"]) for t in unscannable] == [("ad.example/remote", ["remote"])]
    assert cursor == _iso(NOW - timedelta(minutes=5)).replace(".000Z", ".000000Z")

    verdicts = {"@x/files-mcp": {"status": "clean", "level": "none"}, "x-mcp": {"status": "hit", "level": "warning"}}
    worst = ss.scan_mcp(lambda package: verdicts[package["package"]], {"packages": targets[0]["packages"] + targets[1]["packages"]})
    assert worst["status"] == "hit" and worst["package"]["package"] == "x-mcp"


def test_mcp_releases_enter_coverage_and_escalate_as_their_package():
    feeds = Feeds()
    page = _mcp_page(NOW - timedelta(minutes=5))
    base = feeds.fetch_json
    feeds.fetch_json = lambda url: page if url.startswith(ss.MCP_REGISTRY) else base(url)
    state = {"npm_seq": "10", "pypi_serial": 500, "mcp_since": _iso(NOW - timedelta(hours=1))}
    stats, escalated = {}, []

    def scan(target):
        if target["ecosystem"] == "mcp-registry":
            return ss.scan_mcp(lambda package: {"status": "hit", "level": "warning"} if package["package"] == "x-mcp"
                               else {"status": "clean", "level": "none"}, target)
        return {"status": "clean", "level": "none"}

    ss.run(state=state, stats=stats, fetch_json=feeds.fetch_json, pypi_changelog=lambda serial: [], pypi_last_serial=lambda: 500,
           scan=scan, escalate=lambda target, result: escalated.append(target) or {"alerted": False},
           workers=2, now=lambda: NOW, clock=lambda: 0.0, mcp=True)
    assert [(t["ecosystem"], t["package"], t["mcp_server"]) for t in escalated] == [("pypi", "x-mcp", "io.github.x/py")]
    bucket = stats["hours"][(NOW - timedelta(minutes=5)).strftime("%Y-%m-%dT%H")]["mcp-registry"]
    assert (bucket["published"], bucket["scanned"], bucket["unscannable"]) == (2, 2, 1)
    later = NOW + timedelta(hours=3)
    assert ss.coverage_from_stats(stats, now=later)["ecosystems"]["mcp-registry"]["unscannable"] == 1


def test_split_jobs_scan_every_shard_and_a_failed_shard_returns_to_the_backlog():
    state = {"npm_seq": "10", "pypi_serial": 500, "backlog": [
        {"ecosystem": "npm", "package": f"old{i}", "version": "1.0.0", "published_at": _iso(NOW - timedelta(hours=2, minutes=i))}
        for i in range(5)]}
    stats = {}
    feeds = Feeds()
    queue, summary = ss.discover(state=state, stats=stats, fetch_json=feeds.fetch_json, pypi_changelog=lambda serial: feeds.pypi,
                                 pypi_last_serial=lambda: 500, workers=2, now=lambda: NOW)
    assert len(queue) == 8 and state["backlog"] == queue, "the plan saves the whole queue as the backlog"
    assert [t["published_at"] for t in queue] == sorted(t["published_at"] for t in queue)

    shards = ss.shard_queue(queue, 3)
    assert sorted(ss.key(t) for shard in shards for t in shard) == sorted(ss.key(t) for t in queue)
    assert all(shard[0]["published_at"] <= queue[3]["published_at"] for shard in shards), "every shard starts with old releases"

    results, remaining = [], []
    for index, shard in enumerate(shards):
        if index == 1:  # this scan job failed
            remaining += shard
            continue
        done, left = ss.scan_queue(shard, lambda target: {"status": "clean", "level": "none"}, workers=2, now=lambda: NOW,
                                   clock=lambda: 0.0)
        results += done
        remaining += left
    ss.apply_results(stats, results, lambda target, result: {"alerted": False}, summary)
    ss.finish(state, stats, remaining, summary, now=lambda: NOW)
    assert summary["scanned"] == len(queue) - len(shards[1])
    assert sorted(ss.key(t) for t in state["backlog"]) == sorted(ss.key(t) for t in shards[1])
    assert summary["backlog_after"] == len(shards[1])
    assert sum(bucket["npm"]["scanned"] + bucket.get("pypi", {}).get("scanned", 0) for bucket in stats["hours"].values()) == summary["scanned"]
