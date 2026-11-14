import json

from secopsai import blocklist


def _record(ident, ecosystem, name, versions=(), events=None):
    affected = {"package": {"ecosystem": ecosystem, "name": name}, "versions": list(versions)}
    if events is not None:
        affected["ranges"] = [{"type": "SEMVER", "events": events}]
    return {"id": ident, "affected": [affected]}


def test_versions_merge_and_all_versions_ranges():
    blocks = {}
    blocklist.add_record(blocks, _record("MAL-1", "npm", "Left-Pad", ["1.0.1"]))
    blocklist.add_record(blocks, _record("MAL-2", "npm", "left-pad", ["1.0.2"]))
    blocklist.add_record(blocks, _record("MAL-3", "PyPI", "Evil_Pkg", events=[{"introduced": "0"}]))
    blocklist.add_record(blocks, _record("MAL-4", "PyPI", "fixed-pkg", ["1.0"], events=[{"introduced": "0"}, {"fixed": "1.1"}]))
    blocklist.add_record(blocks, _record("MAL-5", "Maven", "a:b", ["1"]))
    assert blocks["npm"]["left-pad"]["versions"] == ["1.0.1", "1.0.2"]
    assert blocks["npm"]["left-pad"]["ids"] == ["MAL-1", "MAL-2"]
    assert blocks["pypi"]["evil-pkg"]["all"] is True
    assert blocks["pypi"]["fixed-pkg"]["all"] is False
    assert "maven" not in blocks
    assert blocklist.blocked(blocks, "pypi", "evil.pkg", "9.9")
    assert blocklist.blocked(blocks, "npm", "left-pad", "1.0.2")
    assert not blocklist.blocked(blocks, "npm", "left-pad", "1.3.0")


def test_shards_cover_every_key_and_match_the_worker_hash(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps(_record("MAL-1", "npm", "@scope/lib", ["1.0.1"])))
    (tmp_path / "bad.json").write_text("{not json")
    shards = blocklist.shards(blocklist.from_osv([tmp_path]))
    assert len(shards) == 512
    key = "npm/" + blocklist.shard_of("npm", "@scope/lib")
    assert "@scope/lib" in shards[key]
    # Same key as the Worker: sha256 of the normalized name, first byte in hex.
    import hashlib
    assert key.endswith(hashlib.sha256(b"@scope/lib").hexdigest()[:2])
    assert sum(len(entries) for entries in shards.values()) == 1
