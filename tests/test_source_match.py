"""Release vs source repository comparison (secopsai/source_match.py)."""
from __future__ import annotations

import pytest

from secopsai import source_match
from secopsai.research_intake import RegistryHTTPError

RAW = "https://raw.githubusercontent.com/o/r/"


class _Raw:
    """raw.githubusercontent.com with fixed files; everything else is 404."""

    def __init__(self, files):
        self.files, self.urls = files, []

    def get(self, url, *, allowed_hosts, max_bytes, **_kwargs):
        assert allowed_hosts == ("raw.githubusercontent.com",)
        self.urls.append(url)
        if url not in self.files:
            raise RegistryHTTPError(404)
        return url, {}, self.files[url]


META = {"info": {"project_urls": {"Homepage": "https://example.test", "Source": "https://github.com/o/r"}}}
PTH, BOOT = b"import p._boot\n", b"PATCH = True\n"


def _scan(extra=()):
    members = [("p-1.0.tar.gz/p-1.0/pyproject.toml", b"[project]\n"), ("p-1.0-py3-none-any.whl/p.pth", PTH),
               ("p-1.0-py3-none-any.whl/p/_boot.py", BOOT), *extra]
    install = [{"path": path} for path, _ in members[1:]]
    return {"install_files": install, "root_manifests": ["p-1.0.tar.gz/p-1.0/pyproject.toml"],
            "file_hashes": {path: source_match.content_hash(data) for path, data in members[1:]}}


def test_a_release_identical_to_its_tag_matches():
    fetcher = _Raw({RAW + "v1.0/pyproject.toml": b"x", RAW + "v1.0/src/p.pth": PTH, RAW + "v1.0/src/p/_boot.py": BOOT.replace(b"\n", b"\r\n")})
    result = source_match.compare(fetcher, "pypi", "p", "1.0", META, _scan())
    assert result["result"] == "matches" and result["tag"] == "v1.0" and result["repository"] == "o/r"
    assert {item["outcome"] for item in result["files"]} == {"same"}


def test_a_planted_start_up_hook_differs():
    fetcher = _Raw({RAW + "v1.0/pyproject.toml": b"x", RAW + "v1.0/src/p.pth": PTH, RAW + "v1.0/src/p/_boot.py": BOOT})
    planted = [("p-1.0-py3-none-any.whl/zz_diag.pth", b"import zz_diag\n"), ("p-1.0-py3-none-any.whl/zz_diag.py", b"import os\n")]
    result = source_match.compare(fetcher, "pypi", "p", "1.0", META, _scan(planted))
    assert result["result"] == "differs"
    assert {item["path"].rsplit("/", 1)[-1]: item["outcome"] for item in result["files"]}["zz_diag.pth"] == "missing"


def test_a_changed_start_up_module_differs():
    fetcher = _Raw({RAW + "v1.0/pyproject.toml": b"x", RAW + "v1.0/src/p.pth": PTH, RAW + "v1.0/src/p/_boot.py": b"PATCH = False\n"})
    assert source_match.compare(fetcher, "pypi", "p", "1.0", META, _scan())["result"] == "differs"


def test_a_pth_written_by_the_build_is_not_planted():
    # setuptools: setup.py builds 'distutils-precedence' + '.pth'.
    scan = _scan()
    fetcher = _Raw({RAW + "v1.0/pyproject.toml": b"x", RAW + "v1.0/src/p/_boot.py": BOOT,
                    RAW + "v1.0/setup.py": b"_pth_name = 'p'\n# installs a .pth file\n"})
    result = source_match.compare(fetcher, "pypi", "p", "1.0", META, scan)
    assert result["result"] == "matches"
    assert [item["outcome"] for item in result["files"]][0] == "built"
    # A build that never writes .pth files does not excuse one named after the package.
    fetcher = _Raw({RAW + "v1.0/pyproject.toml": b"[project]\nname = 'p'\n", RAW + "v1.0/src/p/_boot.py": BOOT})
    assert source_match.compare(fetcher, "pypi", "p", "1.0", META, scan)["result"] == "differs"


@pytest.mark.parametrize("meta,files,reason", [
    ({"info": {"project_urls": {"Homepage": "https://example.test"}}}, {}, "no GitHub repository"),
    (META, {}, "no tag for 1.0"),
])
def test_no_repository_or_no_tag_is_unknown(meta, files, reason):
    result = source_match.compare(_Raw(files), "pypi", "p", "1.0", meta, _scan())
    assert result["result"] == "unknown" and reason in result["reason"]


def test_monorepo_links_and_tags():
    meta = {"info": {"project_urls": {"source": "https://github.com/o/r/tree/main/python Import-Name: x"}}}
    assert source_match.repository_location("pypi", meta) == ("o", "r", "python")
    assert "python-1.0" in source_match.candidate_tags("p", "1.0", "python")
    fetcher = _Raw({RAW + "python-1.0/python/pyproject.toml": b"x", RAW + "python-1.0/python/src/p.pth": PTH,
                    RAW + "python-1.0/python/src/p/_boot.py": BOOT})
    result = source_match.compare(fetcher, "pypi", "p", "1.0", meta, _scan())
    assert result["result"] == "matches" and result["tag"] == "python-1.0"
    npm = {"repository": {"type": "git", "url": "git+https://github.com/o/mono.git", "directory": "packages/x"}}
    assert source_match.repository_location("npm", npm) == ("o", "mono", "packages/x")
    assert source_match.repository("npm", {"repository": "github:o/r"}) == ("o", "r")
    assert source_match.repository_location("npm", {"repository": {"url": "https://github.com/o/r", "directory": "../../etc"}}) == ("o", "r", "")


def test_only_raw_github_is_read_and_built_files_may_be_absent():
    built = [("p-1.0.tar.gz/p-1.0/dist/index.js", b"compiled")]
    scan = _scan()
    scan["file_hashes"].update({path: source_match.content_hash(data) for path, data in built})
    fetcher = _Raw({RAW + "v1.0/pyproject.toml": b"x", RAW + "v1.0/src/p.pth": PTH, RAW + "v1.0/src/p/_boot.py": BOOT})
    result = source_match.compare(fetcher, "pypi", "p", "1.0", META, scan)
    assert result["result"] == "unknown"  # a flagged built file is absent: no warning, no match
    assert all(url.startswith("https://raw.githubusercontent.com/") for url in fetcher.urls)
