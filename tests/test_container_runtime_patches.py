import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from scripts.validate_container_vex import validate


ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_cpython_backports_match_recorded_upstream_revision():
    manifest = json.loads((ROOT / "container/stdlib/3.13/PATCHES.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "secopsai.cpython-runtime-patches.v1"
    assert manifest["base_runtime"] == "CPython 3.13.14"
    assert manifest["source_revision"] == "7933f4bf7131aa4140750f9404f5de0aa2969ced"

    paths = {
        "Lib/tarfile.py": ROOT / "container/stdlib/3.13/tarfile.py",
        "Lib/html/parser.py": ROOT / "container/stdlib/3.13/html/parser.py",
    }
    for record in manifest["files"]:
        assert _sha256(paths[record["path"]]) == record["sha256"]

    tarfile_source = paths["Lib/tarfile.py"].read_text(encoding="utf-8")
    parser_source = paths["Lib/html/parser.py"].read_text(encoding="utf-8")
    assert "if not data:\n                    break" in tarfile_source
    assert "filter_function(\n                    unfiltered.replace(name=tarinfo.name, deep=False)" in tarfile_source
    assert "self._parse_threshold = len(self.rawdata)" in parser_source


def test_openvex_covers_only_verified_python_backports():
    vex = json.loads((ROOT / ".github/vex/python-3.13.14-backports.openvex.json").read_text(encoding="utf-8"))
    assert vex["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert {statement["vulnerability"]["name"] for statement in vex["statements"]} == {
        "CVE-2026-11940",
        "CVE-2026-11972",
        "CVE-2026-15308",
    }
    for statement in vex["statements"]:
        assert statement["status"] == "fixed"
        assert statement["products"] == [{"@id": "pkg:generic/python@3.13.14"}]
        assert "upstream security-fixed revision" in statement["impact_statement"]


def test_container_verifies_backport_hashes_and_grype_consumes_vex():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/test-and-build.yml").read_text(encoding="utf-8")
    assert "container/stdlib/3.13/tarfile.py" in dockerfile
    assert "container/stdlib/3.13/html/parser.py" in dockerfile
    assert "sha256sum -c -" in dockerfile
    assert "vex: .github/vex/python-3.13.14-backports.openvex.json" in workflow
    assert "Validate evidence-backed container VEX" in workflow


def test_vex_policy_is_time_limited_and_matches_patch_manifest():
    policy = ROOT / ".github/vex/python-3.13.14-backports.policy.json"
    payload = validate(ROOT, policy, now=datetime(2026, 7, 30, tzinfo=timezone.utc))
    assert payload["status"] == "valid"
    assert payload["review_after"] == "2026-10-30T00:00:00Z"
    assert payload["vulnerabilities"] == ["CVE-2026-11940", "CVE-2026-11972", "CVE-2026-15308"]
