import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATCHED_PYTHON = "python:3.13-alpine@sha256:2d9aefe2fef018a7eb2c13064c89c71929800fd2e5dccdbf52ea5da5bb8d929a"


def test_container_uses_upstream_patched_python_without_stdlib_overrides():
    # CPython 3.13.16 contains the tarfile and html.parser fixes that were
    # previously backported by hand, so the image ships the stock stdlib.
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/test-and-build.yml").read_text(encoding="utf-8")
    assert f"ARG PYTHON_IMAGE={PATCHED_PYTHON}" in dockerfile
    assert f"SECOPSAI_BASE_IMAGE: {PATCHED_PYTHON}" in workflow
    assert "/usr/local/lib/python3.13/tarfile.py" not in dockerfile
    assert "container/stdlib" not in dockerfile
    assert "sys.version_info >= (3, 13, 16)" in dockerfile
    assert not (ROOT / "container/stdlib").exists()
    assert not re.search(r"vex: .*python-3\.13\.14", workflow)


def test_grype_image_gate_blocks_fixed_high_findings_only(tmp_path):
    from scripts.enforce_grype_image_gate import collect_blocking_findings, has_available_fix

    unfixed = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2026-14456",
                    "severity": "High",
                    "fix": {"versions": [], "state": "unknown"},
                },
                "artifact": {"name": "libssl3", "version": "3.5.7-r0", "locations": []},
            },
            {
                "vulnerability": {
                    "id": "CVE-2026-14456",
                    "severity": "High",
                    "fix": {"versions": [], "state": "unknown"},
                },
                "artifact": {"name": "libcrypto3", "version": "3.5.7-r0", "locations": []},
            },
        ]
    }
    assert collect_blocking_findings(unfixed) == []
    assert has_available_fix(unfixed["matches"][0]["vulnerability"]) is False

    fixed = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2099-0001",
                    "severity": "High",
                    "fix": {"versions": ["3.5.8-r0"], "state": "fixed"},
                },
                "artifact": {"name": "libssl3", "version": "3.5.7-r0", "locations": ["/lib/apk/db/installed"]},
            }
        ]
    }
    failures = collect_blocking_findings(fixed)
    assert failures == [
        "CVE-2099-0001 libssl3@3.5.7-r0 path=['/lib/apk/db/installed']"
    ]
