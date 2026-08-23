import hashlib
import io
import json
import tarfile

from secopsai.research_intake import ADAPTERS, SafeFetcher
from secopsai.source_first_research import _validated_iocs, investigate, normalize_ecosystem


def _archive(source: str) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        data = source.encode()
        member = tarfile.TarInfo("build.rs")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    return output.getvalue()


def _fixture_fetcher(package: str, version: str, artifact: bytes) -> SafeFetcher:
    digest = hashlib.sha256(artifact).hexdigest()
    metadata = {
        "crate": {"id": package, "repository": f"https://github.com/fixture/{package}"},
        "versions": [{"num": version, "created_at": "2026-08-20T00:00:00Z", "checksum": digest}],
    }

    def fetch(url: str, _max_bytes: int):
        if "/api/v1/crates/" in url:
            return 200, {"content-type": "application/json"}, json.dumps(metadata).encode()
        return 200, {"content-type": "application/octet-stream"}, artifact

    return SafeFetcher(fetch=fetch)


def test_universal_aliases_normalize_without_creating_parallel_workflows():
    assert normalize_ecosystem("crates.io") == "crates"
    assert normalize_ecosystem("composer") == "packagist"
    assert normalize_ecosystem("vscode") == "open-vsx"


def test_crates_metadata_defaults_to_newest_stable_row():
    artifact = _archive("fn main() {}")
    fetcher = _fixture_fetcher("fixture", "1.0.1", artifact)
    result = investigate(ecosystem="crates", package="fixture", dry_run=True, fetcher=fetcher)
    assert result["metadata"]["version"] == "1.0.1"


def test_public_ip_iocs_with_ports_are_retained_and_source_domains_rejected():
    accepted, rejected = _validated_iocs({"iocs": {"ips": ["23.254.165.112:9089"], "domains": ["crates.io"]}})
    assert {item["value"] for item in accepted} == {"23.254.165.112:9089"}
    assert any(item["value"] == "crates.io" for item in rejected)


def test_research_type_routes_are_explicit(tmp_path):
    artifact_path = tmp_path / "fixture.tar.gz"
    artifact_path.write_bytes(_archive("print('fixture')"))
    common = {
        "artifact": str(artifact_path),
        "db_path": str(tmp_path / "soc.db"),
        "artifact_db_path": str(tmp_path / "artifact.db"),
    }
    assert investigate(ecosystem="github", package="owner/repo", research_type="github_token_breach", **common)["route"] == "github_security_review"
    assert investigate(ecosystem="npm", package="fixture", research_type="vulnerability_advisory", **common)["route"] == "vulnerability_tracking"


def test_repository_and_model_adapters_are_metadata_safe():
    def fetch(url: str, _max_bytes: int):
        if "api.github.com" in url:
            return 200, {"content-type": "application/json"}, json.dumps({"html_url": "https://github.com/owner/repo", "default_branch": "main", "owner": {"login": "owner"}}).encode()
        return 200, {"content-type": "application/json"}, json.dumps({"sha": "abc", "author": "owner", "lastModified": "2026-08-20T00:00:00Z"}).encode()

    github = ADAPTERS["github"].resolve("owner/repo", "main", SafeFetcher(fetch=fetch))
    huggingface = ADAPTERS["huggingface"].resolve("owner/model", "main", SafeFetcher(fetch=fetch))
    assert github.artifact_url.startswith("https://api.github.com/repos/owner/repo/tarball/")
    assert huggingface.artifact_url == ""


def test_universal_research_preserves_static_only_safety_and_case(tmp_path, monkeypatch):
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    artifact = _archive('use std::process::Command; Command::new("curl");')
    result = investigate(
        ecosystem="crates.io",
        package="proc-macro1",
        version="1.0.107",
        research_type="package_compromise",
        db_path=str(tmp_path / "soc.db"),
        artifact_db_path=str(tmp_path / "artifact.db"),
        fetcher=_fixture_fetcher("proc-macro1", "1.0.107", artifact),
    )
    assert result["ok"] is True
    assert result["research"]["ecosystem"] == "crates"
    assert result["scan"]["status"] == "flagged"
    assert result["safety"]["execution_performed"] is False
    assert result["case_id"].startswith("RSC-")


def test_metadata_only_sources_are_explicit_instead_of_silent_fallback(tmp_path):
    result = investigate(
        ecosystem="container",
        package="registry.example/app",
        version="sha256:abc",
        dry_run=True,
        db_path=str(tmp_path / "soc.db"),
    )
    assert result["ok"] is True
    assert result["metadata"]["status"] == "metadata_only"
    assert result["safety"]["execution_performed"] is False


def test_local_lockfile_usage_is_reported_without_execution(tmp_path):
    lockfile = tmp_path / "Cargo.lock"
    lockfile.write_text('name = "proc-macro1"\nversion = "1.0.107"\n', encoding="utf-8")
    artifact = _archive("fn main() { println!(\"fixture\"); }")
    artifact_path = tmp_path / "fixture.crate"
    artifact_path.write_bytes(artifact)
    result = investigate(
        ecosystem="crates",
        package="proc-macro1",
        version="1.0.107",
        artifact=str(artifact_path),
        search_root=str(tmp_path),
        lockfile=str(lockfile),
        db_path=str(tmp_path / "soc.db"),
        artifact_db_path=str(tmp_path / "artifact.db"),
    )
    # The fixture is static-only; the package reference is still surfaced.
    assert result["local_usage"]["status"] == "confirmed"
    assert result["local_usage"]["matches"][0]["version_present"] is True
    assert result["safety"]["execution_performed"] is False
