from __future__ import annotations

from pathlib import Path

import pytest

from scripts.sync_research_operation_projection import FinalProjectionError, sync_final_projection


class Client:
    enabled = True

    def __init__(self, result=None):
        self.result = result or {"status": "stored"}
        self.projection = None

    def sync_research_operation(self, projection):
        self.projection = projection
        return self.result


def _projection(run_id="12345", attempt=2):
    return {"runtime": {"worker_run_id": run_id, "worker_run_attempt": attempt}}


def _fresh_projection(run_id="12345", attempt=2):
    return {
        **_projection(run_id, attempt),
        "coverage": {
            "health": {"freshness_gaps": []},
            "sources": [{"source_id": "COL-TEST", "name": "test collector", "enabled": True, "fresh": True}],
        },
    }


def test_final_projection_is_durably_stored_for_current_run():
    client = Client()
    result = sync_final_projection(
        client,
        projection_builder=_projection,
        environment={"GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2"},
    )

    assert result == {"status": "stored", "worker_run_id": "12345", "worker_run_attempt": 2}
    assert client.projection == _projection()


@pytest.mark.parametrize(
    ("projection", "environment", "message"),
    [
        (_projection("other"), {"GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2"}, "current worker run"),
        (_projection(), {"GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "3"}, "current worker attempt"),
        (_projection(), {"GITHUB_RUN_ID": "12345"}, "run identity is unavailable"),
    ],
)
def test_final_projection_rejects_missing_or_mismatched_run_identity(projection, environment, message):
    with pytest.raises(RuntimeError, match=message):
        sync_final_projection(Client(), projection_builder=lambda: projection, environment=environment)


def test_final_projection_requires_core_durable_acknowledgement():
    with pytest.raises(RuntimeError, match="durable storage"):
        sync_final_projection(
            Client({"status": "disabled"}),
            projection_builder=_projection,
            environment={"GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2"},
        )


def test_final_projection_fails_closed_on_stale_source_rows_before_sync():
    client = Client()
    projection = _fresh_projection()
    # Catch inconsistent coverage where the summary omits a stale enabled row.
    projection["coverage"]["sources"][0]["fresh"] = False

    with pytest.raises(FinalProjectionError, match="test collector"):
        sync_final_projection(
            client,
            projection_builder=lambda: projection,
            environment={"GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2"},
            require_fresh_sources=True,
        )

    assert client.projection is None


def test_final_projection_requires_source_health_data_when_freshness_is_gated():
    client = Client()
    with pytest.raises(FinalProjectionError, match="no source coverage rows"):
        sync_final_projection(
            client,
            projection_builder=_projection,
            environment={"GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2"},
            require_fresh_sources=True,
        )

    assert client.projection is None


def test_final_projection_rejects_missing_freshness_gap_summary():
    client = Client()
    projection = _fresh_projection()
    del projection["coverage"]["health"]["freshness_gaps"]

    with pytest.raises(FinalProjectionError, match="no freshness-gap result"):
        sync_final_projection(
            client,
            projection_builder=lambda: projection,
            environment={"GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "2"},
            require_fresh_sources=True,
        )

    assert client.projection is None


def test_workflow_publishes_final_snapshot_after_health_check_and_before_artifacts():
    workflow = (Path(__file__).parents[1] / ".github/workflows/research-worker.yml").read_text()
    sync_step = workflow.index("- name: Publish final hosted operation projection")
    health_check = workflow.index("- name: Verify final checkpoint and hosted delivery health")
    diagnostics = workflow.index("- name: Preserve worker and delivery diagnostics")
    assert sync_step > health_check
    assert sync_step < diagnostics
    assert "id: worker" in workflow
    assert "always() && steps.worker.outcome == 'success'" in workflow[sync_step:]
    assert "python -m scripts.sync_research_operation_projection" in workflow[sync_step:]
    assert 'SECOPSAI_VERIFY_REFRESH_STALE_SOURCES: "1"' in workflow
    assert 'SECOPSAI_VERIFY_FRESHNESS_MARGIN_SECONDS: "300"' in workflow
    assert "reports/research/final-projection.json" in workflow[diagnostics:]
