from __future__ import annotations

from pathlib import Path

import pytest

from scripts.sync_research_operation_projection import sync_final_projection


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


def test_workflow_syncs_final_snapshot_after_diagnostics_and_only_after_worker_success():
    workflow = (Path(__file__).parents[1] / ".github/workflows/research-worker.yml").read_text()
    sync_step = workflow.index("- name: Publish final hosted operation projection")
    diagnostics = workflow.index("- name: Preserve delivery verification diagnostics")
    assert sync_step > diagnostics
    assert "id: worker" in workflow
    assert "always() && steps.worker.outcome == 'success'" in workflow[sync_step:]
    assert "python -m scripts.sync_research_operation_projection" in workflow[sync_step:]
