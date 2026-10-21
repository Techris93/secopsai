from scripts.research_operation_watchdog import active_worker_job_started_at
from pathlib import Path


def test_active_worker_uses_job_start_instead_of_queued_workflow_start():
    workflow_run = {
        "run_started_at": "2026-10-21T18:47:57Z",
        "created_at": "2026-10-21T18:47:57Z",
    }
    jobs = {
        "jobs": [
            {"status": "completed", "started_at": "2026-10-21T18:47:57Z"},
            {"status": "in_progress", "started_at": "2026-10-21T19:36:14Z"},
        ]
    }

    assert active_worker_job_started_at(jobs) == "2026-10-21T19:36:14Z"
    assert active_worker_job_started_at({"jobs": [{"status": "queued", "started_at": None}]}) is None
    assert active_worker_job_started_at({"jobs": [{"status": "in_progress", "started_at": "invalid"}]}) is None


def test_watchdog_fetches_active_job_timing_from_github_jobs_api():
    workflow = (Path(__file__).parents[1] / ".github/workflows/research-operation-watchdog.yml").read_text()

    assert "/actions/runs/${active_run_id}/jobs?per_page=100" in workflow
    assert "active_worker_job_started_at" in workflow
    assert '.workflow_runs[0].run_started_at' not in workflow
