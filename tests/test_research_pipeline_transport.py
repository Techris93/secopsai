from __future__ import annotations

import json
from contextlib import closing

import soc_store
from secopsai.core_edge_client import CoreEdgeHTTPError
from secopsai.intelligence_jobs import cancel_job, list_jobs
from secopsai.investigation_autopilot import get_run, reconcile_pipeline, recover_due_runs
from secopsai.research_pipeline import get_pipeline, start_investigation_pipeline
from secopsai.research_pipeline_transport import sync_hosted
from tests.test_research_pipeline import _bridge_result, _case, _fetcher


class Core:
    enabled = True

    def __init__(self):
        self.jobs, self.finished, self.canceled, self.sent = {}, {}, [], []

    def queue_assistant_job(self, payload):
        self.sent.append(payload)
        job_id = f"AIJ-{len(self.jobs):016X}"
        self.jobs[job_id] = payload
        return {"job": {"job_id": job_id}}

    def assistant_results(self, job_ids):
        return {"results": [{"job_id": job_id, "status": self.finished[job_id][0], "result": self.finished[job_id][1],
                             "provider": "opencodex_proxy", "model": "opencodex/test"} for job_id in job_ids if job_id in self.finished]}

    def cancel_assistant_jobs(self, job_ids):
        self.canceled += job_ids
        return {"canceled": job_ids}

    def bridge_answers(self):
        for job_id, payload in self.jobs.items():
            self.finished.setdefault(job_id, ("succeeded", _bridge_result(payload["action"])["data"]))


def _pipeline(tmp_path, monkeypatch, *, run_status="awaiting_model"):
    db = str(tmp_path / "research.db")
    monkeypatch.setenv("SECOPSAI_RESEARCH_QUARANTINE", str(tmp_path / "quarantine"))
    case = _case(db)
    pipeline = start_investigation_pipeline(case["case_id"], reference_ecosystem="npm", reference_package="legitimate-pkg",
                                            reference_version="1.0.0", actor="tester", db_path=db, fetcher=_fetcher())
    now = soc_store.utc_now()
    with closing(soc_store.connect(db)) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        values = {"run_id": "IAR-0000000000000001", "finding_id": "RSCF-1", "finding_fingerprint": "f", "status": run_status, "case_id": case["case_id"],
                  "pipeline_id": pipeline["pipeline_id"], "current_stage": "local_codex_bridge", "last_successful_stage": "collect_subject",
                  "evidence_summary_json": "{}", "decision_json": "{}", "created_at": now, "updated_at": now}
        connection.execute(f"INSERT INTO investigation_autopilot_runs ({','.join(values)}) VALUES ({','.join('?' for _ in values)})", tuple(values.values()))
        connection.commit()
    return db, pipeline


def test_jobs_reach_core_without_routing_and_the_answers_finish_the_pipeline(tmp_path, monkeypatch):
    db, pipeline = _pipeline(tmp_path, monkeypatch)
    core = Core()

    outcome = sync_hosted(core, db_path=db)
    assert outcome["delivered"] == 3 and outcome["waiting"] == 3
    for payload in core.sent:
        assert payload["target_id"] == pipeline["case_id"]
        assert payload["inputs"]["assistant_request"]["context"]["case"]["case_id"] == pipeline["case_id"]
        assert "selected_model" not in payload["inputs"], "the bridge applies the operator's routing at claim"
    assert get_pipeline(pipeline["pipeline_id"], db_path=db)["status"] == "awaiting_ai"

    assert sync_hosted(core, db_path=db)["delivered"] == 0, "delivered once"
    core.bridge_answers()
    assert sync_hosted(core, db_path=db)["applied"] == 3
    assert get_pipeline(pipeline["pipeline_id"], db_path=db)["status"] == "awaiting_review"
    assert get_run("IAR-0000000000000001", db_path=db)["status"] == "ready_for_decision", "the slot is free for the next run"
    assert sync_hosted(core, db_path=db) == {"status": "ok", "delivered": 0, "applied": 0, "failed": 0, "canceled": 0, "waiting": 0}


def test_a_job_without_a_live_investigation_spends_no_model_quota(tmp_path, monkeypatch):
    db, _ = _pipeline(tmp_path, monkeypatch, run_status="evidence_gap")
    core = Core()
    assert sync_hosted(core, db_path=db)["delivered"] == 0
    assert core.sent == []


def test_a_failed_or_invalid_answer_fails_the_pipeline_so_it_can_retry(tmp_path, monkeypatch):
    db, pipeline = _pipeline(tmp_path, monkeypatch)
    core = Core()
    sync_hosted(core, db_path=db)
    first, second, third = core.jobs
    core.finished[first] = ("failed", {})
    core.finished[second] = ("succeeded", {"summary": "missing the rest"})
    core.finished[third] = ("succeeded", _bridge_result(core.jobs[third]["action"])["data"])

    assert sync_hosted(core, db_path=db)["failed"] == 2
    assert get_pipeline(pipeline["pipeline_id"], db_path=db)["status"] == "failed"
    reconcile_pipeline(pipeline["pipeline_id"], db_path=db)
    assert get_run("IAR-0000000000000001", db_path=db)["status"] == "failed"


def test_core_refusing_a_job_fails_it_but_an_outage_retries_the_same_request(tmp_path, monkeypatch):
    db, _ = _pipeline(tmp_path, monkeypatch)

    class Down(Core):
        status = 503

        def queue_assistant_job(self, payload):
            self.sent.append(payload)
            raise CoreEdgeHTTPError("unavailable", status=self.status, error_code="unavailable")

    core = Down()
    try:
        sync_hosted(core, db_path=db)
    except CoreEdgeHTTPError:
        pass
    healthy = Core()
    assert sync_hosted(healthy, db_path=db)["delivered"] == 3
    assert json.dumps(core.sent[0], sort_keys=True) == json.dumps(healthy.sent[0], sort_keys=True)


def test_a_canceled_job_is_canceled_at_core_once(tmp_path, monkeypatch):
    db, _ = _pipeline(tmp_path, monkeypatch)
    core = Core()
    sync_hosted(core, db_path=db)
    job = list_jobs(db_path=db)[0]
    cancel_job(job["job_id"], actor="tester", db_path=db)
    assert sync_hosted(core, db_path=db)["canceled"] == 1
    assert len(core.canceled) == 1
    sync_hosted(core, db_path=db)
    assert len(core.canceled) == 1


def test_agent_mode_finishes_the_investigation_without_publishing_anything(tmp_path, monkeypatch):
    db, pipeline = _pipeline(tmp_path, monkeypatch)
    monkeypatch.setenv("SECOPSAI_RESEARCH_AUTONOMY_MODE", "agent_review")
    core = Core()
    sync_hosted(core, db_path=db)
    core.bridge_answers()
    assert sync_hosted(core, db_path=db)["applied"] == 3

    finished = get_pipeline(pipeline["pipeline_id"], db_path=db)
    assert finished["status"] == "succeeded" and finished["summary"]["verdict_recorded"] is True
    assert finished["summary"]["published"] is False and finished["summary"]["disclosure_sent"] is False
    assert finished["summary"]["sandbox_submitted"] is False
    assert get_run("IAR-0000000000000001", db_path=db)["status"] == "escalated", "the fixture's answer is a likely verdict"


def _gap(db, code):
    with closing(soc_store.connect(db)) as connection:
        connection.execute("UPDATE investigation_autopilot_runs SET status='evidence_gap', blocker_code=?, attempt=1, updated_at='2026-01-01T00:00:00Z'", (code,))
        connection.commit()
    return recover_due_runs(db_path=db)["count"]


def test_an_inconclusive_finished_analysis_spends_no_more_model_jobs(tmp_path, monkeypatch):
    db, _ = _pipeline(tmp_path, monkeypatch)
    assert _gap(db, "evidence_incomplete") == 0
    assert _gap(db, "artifact_unavailable") == 1, "a temporary evidence gap is still retried"
