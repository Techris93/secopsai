import json

import pytest

from secopsai.research_case_sync import project_case, sync_research_cases
from secopsai.research_cases import add_evidence, create_case, get_case, list_cases


class FakeCore:
    enabled = True

    def __init__(self, fail_after=None):
        self.batches = []
        self.fail_after = fail_after

    def sync_research_cases(self, cases):
        if self.fail_after is not None and len(self.batches) >= self.fail_after:
            raise RuntimeError("core unavailable")
        self.batches.append(cases)
        return {"status": "accepted", "accepted": len(cases), "rejected": []}


def _case(db, title="Synthetic exfil demo"):
    case = create_case(title=title, db_path=db)
    add_evidence(
        case["case_id"], evidence_type="package_artifact", title="Reviewed local artifact",
        locator="local-artifact://" + "a" * 64, sha256="a" * 64, provenance="operator",
        metadata={"api_token": "must-not-leave", "execution_performed": False}, db_path=db,
    )
    add_evidence(case["case_id"], evidence_type="source", title="Advisory", locator="https://example.com/advisory", db_path=db)
    return case


def test_projection_removes_local_locators_secrets_and_metadata(tmp_path):
    db = str(tmp_path / "research.db")
    case = _case(db)
    summary = next(item for item in list_cases(db_path=db) if item["case_id"] == case["case_id"])
    projection = project_case(get_case(case["case_id"], db_path=db), summary)
    encoded = json.dumps(projection)
    assert "local-artifact://" not in encoded
    assert "must-not-leave" not in encoded
    locators = {item["title"]: item["locator"] for item in projection["detail"]["evidence"]}
    assert locators["Reviewed local artifact"] == "local evidence (not published)"
    assert locators["Advisory"] == "https://example.com/advisory"
    assert "metadata" not in projection["detail"]["evidence"][0]
    assert len(json.dumps(projection["detail"])) <= 90_000


def test_sync_is_incremental_and_resumes_after_failure(tmp_path):
    db = str(tmp_path / "research.db")
    for index in range(3):
        _case(db, title=f"Case {index}")
    core = FakeCore()
    first = sync_research_cases(core, db_path=db)
    assert first["accepted"] == 3
    assert sync_research_cases(core, db_path=db)["considered"] == 0

    _case(db, title="Late case")
    failing = FakeCore(fail_after=0)
    with pytest.raises(RuntimeError):
        sync_research_cases(failing, db_path=db)
    retry = sync_research_cases(FakeCore(), db_path=db)
    assert retry["accepted"] == 1


def test_sync_is_disabled_without_core():
    class Disabled:
        enabled = False

    assert sync_research_cases(Disabled()) == {"status": "disabled"}
