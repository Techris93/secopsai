from __future__ import annotations

import json

import soc_store
from secopsai.core_edge_client import CoreEdgeClient, CoreEdgeSettings, _compact_ontology_snapshot, _ontology_idempotency_key


class _Response:
    content = b'{}'
    status_code = 200
    ok = True

    def json(self):
        return {"status": "accepted"}


class _Session:
    def __init__(self):
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        return _Response()


def _settings() -> CoreEdgeSettings:
    return CoreEdgeSettings(
        url="https://core.example.test",
        token="bridge-token-with-at-least-thirty-two-characters",
        worker_id="runner-test",
    )


def test_ontology_snapshot_compaction_preserves_valid_arrays_under_request_limit():
    snapshot = {
        "schema_version": "secopsai.ontology.v1",
        "source_instance": "runner-test",
        "entities": [
            {"entity_id": f"pkg:pypi:pkg-{index}", "entity_type": "package", "namespace": "pypi", "canonical_key": f"pkg-{index}", "properties": {"summary": "x" * 4000}}
            for index in range(100)
        ],
        "relationships": [],
        "events": [],
        "evidence_refs": [],
    }
    compacted = _compact_ontology_snapshot(snapshot)
    encoded = json.dumps(compacted, sort_keys=True, separators=(",", ":")).encode()
    assert len(encoded) < 64 * 1024
    assert compacted["entities"]
    assert compacted["snapshot_truncated"] is True


def test_sync_ontology_sends_compacted_payload_and_clears_error():
    session = _Session()
    client = CoreEdgeClient(_settings(), session=session)
    result = client.sync_ontology({
        "entities": [{"entity_id": "pkg:pypi:example", "entity_type": "package", "namespace": "pypi", "canonical_key": "example", "properties": {"x": "y"}}],
        "relationships": [],
        "events": [],
        "evidence_refs": [],
    })
    assert result["status"] == "accepted"
    payload = session.calls[0][2]["json"]
    assert payload["source_instance"] == "runner-test"
    assert payload["entities"][0]["entity_id"] == "pkg:pypi:example"
    assert len(session.calls[0][2]["headers"]["Idempotency-Key"]) == 64
    assert payload["idempotency_key"] == session.calls[0][2]["headers"]["Idempotency-Key"]
    assert client.last_error == ""


def test_snapshot_envelope_timestamps_do_not_change_idempotency_key():
    base = {"schema_version": "secopsai.ontology.v1", "entities": [], "relationships": [], "events": [], "evidence_refs": []}
    assert _ontology_idempotency_key({**base, "exported_at": "2026-09-12T00:00:00Z"}) == _ontology_idempotency_key({**base, "exported_at": "2026-09-12T00:01:00Z"})


def test_sync_ontology_is_failure_tolerant():
    class FailingSession:
        def request(self, *args, **kwargs):
            raise OSError("network offline")

    client = CoreEdgeClient(_settings(), session=FailingSession())
    result = client.sync_ontology({"entities": [], "relationships": [], "events": [], "evidence_refs": []})
    assert result["status"] == "degraded"
    assert "network offline" in result["error"]


def test_ontology_outbox_retries_and_removes_acknowledged_snapshot(tmp_path):
    db_path = str(tmp_path / "outbox.db")
    session = _Session()
    client = CoreEdgeClient(_settings(), session=session)
    queued = client.enqueue_ontology_snapshot({"entities": [], "relationships": [], "events": [], "evidence_refs": []}, db_path=db_path, error="offline")
    assert queued["status"] == "queued"
    with soc_store.read_connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ontology_sync_outbox").fetchone()[0] == 1
    flushed = client.flush_ontology_outbox(db_path=db_path)
    assert flushed["flushed"] == 1
    with soc_store.read_connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ontology_sync_outbox").fetchone()[0] == 0
