from __future__ import annotations

import json

import soc_store
from secopsai.core_edge_client import CoreEdgeClient, CoreEdgeSettings, ONTOLOGY_CHUNK_READ_BUDGET, ONTOLOGY_CHUNK_TARGET_BYTES, _compact_command_result, _compact_ontology_snapshot, _ontology_chunk_read_cost, _ontology_idempotency_key, _ontology_sync_chunks


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


def test_operation_projection_preserves_complete_draft_and_rejects_oversize():
    import pytest
    session = _Session()
    client = CoreEdgeClient(_settings(), session=session)
    projection = {'schema_version': 'secopsai.research.operation.v1', 'coverage': {'sources': []},
                  'editions': [{'draft': {'body_markdown': 'Original first line\n' + 'x' * 10000}}],
                  'assistant_teams': [{'team_id': 'RTM-0123456789ABCDEF', 'status': 'running'}]}
    client.sync_research_operation(projection)
    assert session.calls[0][2]['json'] == projection
    projection['editions'][0]['draft']['body_markdown'] = 'x' * 131073
    with pytest.raises(ValueError, match='bounded request size'):
        client.sync_research_operation(projection)
    assert len(session.calls) == 1


def test_process_revision_prefers_deployment_revision(monkeypatch):
    monkeypatch.setenv("SECOPSAI_BUILD_REVISION", "build-123")
    monkeypatch.setenv("RENDER_GIT_COMMIT", "render-456")
    monkeypatch.setenv("GIT_COMMIT", "git-789")
    client = CoreEdgeClient(_settings())
    assert client.process_revision == "build-123"


def test_process_revision_falls_back_to_process_uuid(monkeypatch):
    for name in ("SECOPSAI_BUILD_REVISION", "RENDER_GIT_COMMIT", "GIT_COMMIT"):
        monkeypatch.delenv(name, raising=False)
    client = CoreEdgeClient(_settings())
    assert len(client.process_revision) == 32
    assert all(character in "0123456789abcdef" for character in client.process_revision)


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
    assert session.calls[0][2]["headers"]["Idempotency-Key"].startswith("ontology-v2:")
    assert len(session.calls[0][2]["headers"]["Idempotency-Key"]) == 76
    assert payload["idempotency_key"] == session.calls[0][2]["headers"]["Idempotency-Key"]
    assert client.last_error == ""


def test_sync_ontology_chunks_oversized_snapshots_without_dropping_records():
    session = _Session()
    client = CoreEdgeClient(_settings(), session=session)
    snapshot = {
        "entities": [
            {"entity_id": f"pkg:pypi:chunk-{index}", "entity_type": "package", "namespace": "pypi", "canonical_key": f"chunk-{index}", "display_name": f"Chunk {index}", "source": "registry", "properties": {"description": "x" * 3500}}
            for index in range(100)
        ],
        "relationships": [],
        "events": [],
        "evidence_refs": [],
    }
    chunks = _ontology_sync_chunks({**snapshot, "source_instance": "runner-test"})
    assert len(chunks) > 1
    assert sum(len(chunk.get("entities", [])) for chunk in chunks) == 100
    result = client.sync_ontology(snapshot)
    assert result["status"] == "accepted"
    assert result["chunks"] == len(chunks)
    assert len(session.calls) == len(chunks)
    assert all(len(json.dumps(call[2]["json"], separators=(",", ":")).encode()) < 64 * 1024 for call in session.calls)


def test_ontology_chunks_leave_wire_room_for_metadata_and_idempotency_key():
    session = _Session()
    client = CoreEdgeClient(_settings(), session=session)
    snapshot = {
        "entities": [
            {
                "entity_id": f"pkg:pypi:wire-{index}",
                "entity_type": "package",
                "namespace": "pypi",
                "canonical_key": f"wire-{index}",
                "properties": {"description": "x" * 3500},
            }
            for index in range(100)
        ],
        "relationships": [],
        "events": [],
        "evidence_refs": [],
    }
    chunks = _ontology_sync_chunks(snapshot)
    assert all(len(json.dumps({**chunk, "idempotency_key": "a" * 64}, separators=(",", ":")).encode()) <= 64 * 1024 for chunk in chunks)
    assert all(len(json.dumps(chunk, separators=(",", ":")).encode()) <= ONTOLOGY_CHUNK_TARGET_BYTES for chunk in chunks)


def test_ontology_chunks_respect_edge_read_budget_with_many_aliases():
    snapshot = {
        "entities": [
            {
                "entity_id": f"pkg:pypi:aliases-{index}",
                "entity_type": "package",
                "namespace": "pypi",
                "canonical_key": f"aliases-{index}",
                "aliases": [f"alias-{index}-{alias}" for alias in range(20)],
            }
            for index in range(20)
        ],
        "relationships": [],
        "events": [],
        "evidence_refs": [],
    }
    chunks = _ontology_sync_chunks(snapshot)
    assert all(1 + _ontology_chunk_read_cost("entities", chunk.get("entities", [])) <= ONTOLOGY_CHUNK_READ_BUDGET for chunk in chunks)
    assert sum(len(chunk.get("entities", [])) for chunk in chunks) == 20


def test_ontology_chunk_marks_nested_minimization():
    snapshot = {
        "source_instance": "runner-test",
        "entities": [{
            "entity_id": "pkg:pypi:nested",
            "entity_type": "package",
            "namespace": "pypi",
            "canonical_key": "nested",
            "properties": {"aliases": [f"alias-{index}" for index in range(101)]},
        }],
        "relationships": [],
        "events": [],
        "evidence_refs": [],
    }
    chunks = _ontology_sync_chunks(snapshot)
    entity = next(record for chunk in chunks for record in chunk.get("entities", []))
    assert entity["_secopsai_truncated"] is True
    assert all(chunk["snapshot_truncated"] is True for chunk in chunks)


def test_snapshot_envelope_timestamps_do_not_change_idempotency_key():
    base = {"schema_version": "secopsai.ontology.v1", "entities": [], "relationships": [], "events": [], "evidence_refs": []}
    assert _ontology_idempotency_key({**base, "exported_at": "2026-09-12T00:00:00Z"}) == _ontology_idempotency_key({**base, "exported_at": "2026-09-12T00:01:00Z"})


def test_compact_command_result_handles_summary_without_argument_error():
    result = _compact_command_result({"status": "succeeded", "summary": {"status": "succeeded", "completed_steps": 3}})
    assert result["summary"]["completed_steps"] == 3


def test_sync_ontology_is_failure_tolerant():
    class FailingSession:
        def request(self, *args, **kwargs):
            raise OSError("network offline")

    client = CoreEdgeClient(_settings(), session=FailingSession())
    result = client.sync_ontology({"entities": [], "relationships": [], "events": [], "evidence_refs": []})
    assert result["status"] == "degraded"
    assert "exhausted transient retries" in result["error"]


def test_sync_ontology_reports_resumable_partial_chunk_outcome():
    class FailingAfterFirst:
        def __init__(self):
            self.calls = 0

        def request(self, method, url, **kwargs):
            self.calls += 1
            if self.calls > 1:
                raise OSError("second chunk unavailable")
            return _Response()

    session = FailingAfterFirst()
    client = CoreEdgeClient(_settings(), session=session)
    snapshot = {
        "entities": [
            {"entity_id": f"pkg:pypi:partial-{index}", "entity_type": "package", "namespace": "pypi", "canonical_key": f"partial-{index}", "properties": {"description": "x" * 3500}}
            for index in range(100)
        ],
        "relationships": [],
        "events": [],
        "evidence_refs": [],
    }
    result = client.sync_ontology(snapshot)
    assert result["status"] == "degraded"
    assert result["chunks"] > 1
    assert result["accepted_chunks"] == 1
    assert result["rejected_chunks"] == result["chunks"] - 1
    assert len(result["accepted_chunk_ids"]) == 1
    assert len(result["rejected_chunk_ids"]) == result["rejected_chunks"]
    assert result["accepted_counts"]["entities"] > 0
    assert client.last_ontology_sync["rejected_chunk_ids"] == result["rejected_chunk_ids"]


def test_sync_state_carries_process_lease_and_ontology_summary():
    session = _Session()
    client = CoreEdgeClient(_settings(), session=session)
    client.last_ontology_sync = {
        "status": "degraded",
        "chunks": 3,
        "counts": {"entities": 8},
        "accepted_chunk_ids": ["a"],
        "rejected_chunk_ids": ["b", "c"],
        "accepted_chunks": 1,
        "rejected_chunks": 2,
    }
    result = client.sync_state({"status": "degraded", "completed_at": "2026-09-12T00:00:00Z"}, status="degraded")
    assert result["status"] == "accepted"
    payload = session.calls[-1][2]["json"]
    assert payload["worker_id"] == "runner-test"
    assert payload["process_generation"] > 0
    assert payload["process_revision"]
    assert payload["process_started_at"].endswith("Z")
    assert payload["lease_token"]
    ontology = payload["coordinator"]["ontology"]
    assert ontology["status"] == "degraded"
    assert ontology["accepted_chunk_ids"] == ["a"]
    assert ontology["rejected_chunks"] == 2


def test_sync_state_keeps_large_daily_result_observable_and_carries_ontology_error():
    session = _Session()
    client = CoreEdgeClient(_settings(), session=session)
    client.last_ontology_sync = {
        "status": "degraded",
        "chunks": 0,
        "error": "entities record cannot fit the bounded ontology request",
    }
    result = client.sync_state(
        {
            "status": "succeeded",
            "completed_at": "2026-09-12T00:00:00Z",
            "daily_automation": {
                "run": {
                    "status": "running",
                    "run_id": "DAR-1",
                    "steps": [
                        {"step_name": f"step-{index}", "status": "succeeded", "result": {"large": "x" * 5000}}
                        for index in range(100)
                    ],
                }
            },
        },
        status="degraded",
    )
    assert result["status"] == "accepted"
    payload = session.calls[-1][2]["json"]
    coordinator = payload["coordinator"]
    assert coordinator["ontology"]["error"] == "entities record cannot fit the bounded ontology request"
    assert coordinator["daily_automation"]["run_id"] == "DAR-1"


def test_command_terminal_payload_preserves_lease_proof():
    session = _Session()
    client = CoreEdgeClient(_settings(), session=session)
    result = client.complete_command("CMD-1", {"status": "succeeded"}, lease_generation=3, lease_token="lease-token")
    assert result["status"] == "accepted"
    payload = session.calls[-1][2]["json"]
    assert payload["worker_id"] == "runner-test"
    assert payload["lease_generation"] == 3
    assert payload["lease_token"] == "lease-token"


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
    assert session.calls[-1][2]["headers"]["Idempotency-Key"] == queued["idempotency_key"]
    assert session.calls[-1][2]["json"]["idempotency_key"] == queued["idempotency_key"]
    with soc_store.read_connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM ontology_sync_outbox").fetchone()[0] == 0


def test_transient_chunk_retries_use_the_same_receipt(monkeypatch):
    import requests
    from secopsai import core_edge_client as module
    monkeypatch.setattr(module.time, 'sleep', lambda _: None)
    class LostAcknowledgement(_Session):
        def request(self, *args, **kwargs):
            super().request(*args, **kwargs)
            if len(self.calls) == 1:
                raise requests.ConnectionError('synthetic dropped response')
            return _Response()
    session = LostAcknowledgement()
    result = CoreEdgeClient(_settings(), session=session).sync_ontology({'entities': [], 'relationships': [], 'events': [], 'evidence_refs': []})
    assert result['status'] == 'accepted'
    assert len(session.calls) == 2
    assert session.calls[0][2]['headers']['Idempotency-Key'] == session.calls[1][2]['headers']['Idempotency-Key']
    assert session.calls[0][2]['json'] == session.calls[1][2]['json']


def test_outbox_preserves_more_than_100_unacknowledged_chunks(tmp_path):
    db = str(tmp_path / 'outbox.db')
    client = CoreEdgeClient(_settings(), session=_Session())
    for i in range(103):
        result = client.enqueue_ontology_snapshot({'entities': [{'entity_id': f'pkg:npm:{i}', 'entity_type': 'package', 'namespace': 'npm', 'canonical_key': str(i)}]}, db_path=db)
        assert result['status'] == 'queued'
    with soc_store.read_connect(db) as conn:
        assert conn.execute('SELECT count(*) FROM ontology_sync_outbox').fetchone()[0] == 103
    result = client.flush_ontology_outbox(db_path=db, max_items=100)
    assert result['flushed'] == 100 and result['pending'] == 3 and result['status'] == 'degraded'
    result = client.flush_ontology_outbox(db_path=db)
    assert result['flushed'] == 3 and result['pending'] == 0


def test_worker_shutdown_does_not_send_new_requests():
    import pytest
    from secopsai.worker_control import WorkerShutdown, request_shutdown, reset_shutdown
    session = _Session()
    try:
        request_shutdown()
        with pytest.raises(WorkerShutdown):
            CoreEdgeClient(_settings(), session=session).sync_ontology({'entities': []})
        assert not session.calls
    finally:
        reset_shutdown()


def test_chunk_authentication_failure_is_not_retried():
    class Unauthorized(_Session):
        def request(self,*args,**kwargs):
            super().request(*args,**kwargs)
            class Response(_Response):
                status_code = 401
                ok = False
                def json(self): return {'error':'unauthorized'}
            return Response()
    session = Unauthorized()
    result = CoreEdgeClient(_settings(),session=session).sync_ontology({'entities':[]})
    assert result['status']=='degraded' and len(session.calls)==1


def test_outbox_deadline_leaves_unattempted_work_durable(tmp_path, monkeypatch):
    from secopsai import core_edge_client as module
    db = str(tmp_path/'deadline.db')
    clock = [0.0]
    monkeypatch.setattr(module.time,'monotonic',lambda:clock[0])
    class Slow(_Session):
        def request(self,*args,**kwargs):
            assert 0 < kwargs['timeout'] <= 1
            clock[0] += 1.1
            return super().request(*args,**kwargs)
    session = Slow()
    client = CoreEdgeClient(_settings(),session=session)
    for i in range(3):
        client.enqueue_ontology_snapshot({'entities':[{'entity_id':f'pkg:npm:{i}','entity_type':'package','namespace':'npm','canonical_key':str(i)}]},db_path=db)
    result = client.flush_ontology_outbox(db_path=db,max_items=100,seconds=1)
    assert result['flushed']==1 and result['pending']==2 and result['status']=='degraded'
    assert len(session.calls)==1


def test_outbox_rejection_diagnostics_are_bounded_and_keep_original_work(tmp_path):
    class Rejected(_Session):
        def request(self,*args,**kwargs):
            super().request(*args,**kwargs)
            class Response(_Response):
                status_code=422
                ok=False
                def json(self):
                    return {'error':'invalid_event','detail':'synthetic-private-token'}
            return Response()
    session=Rejected()
    client=CoreEdgeClient(_settings(),session=session)
    db=str(tmp_path/'rejected.db')
    client.enqueue_ontology_snapshot({'entities':[]},db_path=db)
    result=client.flush_ontology_outbox(db_path=db)
    assert result['http_status']==422
    assert result['pending']==1 and result['failed']==1
    assert 'synthetic-private-token' not in result['error']
    assert len(session.calls)==1


def _legacy_outbox_fixture(tmp_path, client):
    db=str(tmp_path/'legacy.db')
    receipt=client.enqueue_ontology_snapshot({'entities':[]},db_path=db)
    current=receipt['idempotency_key']
    legacy='a'*64
    with soc_store.connect(db) as conn:
        payload=json.loads(conn.execute('SELECT payload_json FROM ontology_sync_outbox').fetchone()[0])
        payload['idempotency_key']=legacy
        original=json.dumps(payload,sort_keys=True,separators=(',',':'))
        conn.execute('UPDATE ontology_sync_outbox SET idempotency_key=?,payload_json=? WHERE idempotency_key=?',(legacy,original,current))
    return db,legacy,original


def test_legacy_receipt_migration_survives_lost_ack_and_preserves_original_bytes(tmp_path, monkeypatch):
    import requests
    monkeypatch.setattr('secopsai.core_edge_client.time.sleep',lambda _:None)
    class ReceiptSession(_Session):
        ready=False
        def request(self,*args,**kwargs):
            super().request(*args,**kwargs)
            key=kwargs['headers']['Idempotency-Key']
            if not key.startswith('ontology-v2:'):
                class Conflict(_Response):
                    status_code=409
                    ok=False
                    def json(self):return {'error':'idempotency_conflict','detail':'different serialization'}
                return Conflict()
            if not self.ready:raise requests.ConnectionError('lost acknowledgement')
            class Ack(_Response):
                def json(self):return {'status':'accepted','idempotency_key':key,'idempotent':True}
            return Ack()
    session=ReceiptSession()
    client=CoreEdgeClient(_settings(),session=session)
    db,legacy,original=_legacy_outbox_fixture(tmp_path,client)
    failed=client.flush_ontology_outbox(db_path=db)
    assert failed['pending']==1 and failed['flushed']==0
    with soc_store.connect(db) as conn:
        saved=conn.execute('SELECT * FROM ontology_sync_receipt_migrations').fetchone()
        assert saved['original_payload_json']==original and saved['acknowledged_at'] is None
        assert conn.execute('SELECT payload_json FROM ontology_sync_outbox').fetchone()[0]==original
        conn.execute("UPDATE ontology_sync_outbox SET next_attempt_at='1970-01-01T00:00:00Z'")
    session.ready=True
    accepted=client.flush_ontology_outbox(db_path=db)
    assert accepted['flushed']==1 and accepted['pending']==0
    migrated=[c[2] for c in session.calls if c[2]['headers']['Idempotency-Key'].startswith('ontology-v2:')]
    assert all(c['json']==migrated[0]['json'] for c in migrated)
    assert migrated[0]['json']['idempotency_key']==saved['new_idempotency_key']
    with soc_store.read_connect(db) as conn:
        audit=conn.execute('SELECT * FROM ontology_sync_receipt_migrations').fetchone()
        assert audit['original_payload_json']==original and audit['acknowledged_at']


def test_entity_identity_conflict_is_not_migrated_or_discarded(tmp_path):
    class ConflictSession(_Session):
        def request(self,*args,**kwargs):
            super().request(*args,**kwargs)
            class Conflict(_Response):
                status_code=409
                ok=False
                def json(self):return {'error':'entity_identity_conflict'}
            return Conflict()
    session=ConflictSession()
    client=CoreEdgeClient(_settings(),session=session)
    db,_,original=_legacy_outbox_fixture(tmp_path,client)
    failed=client.flush_ontology_outbox(db_path=db)
    assert failed['pending']==1 and failed['http_status']==409
    assert len(session.calls)==1
    with soc_store.read_connect(db) as conn:
        assert conn.execute('SELECT count(*) FROM ontology_sync_receipt_migrations').fetchone()[0]==0
        assert conn.execute('SELECT payload_json FROM ontology_sync_outbox').fetchone()[0]==original


def test_invalid_dependency_chunk_does_not_block_valid_entity_delivery(tmp_path):
    class DependencySession(_Session):
        def request(self,*args,**kwargs):
            super().request(*args,**kwargs)
            if kwargs['json'].get('events'):
                class Rejected(_Response):
                    status_code=422
                    ok=False
                    def json(self):return {'error':'invalid_event'}
                return Rejected()
            return _Response()
    session=DependencySession()
    client=CoreEdgeClient(_settings(),session=session)
    db=str(tmp_path/'dependencies.db')
    client.enqueue_ontology_snapshot({'events':[{'event_id':'event:test','entity_id':'pkg:test','event_type':'observed'}]},db_path=db)
    client.enqueue_ontology_snapshot({'entities':[{'entity_id':'pkg:test','entity_type':'package','namespace':'test','canonical_key':'test'}]},db_path=db)
    result=client.flush_ontology_outbox(db_path=db)
    assert result['failed']==1 and result['flushed']==1 and result['pending']==1
    assert 'invalid_event' in result['error']
    with soc_store.read_connect(db) as conn:
        assert json.loads(conn.execute('SELECT payload_json FROM ontology_sync_outbox').fetchone()[0])['events']
