import gzip
import io
import json
import os
import sqlite3

from secopsai import research_ledger_export as export
from tests.test_research_runner_supervisor import FakeLedgerServer


def test_streamed_export_restores_to_an_identical_database(tmp_path, monkeypatch):
    monkeypatch.setattr(export, "PART_BYTES", 4096)
    monkeypatch.setattr(export, "READ_BYTES", 2048)
    db = tmp_path / "openclaw_soc.db"
    connection = sqlite3.connect(db)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE research_cases (case_id TEXT, title TEXT)")
    connection.executemany("INSERT INTO research_cases VALUES (?, ?)", [(f"RSC-{i:012X}", os.urandom(100).hex()) for i in range(400)])
    connection.commit()
    connection.close()

    server = FakeLedgerServer()
    result = export.export_ledger(str(db), "http://ledger.internal", "tok", opener=server)
    assert result["parts"] > 1
    restored = tmp_path / "restored.db"
    restored.write_bytes(gzip.decompress(server.objects[server.latest]))
    count = sqlite3.connect(restored).execute("SELECT count(*) FROM research_cases").fetchone()[0]
    assert count == 400


def test_export_runs_once_and_requests_idle(tmp_path, monkeypatch):
    db = tmp_path / "openclaw_soc.db"
    sqlite3.connect(db).execute("CREATE TABLE t (x)").connection.commit()
    calls = []
    monkeypatch.setattr(export, "export_ledger", lambda *a, **k: calls.append(a) or {"key": "k"})
    monkeypatch.setenv("SECOPSAI_LEDGER_EXPORT_URL", "https://ledger.example")
    monkeypatch.setenv("SECOPSAI_CORE_BRIDGE_TOKEN", "bridge")
    monkeypatch.setenv("SECOPSAI_LEDGER_EXPORT_AND_STOP", "true")
    assert export.maybe_export_before_worker(str(db)) is True
    assert export.maybe_export_before_worker(str(db)) is True
    assert len(calls) == 1
    monkeypatch.delenv("SECOPSAI_LEDGER_EXPORT_URL")
    assert export.maybe_export_before_worker(str(db)) is False


def test_export_requests_send_a_non_default_user_agent():
    # Cloudflare answers the default Python-urllib agent with 403 (error 1010).
    seen = []

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def opener(request, timeout=None):
        seen.append(request.get_header("User-agent"))
        return Response(json.dumps({"upload_id": "u", "key": "ledger/snapshots/x.db.gz"}).encode())

    export._Uploader("https://ledger.example", "tok", opener)
    assert seen == ["SecOpsAI-Research/1.0"]
