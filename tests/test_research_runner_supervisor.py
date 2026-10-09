import importlib.util
import io
import json
import sqlite3
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "research_runner_supervisor", ROOT / "cloudflare" / "secopsai-research-runner" / "container" / "supervisor.py"
)
supervisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(supervisor)


class FakeLedgerServer:
    """Implements the LedgerStore HTTP contract in memory."""

    def __init__(self):
        self.objects = {}
        self.uploads = {}
        self.latest = None

    def __call__(self, request, timeout=None):
        assert request.get_header("Authorization") == "Bearer tok"
        url = request.full_url.replace("http://ledger.internal", "")
        path, _, query = url.partition("?")
        key = query.removeprefix("key=")
        method = request.get_method()
        if method == "GET" and path == "/snapshot":
            if self.latest is None:
                raise urllib.error.HTTPError(url, 404, "missing", {}, io.BytesIO(b""))
            return _Response(self.objects[self.latest])
        if method == "POST" and path == "/uploads":
            upload_id = f"u{len(self.uploads) + 1}"
            self.uploads[upload_id] = {"key": f"ledger/snapshots/{upload_id}.db.gz", "parts": {}}
            return _Response(json.dumps({"upload_id": upload_id, "key": self.uploads[upload_id]["key"]}).encode())
        parts = path.strip("/").split("/")
        upload = self.uploads[parts[1]]
        assert key == upload["key"]
        if method == "PUT":
            upload["parts"][int(parts[3])] = request.data
            return _Response(json.dumps({"etag": f"e{parts[3]}"}).encode())
        body = json.loads(request.data)
        self.objects[key] = b"".join(upload["parts"][item["partNumber"]] for item in body["parts"])
        self.latest = key
        return _Response(json.dumps({"key": key}).encode())


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False


def test_checkpoint_and_restore_round_trip_a_live_wal_database(tmp_path, monkeypatch):
    monkeypatch.setattr(supervisor, "PART_BYTES", 1024)  # force several parts
    server = FakeLedgerServer()
    store = supervisor.LedgerStore("http://ledger.internal", "tok", opener=server)

    assert store.download(tmp_path / "missing.db") is False

    db = tmp_path / "openclaw_soc.db"
    live = sqlite3.connect(db)
    live.execute("PRAGMA journal_mode=WAL")
    live.execute("CREATE TABLE research_verdicts (id INTEGER PRIMARY KEY, verdict TEXT)")
    live.executemany("INSERT INTO research_verdicts (verdict) VALUES (?)", [("likely",)] * 500)
    live.commit()  # left open: the worker keeps its connection during checkpoints

    key = supervisor.checkpoint(db, store, tmp_path)
    assert key == server.latest
    assert len(server.uploads["u1"]["parts"]) > 1

    restored = tmp_path / "restored" / "openclaw_soc.db"
    restored.parent.mkdir()
    assert store.download(restored) is True
    count = sqlite3.connect(restored).execute("SELECT count(*) FROM research_verdicts").fetchone()[0]
    assert count == 500
    live.close()


def test_supervisor_refuses_to_start_an_empty_ledger(tmp_path, monkeypatch):
    server = FakeLedgerServer()
    monkeypatch.setattr(supervisor.urllib.request, "urlopen", server)
    monkeypatch.setenv("SECOPS_FINDINGS_DIR", str(tmp_path / "research"))
    monkeypatch.setenv("LEDGER_STORE_URL", "http://ledger.internal")
    monkeypatch.setenv("LEDGER_STORE_TOKEN", "tok")
    monkeypatch.delenv("SECOPSAI_LEDGER_ALLOW_EMPTY", raising=False)
    monkeypatch.setattr(supervisor.LedgerStore, "__init__", lambda self, url, token: (setattr(self, "base_url", url), setattr(self, "token", token), setattr(self, "_open", server)) and None)
    assert supervisor.main(["--cycles", "1"]) == 2
    assert not (tmp_path / "research" / "openclaw_soc.db").exists()


def test_checkpoint_only_uploads_existing_ledger(tmp_path, monkeypatch):
    server = FakeLedgerServer()
    data = tmp_path / "research"
    data.mkdir()
    sqlite3.connect(data / "openclaw_soc.db").execute("CREATE TABLE t (x)").connection.commit()
    monkeypatch.setenv("SECOPS_FINDINGS_DIR", str(data))
    monkeypatch.setenv("LEDGER_STORE_URL", "http://ledger.internal")
    monkeypatch.setenv("LEDGER_STORE_TOKEN", "tok")
    monkeypatch.setattr(supervisor.LedgerStore, "__init__", lambda self, url, token: (setattr(self, "base_url", url), setattr(self, "token", token), setattr(self, "_open", server)) and None)
    assert supervisor.main(["--checkpoint-only"]) == 0
    assert server.latest is not None


def test_time_budget_stops_the_worker_and_still_checkpoints(tmp_path, monkeypatch):
    # Regression: a run that outlived the CI job timeout was killed before the
    # final checkpoint and lost all of its work.
    import subprocess as real_subprocess
    import time

    server = FakeLedgerServer()
    data = tmp_path / "research"
    data.mkdir()
    sqlite3.connect(data / "openclaw_soc.db").execute("CREATE TABLE t (x)").connection.commit()
    monkeypatch.setenv("SECOPS_FINDINGS_DIR", str(data))
    monkeypatch.setenv("LEDGER_STORE_URL", "http://ledger.internal")
    monkeypatch.setenv("LEDGER_STORE_TOKEN", "tok")
    monkeypatch.setattr(supervisor.LedgerStore, "__init__", lambda self, url, token: (setattr(self, "base_url", url), setattr(self, "token", token), setattr(self, "_open", server)) and None)
    slow_worker = [supervisor.sys.executable, "-c", "import time; time.sleep(120)"]
    original_popen = real_subprocess.Popen
    monkeypatch.setattr(supervisor.subprocess, "Popen", lambda _cmd, **kw: original_popen(slow_worker, **kw))
    started = time.monotonic()
    assert supervisor.main(["--cycles", "5", "--max-seconds", "1"]) == 0
    assert time.monotonic() - started < 60
    assert server.latest is not None, "budget stop must still checkpoint the ledger"
