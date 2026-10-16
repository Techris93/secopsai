import importlib.util
import io
import json
import sqlite3
import urllib.error
from pathlib import Path

import pytest

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
        self.completion_retry_safe = True

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
            return _Response(json.dumps({"upload_id": upload_id, "key": self.uploads[upload_id]["key"],
                                         "completion_retry_safe": self.completion_retry_safe}).encode())
        parts = path.strip("/").split("/")
        upload = self.uploads[parts[1]]
        assert key == upload["key"]
        if method == "PUT":
            upload["parts"][int(parts[3])] = request.data
            return _Response(json.dumps({"etag": f"e{parts[3]}"}).encode())
        body = json.loads(request.data)
        if key not in self.objects:
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


@pytest.mark.parametrize("stage", ["create", "part", "complete"])
@pytest.mark.parametrize("lost_response", [False, True])
def test_checkpoint_recovers_a_dropped_connection_without_losing_parts(tmp_path, monkeypatch, stage, lost_response):
    server = FakeLedgerServer()
    calls = []
    failed = False

    def flaky(request, timeout):
        nonlocal failed
        operation = "part" if request.get_method() == "PUT" else "complete" if "/complete?" in request.full_url else "create"
        calls.append((operation, request.full_url, request.data))
        if operation == stage and not failed:
            failed = True
            if lost_response:
                server(request, timeout)  # R2 accepted it; the acknowledgement was lost.
            raise urllib.error.URLError(ConnectionResetError(104, "Connection reset by peer"))
        return server(request, timeout)

    monkeypatch.setattr(supervisor.time, "sleep", lambda _seconds: None)
    monkeypatch.setattr(supervisor, "PART_BYTES", 16)
    db = tmp_path / "ledger.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE t (value)")
        conn.execute("INSERT INTO t VALUES ('committed finding')")
    store = supervisor.LedgerStore("http://ledger.internal", "tok", opener=flaky)
    key = supervisor.checkpoint(db, store, tmp_path)
    assert key == server.latest
    restored = tmp_path / "restored.db"
    assert supervisor.LedgerStore("http://ledger.internal", "tok", opener=server).download(restored)
    with sqlite3.connect(restored) as conn:
        assert conn.execute("SELECT value FROM t").fetchone()[0] == "committed finding"
    retried = [call for call in calls if call[0] == stage]
    assert retried[0] == retried[1], "retries retain the part number and exact bytes"
    if stage != "create":
        assert len(server.uploads) == 1, "retry only the failed operation, not the entire large upload"


@pytest.mark.parametrize("status,attempts", [(401, 1), (403, 1), (400, 1), (413, 1), (429, 3), (503, 3)])
def test_upload_retries_only_transient_http_errors(tmp_path, monkeypatch, status, attempts):
    calls = []
    sleeps = []
    def unavailable(request, timeout):
        calls.append(request)
        raise urllib.error.HTTPError(request.full_url, status, "failure", {"Retry-After": "2"}, io.BytesIO(b""))
    monkeypatch.setattr(supervisor.time, "sleep", sleeps.append)
    compressed = tmp_path / "snapshot.gz"
    compressed.write_bytes(b"snapshot")
    with pytest.raises((urllib.error.HTTPError, ConnectionError)):
        supervisor.LedgerStore("http://ledger.internal", "tok", opener=unavailable).upload(compressed)
    assert len(calls) == attempts
    assert sleeps == ([2, 2] if attempts == 3 else [])


def test_upload_deadline_is_shared_by_all_parts(tmp_path, monkeypatch):
    server = FakeLedgerServer()
    clock = [0]
    timeouts = []
    def slow(request, timeout):
        timeouts.append(timeout)
        clock[0] += 4
        return server(request, timeout)
    monkeypatch.setattr(supervisor.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(supervisor, "UPLOAD_TIMEOUT_SECONDS", 10)
    monkeypatch.setattr(supervisor, "PART_BYTES", 3)
    compressed = tmp_path / "snapshot.gz"
    compressed.write_bytes(b"abcdef")
    with pytest.raises(TimeoutError):
        supervisor.LedgerStore("http://ledger.internal", "tok", opener=slow).upload(compressed)
    assert timeouts == [10, 6, 2]
    assert server.latest is None, "exceeding the budget must not publish an incomplete object"


def test_retry_after_cannot_exceed_upload_deadline(tmp_path, monkeypatch):
    sleeps = []
    def limited(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 429, "limited", {"Retry-After": "1000"}, io.BytesIO(b""))
    monkeypatch.setattr(supervisor.time, "sleep", sleeps.append)
    compressed = tmp_path / "snapshot.gz"
    compressed.write_bytes(b"snapshot")
    with pytest.raises(TimeoutError):
        supervisor.LedgerStore("http://ledger.internal", "tok", opener=limited).upload(compressed)
    assert sleeps == []


def test_old_ledger_store_completion_is_not_blindly_repeated(tmp_path, monkeypatch):
    server = FakeLedgerServer()
    server.completion_retry_safe = False
    calls = []
    def flaky(request, timeout):
        if "/complete?" in request.full_url:
            calls.append(request)
            raise ConnectionResetError("lost response")
        return server(request, timeout)
    monkeypatch.setattr(supervisor.time, "sleep", lambda _seconds: None)
    compressed = tmp_path / "snapshot.gz"
    compressed.write_bytes(b"snapshot")
    with pytest.raises(ConnectionError):
        supervisor.LedgerStore("http://ledger.internal", "tok", opener=flaky).upload(compressed)
    assert len(calls) == 1
    assert server.latest is None


def test_exhausted_part_retries_preserve_previous_snapshot(tmp_path, monkeypatch):
    server = FakeLedgerServer()
    server.latest = "previous"
    server.objects["previous"] = b"previous snapshot"
    attempts = []
    def unavailable(request, timeout):
        if request.get_method() == "PUT":
            attempts.append(request)
            raise ConnectionResetError("lost connection")
        return server(request, timeout)
    monkeypatch.setattr(supervisor.time, "sleep", lambda _seconds: None)
    compressed = tmp_path / "snapshot.gz"
    compressed.write_bytes(b"new snapshot")
    with pytest.raises(ConnectionError):
        supervisor.LedgerStore("http://ledger.internal", "tok", opener=unavailable).upload(compressed)
    assert len(attempts) == 3
    assert server.latest == "previous"
    assert server.objects == {"previous": b"previous snapshot"}


def test_part_response_read_failure_retries_exact_bytes(tmp_path, monkeypatch):
    server = FakeLedgerServer()
    parts = []
    class BrokenResponse(_Response):
        def read(self, *_args):
            raise supervisor.http.client.IncompleteRead(b'{"etag":')
    def flaky(request, timeout):
        response = server(request, timeout)
        if request.get_method() == "PUT":
            parts.append(request.data)
            if len(parts) == 1:
                return BrokenResponse()
        return response
    monkeypatch.setattr(supervisor.time, "sleep", lambda _seconds: None)
    compressed = tmp_path / "snapshot.gz"
    compressed.write_bytes(b"snapshot")
    key = supervisor.LedgerStore("http://ledger.internal", "tok", opener=flaky).upload(compressed)
    assert parts == [b"snapshot", b"snapshot"]
    assert server.objects[key] == b"snapshot"


def test_shutdown_still_fails_when_checkpoint_retries_exhaust(tmp_path, monkeypatch):
    server = FakeLedgerServer()
    server.latest = "previous"
    server.objects["previous"] = b"previous snapshot"
    calls = []
    def unavailable(request, timeout):
        if request.get_method() == "PUT":
            calls.append(request)
            raise ConnectionResetError("lost connection")
        return server(request, timeout)
    class FinishedWorker:
        def wait(self, timeout=None): return 0
    data = tmp_path / "research"
    data.mkdir()
    with sqlite3.connect(data / "openclaw_soc.db") as conn:
        conn.execute("CREATE TABLE t (x)")
    monkeypatch.setenv("SECOPS_FINDINGS_DIR", str(data))
    monkeypatch.setenv("LEDGER_STORE_URL", "http://ledger.internal")
    monkeypatch.setenv("LEDGER_STORE_TOKEN", "tok")
    original_init = supervisor.LedgerStore.__init__
    monkeypatch.setattr(supervisor.LedgerStore, "__init__", lambda self, url, token: original_init(self, url, token, opener=unavailable))
    monkeypatch.setattr(supervisor.subprocess, "Popen", lambda *_args, **_kwargs: FinishedWorker())
    monkeypatch.setattr(supervisor.time, "sleep", lambda _seconds: None)
    assert supervisor.main(["--cycles", "1"]) == 1
    assert len(calls) == 3
    assert server.latest == "previous"


class IncrementalServer:
    def __init__(self):
        self.objects, self.manifest, self.puts = {}, None, 0
        self.drill_manifest = None
    def __call__(self, request, timeout=None):
        path = request.full_url.replace('http://ledger.internal', '')
        if path.startswith('/artifact-objects/'):
            key = path.rsplit('/',1)[1]
            if request.get_method() == 'PUT':
                import hashlib
                assert hashlib.sha256(request.data).hexdigest() == key
                self.objects[key] = request.data
                self.puts += 1
                return _Response(json.dumps({'sha256':key,'size_bytes':len(request.data)}).encode())
            return _Response(self.objects[key])
        drill = path.startswith('/recovery-drill/')
        if drill:
            path = path[len('/recovery-drill'):]
        if path == '/checkpoints':
            manifest = json.loads(request.data)
            assert supervisor.valid_manifest(manifest)
            chunks = manifest['chunks'] if manifest['version']==3 else manifest['base']['chunks']+manifest['patches']
            assert all(c['sha256'] in self.objects for c in chunks)
            if drill:
                self.drill_manifest = manifest
            else:
                self.manifest = manifest
            return _Response(b'{"key":"ledger/manifests/fixture.json"}')
        if path == '/checkpoint-manifest':
            return _Response(json.dumps(self.drill_manifest if drill else self.manifest).encode())
        raise AssertionError(path)


def test_incremental_checkpoint_restores_and_reuses_verified_chunks(tmp_path, monkeypatch):
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS','1')
    db = tmp_path / 'live.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE data(id INTEGER PRIMARY KEY, value BLOB)')
        conn.execute('INSERT INTO data VALUES(1,zeroblob(30000000))')
    server = IncrementalServer()
    client = supervisor.LedgerStore('http://ledger.internal','tok',opener=server)
    supervisor.checkpoint(db,client,tmp_path)
    first_puts = server.puts
    assert first_puts == 2
    supervisor.checkpoint(db,client,tmp_path)
    assert server.puts == first_puts, 'unchanged chunks must not be uploaded again'
    destination = tmp_path / 'restored.db'
    assert client.download(destination)
    with sqlite3.connect(destination) as restored:
        assert restored.execute('SELECT length(value) FROM data').fetchone()[0] == 30000000
    assert destination.stat().st_mode & 0o777 == 0o600
    original = destination.read_bytes()
    first_hash = server.manifest['chunks'][0]['sha256']
    server.objects[first_hash] = b'corrupted compressed chunk'
    with pytest.raises(ValueError, match='checksum'):
        client.download(destination)
    assert destination.read_bytes() == original
    assert not destination.with_suffix('.restore').exists()


def test_invalid_incremental_manifest_cannot_start_restoration(tmp_path):
    server = IncrementalServer()
    client = supervisor.LedgerStore('http://ledger.internal','tok',opener=server)
    for manifest in [{}, {'version':3, 'chunks':[{'raw_size_bytes':float('inf')}]}]:
        with pytest.raises(ValueError, match='manifest'):
            client.download_chunked(tmp_path/'missing.db',manifest)
    assert not (tmp_path/'missing.db').exists()


def test_forced_budget_shutdown_is_failed_even_when_checkpoint_survives(tmp_path, monkeypatch):
    import subprocess as real_subprocess
    server = FakeLedgerServer()
    data = tmp_path / "research"
    data.mkdir()
    with sqlite3.connect(data / "openclaw_soc.db") as conn:
        conn.execute("CREATE TABLE retained (value TEXT)")
        conn.execute("INSERT INTO retained VALUES ('committed before interruption')")
    monkeypatch.setenv("SECOPS_FINDINGS_DIR", str(data))
    monkeypatch.setenv("LEDGER_STORE_URL", "http://ledger.internal")
    monkeypatch.setenv("LEDGER_STORE_TOKEN", "tok")
    original_init = supervisor.LedgerStore.__init__
    monkeypatch.setattr(supervisor.LedgerStore,"__init__",lambda self,url,token: original_init(self,url,token,opener=server))
    original_popen = real_subprocess.Popen
    command = [supervisor.sys.executable,"-c","import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(120)"]
    monkeypatch.setattr(supervisor.subprocess,"Popen",lambda _cmd,**kw: original_popen(command,**kw))
    monkeypatch.setattr(supervisor,"GRACE_SECONDS",1)
    assert supervisor.main(["--cycles","1","--max-seconds","1"]) == 1
    restored = tmp_path / "restored.db"
    assert supervisor.LedgerStore("http://ledger.internal","tok").download(restored)
    with sqlite3.connect(restored) as conn:
        assert conn.execute("SELECT value FROM retained").fetchone()[0] == 'committed before interruption'


@pytest.mark.parametrize('writer_failed', [False, True])
def test_production_recovery_drill_isolated_from_live_checkpoint(tmp_path, monkeypatch, writer_failed):
    import sys
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS','1')
    monkeypatch.setenv('LEDGER_STORE_URL','http://ledger.internal')
    monkeypatch.setenv('LEDGER_STORE_TOKEN','synthetic-owner-token')
    db = tmp_path/'production.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE research_source_snapshots(content BLOB, sha256 TEXT)')
        import hashlib
        content = b'synthetic archived source'
        conn.execute('INSERT INTO research_source_snapshots VALUES (?,?)', (content,hashlib.sha256(content).hexdigest()))
    server = IncrementalServer()
    client = supervisor.LedgerStore('http://ledger.internal','synthetic-owner-token',opener=server)
    supervisor.checkpoint(db,client,tmp_path)
    production_manifest = dict(server.manifest)
    monkeypatch.setattr('urllib.request.urlopen',server)
    drill_spec = importlib.util.spec_from_file_location('isolated_recovery_smoke',ROOT/'scripts/research_recovery_smoke.py')
    drill = importlib.util.module_from_spec(drill_spec)
    drill_spec.loader.exec_module(drill)
    report = tmp_path/'recovery.json'
    monkeypatch.setattr(sys,'argv',['recovery','--output',str(report)])
    if writer_failed:
        class FailedWriter:
            def poll(self): return 1
            def wait(self, timeout=None): return 1
        monkeypatch.setattr(drill.subprocess, 'Popen', lambda *a, **kw: FailedWriter())
    assert drill.main() == (1 if writer_failed else 0)
    result = json.loads(report.read_text())
    assert server.manifest == production_manifest
    assert server.drill_manifest != production_manifest
    assert result['production_modified'] is False
    if writer_failed:
        assert result['status']=='failed' and result['phase']=='simulate_isolated_failed_commit'
        return
    assert result['failed_commit_preserved_previous_checkpoint'] is True
    assert result['isolated_committed_rows'] > result['isolated_restored_rows'] == 1
    assert result['maximum_committed_loss_seconds'] < 300
    assert result['source_archives_hash_verified'] == 1
    assert result['rpo_target_proven'] is False
    assert 'synthetic-owner-token' not in report.read_text()


def test_checkpoint_capture_deadline_preserves_previous_manifest(tmp_path, monkeypatch):
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS','1')
    db = tmp_path/'live.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE data(value TEXT)')
        conn.execute("INSERT INTO data VALUES('committed')")
    server = IncrementalServer()
    client = supervisor.LedgerStore('http://ledger.internal','tok',opener=server)
    supervisor.checkpoint(db,client,tmp_path)
    previous = dict(server.manifest)
    ticks = iter([0,301])
    monkeypatch.setattr(supervisor.time,'monotonic',lambda: next(ticks))
    with pytest.raises(TimeoutError,match='capture'):
        supervisor.checkpoint(db,client,tmp_path)
    assert server.manifest == previous


def test_recurring_incremental_checkpoint_reserves_sparse_upload_time(tmp_path, monkeypatch):
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS','1')
    monkeypatch.setenv('SECOPSAI_PAGE_DELTA_CHECKPOINTS','1')
    db = tmp_path/'live.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE data(value TEXT)')
        conn.execute("INSERT INTO data VALUES('committed')")

    class TimedStore:
        incremental_ready = True
        baseline_path = tmp_path/'baseline.db'

        def upload_sparse(self, backup, *, captured_at, deadline):
            self.upload_deadline = deadline
            return 'sparse-checkpoint'

    # Model a backup that has taken 241 seconds. Recurring checkpoints must
    # still enter the sparse upload path with the remaining bounded budget.
    clock = iter([0])
    def monotonic():
        return next(clock, 241)
    monkeypatch.setattr(supervisor.time,'monotonic',monotonic)

    store = TimedStore()
    assert supervisor.checkpoint(db,store,tmp_path) == 'sparse-checkpoint'
    assert store.upload_deadline == 300


def test_checkpoint_pins_snapshot_while_wal_writer_keeps_committing(tmp_path, monkeypatch):
    import threading
    import time
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS','1')
    db = tmp_path/'live.db'
    with sqlite3.connect(db) as conn:
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('CREATE TABLE data(id INTEGER PRIMARY KEY, value BLOB)')
        conn.execute('INSERT INTO data VALUES(1,zeroblob(30000000))')
        conn.execute('CREATE TABLE updates(id INTEGER PRIMARY KEY)')
    stop = threading.Event()
    def write():
        with sqlite3.connect(db,timeout=10) as conn:
            i=0
            while not stop.is_set():
                conn.execute('INSERT INTO updates VALUES (?)',(i,))
                conn.commit()
                i+=1
                time.sleep(.002)
    writer = threading.Thread(target=write)
    writer.start()
    server = IncrementalServer()
    client = supervisor.LedgerStore('http://ledger.internal','tok',opener=server)
    try:
        supervisor.checkpoint(db,client,tmp_path)
    finally:
        stop.set()
        writer.join(timeout=10)
    assert not writer.is_alive()
    restored = tmp_path/'restored.db'
    client.download(restored)
    with sqlite3.connect(restored) as conn, sqlite3.connect(db) as live:
        assert conn.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        assert live.execute('SELECT count(*) FROM updates').fetchone()[0] > conn.execute('SELECT count(*) FROM updates').fetchone()[0]


def test_failed_manifest_reuses_individually_verified_chunk_receipts(tmp_path, monkeypatch):
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS','1')
    db=tmp_path/'live.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE data(value BLOB)')
        conn.execute('INSERT INTO data VALUES(zeroblob(30000000))')
    server=IncrementalServer()
    client=supervisor.LedgerStore('http://ledger.internal','tok',opener=server)
    request=client._request
    def interrupted(method,path,*args,**kwargs):
        if method=='POST' and path=='/checkpoints':
            raise ConnectionError('synthetic lost manifest commit')
        return request(method,path,*args,**kwargs)
    monkeypatch.setattr(client,'_request',interrupted)
    with pytest.raises(ConnectionError):
        supervisor.checkpoint(db,client,tmp_path)
    assert server.manifest is None
    assert len(client.chunk_cache)==server.puts==2
    monkeypatch.setattr(client,'_request',request)
    supervisor.checkpoint(db,client,tmp_path)
    assert server.manifest is not None
    assert server.puts==2
    assert supervisor.LedgerStore('http://ledger.internal','tok',opener=server).download(tmp_path/'restored.db')


def test_recovery_failure_always_preserves_bounded_report(tmp_path, monkeypatch):
    import sys
    monkeypatch.setenv('LEDGER_STORE_URL','http://ledger.internal')
    monkeypatch.setenv('LEDGER_STORE_TOKEN','synthetic-private-token')
    def not_ready(request,timeout=None):
        raise urllib.error.HTTPError(request.full_url,404,'Not Found',{},None)
    monkeypatch.setattr('urllib.request.urlopen',not_ready)
    spec = importlib.util.spec_from_file_location('failed_recovery_smoke',ROOT/'scripts/research_recovery_smoke.py')
    drill=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(drill)
    report=tmp_path/'failure.json'
    monkeypatch.setattr(sys,'argv',['recovery','--output',str(report)])
    assert drill.main()==1
    result=json.loads(report.read_text())
    assert result['phase']=='read_production_manifest'
    assert result['http_status']==404
    assert result['production_modified'] is False
    assert 'synthetic-private-token' not in report.read_text()
    assert len(report.read_bytes())<1024


def test_first_full_transfer_has_separate_bounded_bootstrap_budget(tmp_path,monkeypatch):
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS','1')
    db=tmp_path/'live.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE data(value TEXT)')
    client=supervisor.LedgerStore('http://ledger.internal','tok',opener=IncrementalServer())
    deadlines=[]
    monkeypatch.setattr(supervisor.time,'monotonic',lambda:100)
    monkeypatch.setattr(client,'upload_chunked',lambda backup,**kw: deadlines.append(kw['deadline']) or 'fixture')
    supervisor.checkpoint(db,client,tmp_path)
    client.chunk_cache={'a'*64}
    supervisor.checkpoint(db,client,tmp_path)
    client.incremental_ready=True
    supervisor.checkpoint(db,client,tmp_path)
    assert deadlines==[700,700,400]


def test_sparse_checkpoint_preserves_distributed_edits_and_immutable_baseline(tmp_path, monkeypatch):
    import hashlib
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS','1')
    monkeypatch.setenv('SECOPSAI_PAGE_DELTA_CHECKPOINTS','1')
    db=tmp_path/'live.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE data(id INTEGER PRIMARY KEY, label TEXT, value BLOB)')
        conn.executemany('INSERT INTO data VALUES (?, ?, zeroblob(5000000))', [(i,'before') for i in range(12)])
    server=IncrementalServer()
    client=supervisor.LedgerStore('http://ledger.internal','tok',opener=server)
    supervisor.checkpoint(db,client,tmp_path)
    base=dict(server.manifest)
    base_bytes=client.baseline_path.read_bytes()
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE data SET label='after!'")
    supervisor.checkpoint(db,client,tmp_path)
    delta=server.manifest
    assert delta['version']==4 and delta['base']==base
    assert sum(c['raw_size_bytes'] for c in delta['patches']) < 1000000
    assert client.baseline_path.read_bytes()==base_bytes
    restored=tmp_path/'restored.db'
    fresh=supervisor.LedgerStore('http://ledger.internal','tok',opener=server)
    assert fresh.download(restored)
    assert hashlib.sha256(restored.read_bytes()).hexdigest()==delta['sha256']
    with sqlite3.connect(restored) as conn:
        assert conn.execute("SELECT count(*) FROM data WHERE label='after!'").fetchone()[0]==12
        conn.execute("UPDATE data SET label='latest' WHERE id=1")
    supervisor.checkpoint(restored,fresh,tmp_path)
    assert server.manifest['version']==4 and server.manifest['base']==base, 'deltas must not form an unbounded chain'
    assert fresh.baseline_path.read_bytes()==base_bytes


@pytest.mark.parametrize('attack', ['overlap','out_of_bounds','wrong_final_hash','corrupt_frame'])
def test_sparse_restore_rejects_invalid_deltas_without_replacing_existing_database(tmp_path, monkeypatch, attack):
    import gzip, hashlib, struct
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS','1')
    monkeypatch.setenv('SECOPSAI_PAGE_DELTA_CHECKPOINTS','1')
    db=tmp_path/'live.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE data(label TEXT, value BLOB)')
        conn.execute("INSERT INTO data VALUES ('before',zeroblob(30000000))")
    server=IncrementalServer()
    client=supervisor.LedgerStore('http://ledger.internal','tok',opener=server)
    supervisor.checkpoint(db,client,tmp_path)
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE data SET label='after!'")
    supervisor.checkpoint(db,client,tmp_path)
    manifest=json.loads(json.dumps(server.manifest))
    if attack=='wrong_final_hash':
        manifest['sha256']='a'*64
    else:
        entry=manifest['patches'][0]
        raw=gzip.decompress(server.objects[entry['sha256']])
        if attack=='overlap':
            raw+=raw[len(supervisor.DELTA_MAGIC):]
        elif attack=='out_of_bounds':
            raw=raw[:8]+struct.pack('>QI',manifest['size_bytes']+4096,4096)+raw[20:]
        else:
            raw=b'BADFRAME'+raw[8:]
        packed=gzip.compress(raw,mtime=0)
        key=hashlib.sha256(packed).hexdigest()
        server.objects[key]=packed
        manifest['patches'][0]={'sha256':key,'size_bytes':len(packed),'raw_sha256':hashlib.sha256(raw).hexdigest(),'raw_size_bytes':len(raw)}
    target=tmp_path/'existing.db'
    target.write_bytes(b'previous verified bytes')
    with pytest.raises(ValueError):
        client.download_chunked(target,manifest)
    assert target.read_bytes()==b'previous verified bytes'
    assert not target.with_suffix('.restore').exists()


def test_sparse_checkpoint_rebases_a_large_rewrite_with_a_separate_full_budget(tmp_path, monkeypatch):
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS','1')
    monkeypatch.setenv('SECOPSAI_PAGE_DELTA_CHECKPOINTS','1')
    db=tmp_path/'live.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE data(value BLOB)')
        conn.execute('INSERT INTO data VALUES(zeroblob(2000000))')
    server=IncrementalServer()
    client=supervisor.LedgerStore('http://ledger.internal','tok',opener=server)
    supervisor.checkpoint(db,client,tmp_path)
    old=server.manifest['sha256']
    with sqlite3.connect(db) as conn:
        conn.execute('UPDATE data SET value=randomblob(2000000)')
    supervisor.checkpoint(db,client,tmp_path)
    assert server.manifest['version']==3 and server.manifest['sha256']!=old
    assert client.baseline_manifest==server.manifest


def test_corrupt_local_baseline_is_rebased_instead_of_committing_unrestorable_delta(tmp_path, monkeypatch):
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS','1')
    monkeypatch.setenv('SECOPSAI_PAGE_DELTA_CHECKPOINTS','1')
    db=tmp_path/'live.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE data(value BLOB)')
        conn.execute('INSERT INTO data VALUES(zeroblob(2000000))')
    server=IncrementalServer()
    client=supervisor.LedgerStore('http://ledger.internal','tok',opener=server)
    supervisor.checkpoint(db,client,tmp_path)
    original=client.baseline_path.read_bytes()
    client.baseline_path.chmod(0o600)
    with client.baseline_path.open('r+b') as baseline:
        baseline.seek(4096)
        baseline.write(b'bad')
    supervisor.checkpoint(db,client,tmp_path)
    assert server.manifest['version']==3
    assert client.baseline_path.read_bytes()==original
    restored=tmp_path/'restored.db'
    assert client.download(restored)
    assert restored.read_bytes()==original


def test_sparse_restore_handles_growth_and_truncation_against_the_same_baseline(tmp_path,monkeypatch):
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS','1')
    monkeypatch.setenv('SECOPSAI_PAGE_DELTA_CHECKPOINTS','1')
    db=tmp_path/'live.db'
    with sqlite3.connect(db) as conn:
        conn.execute('PRAGMA auto_vacuum=FULL')
        conn.execute('CREATE TABLE data(id INTEGER PRIMARY KEY,value BLOB)')
        conn.execute('INSERT INTO data VALUES(1,zeroblob(30000000))')
    server=IncrementalServer()
    client=supervisor.LedgerStore('http://ledger.internal','tok',opener=server)
    supervisor.checkpoint(db,client,tmp_path)
    base=dict(server.manifest)
    with sqlite3.connect(db) as conn:
        conn.execute('INSERT INTO data VALUES(2,zeroblob(1000000))')
    supervisor.checkpoint(db,client,tmp_path)
    assert server.manifest['version']==4 and server.manifest['size_bytes']>base['size_bytes']
    restored=tmp_path/'growth.db'
    assert client.download(restored)
    with sqlite3.connect(restored) as conn:
        assert conn.execute('SELECT count(*) FROM data').fetchone()[0]==2
    with sqlite3.connect(db) as conn:
        conn.execute('DELETE FROM data WHERE id=1')
    supervisor.checkpoint(db,client,tmp_path)
    assert server.manifest['version']==4 and server.manifest['base']==base
    assert server.manifest['size_bytes']<base['size_bytes']
    target=tmp_path/'truncated.db'
    fresh=supervisor.LedgerStore('http://ledger.internal','tok',opener=server)
    assert fresh.download(target)
    assert target.stat().st_size==server.manifest['size_bytes']
    with sqlite3.connect(target) as conn:
        assert conn.execute('SELECT id,length(value) FROM data').fetchall()==[(2,1000000)]


def test_checkpoint_schedule_uses_capture_start_and_never_overlaps(monkeypatch):
    clock = [0.0]
    starts = []
    class Stop:
        def wait(self, seconds):
            clock[0] += seconds
            return len(starts) == 3
    def capture():
        starts.append(clock[0])
        clock[0] += 140
    monkeypatch.setattr(supervisor.time, 'monotonic', lambda: clock[0])
    supervisor.periodic_checkpoints(Stop(), 60, capture)
    assert starts == [60, 200, 340]


def test_sparse_capture_reuses_verified_page_index_without_rereading_baseline(tmp_path, monkeypatch):
    from pathlib import Path
    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS', '1')
    monkeypatch.setenv('SECOPSAI_PAGE_DELTA_CHECKPOINTS', '1')
    db = tmp_path / 'live.db'
    with sqlite3.connect(db) as connection:
        connection.execute('CREATE TABLE data(label TEXT, payload BLOB)')
        connection.execute("INSERT INTO data VALUES ('before', zeroblob(2000000))")
    server = IncrementalServer()
    client = supervisor.LedgerStore('http://ledger.internal', 'tok', opener=server)
    supervisor.checkpoint(db, client, tmp_path)
    with sqlite3.connect(db) as connection:
        connection.execute("UPDATE data SET label='after!'")
    original_open = Path.open
    baseline = client.baseline_path
    def guarded_open(path, *args, **kwargs):
        assert path != baseline, 'unchanged verified baseline must not be read every capture'
        return original_open(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(Path, 'open', guarded_open)
        supervisor.checkpoint(db, client, tmp_path)
    assert server.manifest['version'] == 4
    restored = tmp_path / 'restored.db'
    assert client.download(restored)
    with sqlite3.connect(restored) as connection:
        assert connection.execute('SELECT label FROM data').fetchone()[0] == 'after!'


def test_sparse_checkpoint_uploads_changed_frames_in_parallel_and_commits_complete_manifest(tmp_path, monkeypatch):
    import threading
    import time

    monkeypatch.setenv('SECOPSAI_INCREMENTAL_CHECKPOINTS', '1')
    monkeypatch.setenv('SECOPSAI_PAGE_DELTA_CHECKPOINTS', '1')
    monkeypatch.setattr(supervisor, 'SPARSE_FRAME_RAW_LIMIT', 64 * 1024)
    db = tmp_path / 'live.db'
    with sqlite3.connect(db) as connection:
        connection.execute('CREATE TABLE data(value BLOB)')
        connection.execute('INSERT INTO data VALUES(zeroblob(4194304))')

    server = IncrementalServer()
    active, maximum, sparse_puts = [0], [0], [0]
    lock = threading.Lock()

    def delayed(request, timeout=None):
        is_sparse_put = request.get_method() == 'PUT' and '/artifact-objects/' in request.full_url
        if is_sparse_put:
            with lock:
                active[0] += 1
                maximum[0] = max(maximum[0], active[0])
                sparse_puts[0] += 1
            time.sleep(0.01)
        try:
            return server(request, timeout)
        finally:
            if is_sparse_put:
                with lock:
                    active[0] -= 1

    client = supervisor.LedgerStore('http://ledger.internal', 'tok', opener=delayed)
    supervisor.checkpoint(db, client, tmp_path)
    maximum[0] = sparse_puts[0] = 0
    with sqlite3.connect(db) as connection:
        connection.execute('UPDATE data SET value=randomblob(524288)||substr(value,524289)')

    supervisor.checkpoint(db, client, tmp_path)

    assert maximum[0] > 1
    assert maximum[0] <= supervisor.SPARSE_UPLOAD_WORKERS
    assert sparse_puts[0] > 1
    assert server.manifest['version'] == 4
    assert all(patch['sha256'] in server.objects for patch in server.manifest['patches'])
    restored = tmp_path / 'restored.db'
    assert client.download(restored)
    with sqlite3.connect(restored) as connection:
        # length(TEXT) stops at a random NUL; cast back to BLOB to check all bytes.
        assert connection.execute('SELECT length(CAST(value AS BLOB)) FROM data').fetchone()[0] == 4194304


def test_delivery_only_supervisor_uses_verifier_and_preserves_final_checkpoint(tmp_path, monkeypatch):
    import subprocess as real_subprocess
    server = FakeLedgerServer()
    data = tmp_path / 'research'
    data.mkdir()
    with sqlite3.connect(data / 'openclaw_soc.db') as connection:
        connection.execute('CREATE TABLE synthetic(value)')
    monkeypatch.setenv('SECOPS_FINDINGS_DIR', str(data))
    monkeypatch.setenv('LEDGER_STORE_URL', 'http://ledger.internal')
    monkeypatch.setenv('LEDGER_STORE_TOKEN', 'tok')
    monkeypatch.setenv('SECOPSAI_RESTORED_LEDGER_RECOVERY', '1')
    monkeypatch.setattr(supervisor.LedgerStore, '__init__', lambda self, url, token: (setattr(self, 'base_url', url), setattr(self, 'token', token), setattr(self, '_open', server)) and None)
    original_popen = real_subprocess.Popen
    commands = []
    def launch(command, **kwargs):
        commands.append(command)
        assert kwargs['env']['SECOPSAI_RESTORED_LEDGER_RECOVERY'] == '0', 'existing local ledgers cannot inherit restored-owner recovery'
        return original_popen([supervisor.sys.executable, '-c', 'raise SystemExit(0)'], **kwargs)
    monkeypatch.setattr(supervisor.subprocess, 'Popen', launch)
    assert supervisor.main(['--delivery-only', '--cycles', '1']) == 0
    assert commands[0][-1] == 'secopsai.research_delivery_verification'
    assert server.latest is not None
