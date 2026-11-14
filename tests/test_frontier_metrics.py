import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import soc_store
from secopsai import frontier_metrics as fm
from secopsai.research_surveillance import ensure_collectors

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def _row(level, discovered="2026-03-01", eco="npm", category="malicious_intent", status="scanned", set_="malicious"):
    return {"set": set_, "ecosystem": eco, "category": category, "discovered": discovered, "level": level, "status": status}


def test_benchmark_scores_split_held_out_and_skip_errors():
    rows = [_row("alert"), _row("notice"), _row("none", discovered="2025-05-01"), _row("alert", discovered="2025-06-01"),
            {**_row("none"), "status": "error"},
            _row("notice", set_="clean", category=""), *[_row("none", set_="clean", category="") for _ in range(9)]]
    scores = fm.benchmark_scores(rows)
    npm = scores["recall"]["npm/malicious_intent"]
    assert npm["all"]["samples"] == 5 and npm["all"]["errors"] == 1
    assert npm["all"]["hit"] == 0.75 and npm["all"]["alert"] == 0.5
    assert npm["held_out"]["hit"] == 1.0 and npm["held_out"]["alert"] == 0.5, "only samples discovered on or after the cutoff"
    assert scores["false_positive_rate"]["npm"]["hit"] == 0.1


def _db(tmp_path):
    db = str(tmp_path / "ledger.db")
    soc_store.init_db(db)
    ensure_collectors(db_path=db)
    return db


def _event(connection, eco, package, published, metadata=None, event_type="version_observed"):
    collector = connection.execute("SELECT collector_id FROM registry_collectors WHERE ecosystem=?", (eco,)).fetchone()[0]
    key = f"{eco}:{package}:{published}"
    connection.execute(
        """INSERT INTO registry_feed_events (feed_event_id, collector_id, ecosystem, package, version, event_type,
           registry_timestamp, page_url, leaf_url, metadata_json, idempotency_key, collected_at, processing_state)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,'pending')""",
        (key, collector, eco, package, "1.0.0", event_type, published, "u", "u", json.dumps(metadata or {}), key, published))


def _iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def test_live_coverage_counts_releases_that_reached_a_verdict(tmp_path):
    db = _db(tmp_path)
    with soc_store.connect(db) as connection:
        published = NOW - timedelta(hours=3)
        _event(connection, "pypi", "a", _iso(published), {"content_prescan": {"status": "clean", "at": _iso(published + timedelta(minutes=4))}})
        _event(connection, "pypi", "b", _iso(published), {"content_prescan": {"status": "hit", "at": _iso(published + timedelta(minutes=20))}})
        _event(connection, "pypi", "c", _iso(published), {"content_prescan": {"status": "error", "at": _iso(published)}})
        _event(connection, "pypi", "d", _iso(published))
        _event(connection, "pypi", "gone", _iso(published), event_type="unpublish")
        _event(connection, "pypi", "fresh", _iso(NOW - timedelta(minutes=10)))  # not settled yet
        _event(connection, "pypi", "old", _iso(NOW - timedelta(hours=30)))  # outside the window
        _event(connection, "npm", "left-pad", _iso(published))
        _event(connection, "npm", "right-pad", _iso(published))
        connection.execute(
            """INSERT INTO research_npm_release_analyses (analysis_id, source_event_id, package, version, artifact_sha256, status,
               score, indicators_json, intake_json, created_at, updated_at) VALUES ('A1','x','left-pad','1.0.0','s','completed',0,'[]','{}',?,?)""",
            (_iso(published + timedelta(minutes=6)), _iso(published + timedelta(minutes=6))))
    report = fm.live_coverage(db_path=db, now=NOW)
    pypi, npm = report["ecosystems"]["pypi"], report["ecosystems"]["npm"]
    assert (pypi["published"], pypi["scanned"], pypi["coverage"]) == (4, 2, 0.5)
    assert pypi["p50_minutes"] in (4.0, 20.0) and pypi["p95_minutes"] == 20.0
    assert (npm["published"], npm["scanned"], npm["p50_minutes"]) == (2, 1, 6.0)
    assert report["all"]["coverage"] == 0.5


def test_targets_pass_fail_and_never_pass_unmeasured():
    targets = {"phases": [{"id": "p", "targets": [
        {"name": "up", "metric": "benchmark.recall.npm/all.held_out.alert", "op": ">=", "value": 0.5},
        {"name": "down", "metric": "live.ecosystems.npm.p50_minutes", "op": "<=", "value": 10},
        {"name": "missing", "metric": "enforcement.block_rate", "op": ">=", "value": 1.0}]}]}
    measured = {"benchmark": {"recall": {"npm/all": {"held_out": {"alert": 0.4}}}}, "live": {"ecosystems": {"npm": {"p50_minutes": 6}}}}
    outcomes = {row["name"]: row["outcome"] for row in fm.evaluate_targets(targets, measured)}
    assert outcomes == {"up": "fail", "down": "pass", "missing": "not measured"}


def test_registered_targets_are_well_formed():
    targets = json.loads((ROOT / "eval" / "frontier" / "targets.json").read_text())
    assert targets["held_out_cutoff"] == fm.HELD_OUT_CUTOFF
    names = [target["name"] for phase in targets["phases"] for target in phase["targets"]]
    assert len(names) == len(set(names)) and len(targets["phases"]) == 6
    assert all(target["op"] in {">=", "<="} for phase in targets["phases"] for target in phase["targets"])


def test_scorecard_script_reports_without_failing(tmp_path):
    bench = tmp_path / "bench.json"
    bench.write_text(json.dumps({"meta": {"generated_at": "2026-11-15T00:00:00Z"},
                                 "rows": [_row("alert", eco="pypi", category="compromised_lib"), _row("none", set_="clean", category="", eco="npm")]}))
    live = tmp_path / "live.json"
    live.write_text(json.dumps({"window_hours": 24, "ecosystems": {"npm": {"coverage": 0.2, "p50_minutes": 50}}}))
    out = tmp_path / "card.json"
    completed = subprocess.run([sys.executable, str(ROOT / "scripts" / "frontier_scorecard.py"), "--benchmark", str(bench),
                                "--live", str(live), "--out", str(out)], capture_output=True, text=True, env={"PATH": "/usr/bin:/bin"})
    assert completed.returncode == 0, completed.stderr
    card = json.loads(out.read_text())
    outcomes = {row["name"]: row["outcome"] for row in card["results"]}
    assert outcomes["PyPI compromised-library recall (held-out, hit)"] == "pass"
    assert outcomes["npm releases reaching a content verdict"] == "fail"
    assert "## Frontier scorecard" in completed.stdout
