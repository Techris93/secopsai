"""The Fast Lane behaviour-floor replay applies eval/fast_lane_gate/PLAN.md as frozen."""
import hashlib
import importlib.util
import urllib.error
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from secopsai import fast_lane_gate as gate

ROOT = Path(__file__).resolve().parents[1]
T0 = datetime(2026, 11, 26, tzinfo=timezone.utc)
HTTP, WALLET, SECRETS, OBFUSCATOR = "BEH_NPM_SMALL_HTTP_SEND", "BEH_SHELL_WALLET_SEND", "BEH_DIFF_NEW_SECRETS_AND_SEND", "BEH_JS_OBFUSCATOR"
CONFUSION = "BEH_VERSION_CONFUSION"


def _script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _entry(alert_id, package, version, hours, rules=(), severity=None, group="needs_review", other="", eco="npm"):
    reason = "; ".join(([other] if other else []) + ([f"behaviour rules: {', '.join(sorted(rules))}"] if rules else []))
    return {"source": "fast_lane", "alert_id": alert_id, "ecosystem": eco, "package": package, "version": version,
            "occurred_at": (T0 + timedelta(hours=hours)).isoformat().replace("+00:00", "Z"), "reason": reason,
            "severity": severity or gate.floor_of(rules), "group": group}


def _row(package, rules=(), score=None, yara=False, discovered="2026-03-01", category="malicious_intent", eco="npm", version="1.0.0"):
    files = {f"BEHAVIOUR:{r}": ["index.js"] for r in rules}
    if yara:
        files["YARA:SOME_RULE"] = ["index.js"]
    total = score if score is not None else min(100, sum(gate.SCORES[r] for r in rules))
    return {"status": "scanned", "ecosystem": eco, "package": package, "version": version, "discovered": discovered,
            "rule_files": files, "score": total, "set": "clean" if category == "popular" else "malicious", "category": category}


def test_plan_is_frozen_and_the_critical_rules_match_the_fast_lane():
    replay = _script("fast_lane_gate_replay")
    assert hashlib.sha256((ROOT / "eval/fast_lane_gate/PLAN.md").read_bytes()).hexdigest() == replay.PLAN_SHA256
    assert replay.plan_unchanged()
    assert gate.CRITICAL_BEHAVIOUR == _script("fast_lane").CRITICAL_BEHAVIOUR


def test_reasons_and_floors():
    assert gate.parse_reason(f"behaviour rules: {HTTP}, {WALLET}") == ({HTTP, WALLET}, False)
    assert gate.parse_reason(f"YARA warning (score 60): X; behaviour rules: {HTTP}") == ({HTTP}, True)
    assert gate.parse_reason("") == (set(), False)
    assert gate.floor_of({HTTP}) == "medium" and gate.floor_of({SECRETS}) == "high"
    assert gate.floor_of({"BEH_PTH_STARTUP_HARVEST"}) == "critical"
    assert gate.floor_of({HTTP}, keep=[]) == "low" and gate.floor_of({HTTP}, keep=[HTTP]) == "medium"


def test_v1_counts_only_rules_the_package_did_not_have_on_its_last_flagged_release():
    history = gate.alerts([
        _entry("p1", "p", "1", 0, {HTTP}), _entry("p2", "p", "2", 24, {HTTP}), _entry("p3", "p", "3", 48, {HTTP, WALLET}),
        _entry("p4", "p", "4", 48 + 31 * 24, {HTTP}), _entry("q1", "q", "1", 30, {HTTP}),
    ])
    counted = gate.new_rules(history)
    assert counted == {"p1": {HTTP}, "p2": set(), "p3": {WALLET}, "p4": {HTTP}, "q1": {HTTP}}
    p2 = next(a for a in history if a["alert_id"] == "p2")
    assert gate.severity(p2, "V1", counted, []) == "none", "a repeat is not delivered"


def test_variants_never_raise_an_alert_and_leave_mixed_alerts_alone():
    mixed = gate.alerts([_entry("m", "m", "1", 0, {HTTP}, severity="high", other="publisher changed")])[0]
    assert all(gate.severity(mixed, v, {}, []) == "high" for v in gate.VARIANTS)
    capped = gate.alerts([_entry("c", "c", "1", 0, {SECRETS}, severity="medium")])[0]
    assert gate.severity(capped, "V2", {}, [SECRETS]) == "medium"


def _window():
    entries = [_entry(f"bad{i}", f"bad{i}", "1", i, {CONFUSION}, group="known_malicious" if i < 3 else "removed") for i in range(12)]
    entries += [_entry(f"noisy{i}", "noisy", str(i), 20 + i, {HTTP}) for i in range(100)]
    entries += [_entry(f"other{i}", f"other{i}", "1", 30, {HTTP}) for i in range(50)]
    entries.append(_entry("listed", "listed", "1", 40, {HTTP}, group="known_malicious"))
    return gate.alerts(entries)


def test_live_gates_cut_repeats_and_keep_confirmed_malware():
    window = _window()
    report = gate.live_report(window, window, keep=sorted(gate.PRESET_KEEP), days=7)
    assert report["confirmed_packages"] == 13 and report["ossf_packages"] == 4 and report["a3"]
    v0, v1, v2 = (report["variants"][v] for v in ("V0", "V1", "V2"))
    assert v0["behaviour_only_medium_plus"] == 163
    assert v1["behaviour_only_medium_plus"] == 64 and v1["a1"] and v1["a2"]
    assert v2["behaviour_only_medium_plus"] == 12 and v2["a1"]
    assert v2["ossf_lost"] == ["npm/listed"] and not v2["a2"], "an ossf-listed package raised only by a lowered rule fails A2"
    assert v2["low"] == 151


def test_keep_list_applies_the_four_criteria():
    noisy, rated, small, sole = HTTP, WALLET, OBFUSCATOR, SECRETS
    entries = [_entry(f"n{i}", f"n{i}", "1", 0, {noisy}, group="removed" if i == 0 else "needs_review") for i in range(300)]
    entries += [_entry(f"r{i}", f"r{i}", "1", 0, {rated}, group="removed" if i < 2 else "needs_review") for i in range(300)]
    entries += [_entry(f"s{i}", f"s{i}", "1", 0, {small}) for i in range(10)]
    entries += [_entry(f"x{i}", f"x{i}", "1", 0, {sole}) for i in range(300)]
    bench = [_row(f"b{i}", {sole}, discovered="2025-06-01") for i in range(5)]
    bench += [_row(f"h{i}", {noisy}, discovered="2026-02-01") for i in range(9)]  # held-out rows never count
    result = gate.keep_list(gate.alerts(entries), bench)
    rules = {r["rule"]: r for r in result["rules"]}
    assert not rules[noisy]["keep"], "1 of 300 is under 0.5%"
    assert rules[rated]["reasons"] == ["confirmed_rate"]
    assert rules[small]["reasons"] == ["too_few_packages"]
    assert rules[sole]["reasons"] == ["benchmark_sole"]
    assert rules[CONFUSION]["reasons"] == ["preset", "too_few_packages"]
    assert noisy in result["lowered"] and set(gate.PRESET_KEEP) <= set(result["keep"])


def test_benchmark_rows_split_the_yara_score_from_the_behaviour_score():
    rows = gate.bench_rows([_row("a", {HTTP}, score=100, yara=True), _row("b", {HTTP}, score=85, yara=True),
                            _row("c", score=80, yara=True), _row("d", {HTTP})])
    assert [r["yara_score"] for r in rows] == [40, 25, 80, 0]


def test_benchmark_gate_counts_recall_per_package():
    rows = [_row(f"h{i}", {HTTP}) for i in range(50)] + [_row(f"y{i}", score=80, yara=True) for i in range(50)]
    rows += [_row(f"p{i}", {"BEH_PYPI_RAW_IP_URL"}, eco="pypi") for i in range(10)]
    rows += [_row("h0", {HTTP}, version="1.0.1", discovered="2026-04-01")]  # a later version: V1 drops it, the package still counts
    rows += [_row("pop", {HTTP}, category="popular")]
    lowered = gate.benchmark_report(rows, keep=[])
    assert lowered["V0"]["recall"]["npm"] == {"packages": 100, "raised": 100, "recall": 1.0}
    assert lowered["V1"]["b1_drop_points"] == {"npm": 0.0, "pypi": 0.0} and lowered["V1"]["b1"]
    assert lowered["V2"]["b1_drop_points"]["npm"] == 50.0 and not lowered["V2"]["b1"]
    assert lowered["V2"]["popular_raised"] == 0 and lowered["V2"]["b2"]
    kept = gate.benchmark_report(rows, keep=[HTTP, "BEH_PYPI_RAW_IP_URL"])
    assert kept["V2"]["b1"] and kept["V3"]["b1"]


def test_decision_needs_evidence_then_the_largest_cut():
    live = {"a3": False, "confirmed_packages": 4}
    assert gate.decide(live, {}, 0)["result"] == "extend"
    assert gate.decide(live, {}, 2)["result"] == "inconclusive"
    ok = {"a1": True, "a2": True}
    live = {"a3": True, "variants": {"V1": {**ok, "a1_cut": 0.6}, "V2": {**ok, "a1_cut": 0.6}, "V3": {**ok, "a1_cut": 0.8}}}
    bench = {v: {"b1": True, "b2": True} for v in gate.VARIANTS}
    assert gate.decide(live, bench, 0)["variant"] == "V3"
    bench["V3"]["b1"] = False
    assert gate.decide(live, bench, 0)["variant"] == "V1", "a tie goes to the simplest"
    bench = {v: {"b1": False, "b2": True} for v in gate.VARIANTS}
    assert gate.decide(live, bench, 0)["result"] == "no_change"


def test_windows_and_label_dates_follow_the_plan():
    assert gate.windows("selection") == (datetime(2026, 11, 18, 5, 17, tzinfo=timezone.utc), datetime(2026, 11, 25, tzinfo=timezone.utc))
    start, end = gate.windows("held_out", 2)
    assert (start, end) == (datetime(2026, 11, 25, tzinfo=timezone.utc), datetime(2026, 12, 16, tzinfo=timezone.utc))
    assert not gate.labels_ready(gate.HELD_OUT[1], datetime(2026, 12, 8, 23, tzinfo=timezone.utc))
    assert gate.labels_ready(gate.HELD_OUT[1], datetime(2026, 12, 9, tzinfo=timezone.utc))
    with pytest.raises(ValueError):
        gate.windows("held_out", 3)


def test_replay_refuses_to_label_early(monkeypatch, tmp_path, capsys):
    replay = _script("fast_lane_gate_replay")
    monkeypatch.setattr(replay.gate, "labels_ready", lambda end, now: False)
    monkeypatch.setattr("sys.argv", ["replay", "--mode", "held_out", "--benchmark", str(tmp_path / "missing.json")])
    assert replay.main() == 2
    assert "refusing to run early" in capsys.readouterr().err


def test_labels_cache_npm_documents_and_mark_removed_versions():
    replay = _script("fast_lane_gate_replay")
    calls = []

    class Client:
        STORE = "https://ledger.example"

        @staticmethod
        def _get(url, *, token="", accept="application/json", timeout=30):
            calls.append(url)
            if "/firewall/" in url:
                return {}
            if url.endswith("/gone"):
                raise urllib.error.HTTPError(url, 404, "not found", {}, None)
            return {"versions": {"1": {}}}

    entries = [_entry("a1", "kept", "1", 0, {HTTP}), _entry("a2", "kept", "2", 1, {HTTP}), _entry("a3", "gone", "1", 2, {HTTP})]
    groups = {e["alert_id"]: e["group"] for e in replay.label(Client, entries, "token")}
    assert groups == {"a1": "needs_review", "a2": "removed", "a3": "removed"}
    assert sum(1 for url in calls if url.endswith("/kept")) == 1, "one registry read per npm package"
