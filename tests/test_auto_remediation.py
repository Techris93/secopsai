import json
from datetime import datetime, timedelta, timezone

from secopsai import auto_remediation as ar

NOW = datetime(2026, 11, 13, 18, 0, tzinfo=timezone.utc)
DEFECT_LOG = ("run\tTest\t2026-11-13T17:00:01.1Z collected 10 items\n"
              "run\tTest\t2026-11-13T17:00:02.2Z FAILED tests/test_x.py::test_y - AssertionError: assert 3 == 4\n"
              "run\tTest\t2026-11-13T17:00:03.3Z ##[error]Process completed with exit code 1.\n")


class FakeGitHub:
    def __init__(self, runs, logs=None, pr=None):
        self.runs, self.logs, self.pr, self.calls, self.issues = runs, logs or {}, pr or {}, [], 0

    def __call__(self, args, stdin=None):
        self.calls.append(list(args))
        if args[:2] == ["run", "list"]:
            return json.dumps(self.runs)
        if args[0] == "api" and args[1].endswith("/jobs"):
            run_id = int(args[1].split("/")[-2])
            return json.dumps({"jobs": [{"id": run_id * 10, "name": "test", "conclusion": "failure",
                                         "steps": [{"name": "Run tests", "conclusion": "failure"}]}]})
        if args[0] == "api" and args[1].endswith("/logs"):
            return self.logs.get(int(args[1].split("/")[-2]) // 10, DEFECT_LOG)
        if args[:2] == ["issue", "create"]:
            self.issues += 1
            return f"https://github.com/o/r/issues/{100 + self.issues}\n"
        if args[:2] == ["pr", "view"]:
            return json.dumps(self.pr)
        return ""

    def writes(self):
        return [call for call in self.calls if call[0] in {"issue", "pr", "label"}]


def run(run_id, minutes_ago=10, conclusion="failure", workflow="Test & Build"):
    return {"databaseId": run_id, "workflowName": workflow, "conclusion": conclusion, "event": "push",
            "headSha": "a" * 40, "createdAt": (NOW - timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z")}


def test_fingerprint_ignores_run_specific_noise():
    first = ar.error_line(DEFECT_LOG)
    second = ar.error_line(DEFECT_LOG.replace("3 == 4", "7 == 9").replace("17:00", "18:30"))
    assert first.startswith("FAILED tests/test_x.py") and "exit code" not in first
    assert ar.fingerprint("w", "s", first) == ar.fingerprint("w", "s", second)


def test_outages_are_external_and_never_fixed(tmp_path):
    db = str(tmp_path / "r.db")
    gh = FakeGitHub([run(1, conclusion="startup_failure", workflow="Fast Lane"),
                     run(2, workflow="Research Worker"), run(3, 5, workflow="Research Worker")],
                    logs={2: "delivery_blockers: enabled sources remain outside freshness targets: Maven",
                          3: "delivery_blockers: enabled sources remain outside freshness targets: Maven"})
    fixes = []
    ar.tick(gh=gh, db_path=db, run_mode="merge", now=NOW, fixer=lambda item, db_path: fixes.append(item))
    kinds = {item["workflow"]: (item["kind"], item["status"]) for item in ar.incidents(db_path=db)}
    assert kinds["Fast Lane"] == ("external:github_actions_outage", "external")
    assert kinds["Research Worker"] == ("external:upstream_source_down", "external")
    assert fixes == [], "no code fix for an outage"
    later = NOW + timedelta(hours=25)
    ar.tick(gh=FakeGitHub([]), db_path=db, run_mode="merge", now=later)
    assert {item["status"] for item in ar.incidents(db_path=db)} == {"resolved"}, "an outage closes once it stops"


def test_the_error_line_skips_warnings_and_prefers_a_root_cause():
    log = ("##[warning]Node.js 20 is deprecated. Error: not this\n"
           '{"status": "failed", "root_cause": "Research Worker run 123 concluded failure"}\n'
           "##[error]Process completed with exit code 1.\n")
    assert ar.error_line(log) == "Research Worker run 123 concluded failure"
    assert ar.classify(log, "failure") == "external:downstream_of_worker"
    assert ar.error_line("##[warning]Node.js 20 is deprecated\nFAILED tests/a.py::t\n") == "FAILED tests/a.py::t"


def test_a_single_failure_is_watched_not_fixed(tmp_path):
    db = str(tmp_path / "r.db")
    gh = FakeGitHub([run(1)])
    fixes = []
    ar.tick(gh=gh, db_path=db, run_mode="merge", now=NOW, fixer=lambda item, db_path: fixes.append(item))
    assert ar.incidents(db_path=db)[0]["status"] == "watching" and fixes == []
    assert not any(call[:2] == ["issue", "create"] for call in gh.calls), "no issue for a possible flake"
    ar.tick(gh=FakeGitHub([]), db_path=db, run_mode="merge", now=NOW + timedelta(days=8))
    assert ar.incidents(db_path=db)[0]["status"] == "expired"


def test_observe_mode_records_but_writes_nothing(tmp_path):
    db = str(tmp_path / "r.db")
    gh = FakeGitHub([run(1), run(2, 5)])
    summary = ar.tick(gh=gh, db_path=db, run_mode="observe", now=NOW)
    assert summary["new_failures"] == 2 and ar.incidents(db_path=db)[0]["status"] == "open"
    assert gh.writes() == []


def _fix(files, worktree):
    def fixer(item, db_path):
        return {"run_id": "SOR-1", "profile": "engineering/devops-automator", "worktree": str(worktree),
                "branch": "secopsai-specialist/1", "files": files, "output": {"summary": "Fix the count"}}
    return fixer


def test_recurring_defect_is_fixed_verified_shipped_merged_and_confirmed(tmp_path):
    db = str(tmp_path / "r.db")
    gh = FakeGitHub([run(1), run(2, 5)])
    shipped = []
    summary = ar.tick(gh=gh, db_path=db, run_mode="merge", now=NOW,
                      fixer=_fix(["secopsai/x.py", "tests/test_x.py"], tmp_path / "wt"),
                      verifier=lambda worktree, files: {"ok": True, "checks": [{"check": "tests", "ok": True}], "reason": ""},
                      shipper=lambda item, fix, verification, gh: shipped.append(fix) or 77)
    item = ar.incidents(db_path=db)[0]
    assert item["status"] == "pr_open" and item["pr_number"] == 77 and item["issue_number"] == 101, summary
    assert shipped and item["specialist_run_id"] == "SOR-1"
    # CI green and the fix is low risk: it merges itself.
    gh.pr = {"state": "OPEN", "additions": 12, "files": [{"path": "secopsai/x.py"}, {"path": "tests/test_x.py"}],
             "statusCheckRollup": [{"conclusion": "SUCCESS"}, {"conclusion": "SKIPPED"}]}
    ar.tick(gh=gh, db_path=db, run_mode="merge", now=NOW)
    assert ["pr", "merge", "77", "-R", ar.REPO_SLUG, "--squash", "--delete-branch"] in gh.calls
    assert ar.incidents(db_path=db)[0]["status"] == "verifying"
    # 48 quiet hours later it is resolved and the issue closed.
    ar.tick(gh=FakeGitHub([]), db_path=db, run_mode="merge", now=max(NOW, datetime.now(timezone.utc)) + timedelta(hours=49))
    assert ar.incidents(db_path=db)[0]["status"] == "resolved"


def test_a_recurrence_after_the_fix_reopens_the_incident(tmp_path):
    db = str(tmp_path / "r.db")
    for run_id in (1, 2):
        ar.record_failure({**run(run_id), "failed_step": "test / Run tests"}, DEFECT_LOG, db_path=db, now=NOW)
    incident = ar.incidents(db_path=db)[0]
    ar._update(incident["incident_id"], str(db), status="verifying", attempts=1, merged_at=ar._iso(NOW))
    ar.record_failure({**run(3), "failed_step": "test / Run tests"}, DEFECT_LOG, db_path=db, now=NOW + timedelta(hours=3))
    assert ar.incidents(db_path=db)[0]["status"] == "open"


def test_protected_or_untested_fixes_wait_for_a_person(tmp_path):
    assert ar.merge_policy(["secopsai/x.py", "tests/test_x.py"], 20) == (True, [])
    allowed, reasons = ar.merge_policy([".github/workflows/x.yml", "tests/test_x.py"], 5)
    assert not allowed and "protected" in reasons[0]
    allowed, reasons = ar.merge_policy(["secopsai/x.py"], 5)
    assert not allowed and reasons == ["adds no regression test"]
    assert not ar.merge_policy(["secopsai/codex_bridge.py", "tests/t.py"], 5)[0]
    assert not ar.merge_policy([f"tests/t{i}.py" for i in range(11)], 5)[0]
    assert not ar.merge_policy(["secopsai/x.py", "tests/t.py"], 900)[0]

    db = str(tmp_path / "r.db")
    for run_id in (1, 2):
        ar.record_failure({**run(run_id), "failed_step": "s"}, DEFECT_LOG, db_path=db, now=NOW)
    incident = ar.incidents(db_path=db)[0]
    ar._update(incident["incident_id"], db, status="pr_open", pr_number=5, issue_number=9, attempts=1)
    gh = FakeGitHub([], pr={"state": "OPEN", "additions": 3, "files": [{"path": ".github/workflows/x.yml"}, {"path": "tests/t.py"}],
                            "statusCheckRollup": [{"conclusion": "SUCCESS"}]})
    ar.tick(gh=gh, db_path=db, run_mode="merge", now=NOW)
    assert not any(call[:2] == ["pr", "merge"] for call in gh.calls)
    assert ar.incidents(db_path=db)[0]["status"] == "pr_open"


def test_failed_ci_closes_the_pr_and_two_attempts_hand_it_to_a_person(tmp_path):
    db = str(tmp_path / "r.db")
    for run_id in (1, 2):
        ar.record_failure({**run(run_id), "failed_step": "s"}, DEFECT_LOG, db_path=db, now=NOW)
    incident = ar.incidents(db_path=db)[0]
    ar._update(incident["incident_id"], db, status="pr_open", pr_number=5, issue_number=9, attempts=2)
    gh = FakeGitHub([], pr={"state": "OPEN", "additions": 3, "files": [{"path": "tests/t.py"}],
                            "statusCheckRollup": [{"conclusion": "FAILURE"}]})
    ar.tick(gh=gh, db_path=db, run_mode="merge", now=NOW)
    assert any(call[:2] == ["pr", "close"] for call in gh.calls)
    assert ar.incidents(db_path=db)[0]["status"] == "needs_human"


def test_a_fix_that_fails_verification_is_discarded(tmp_path):
    db = str(tmp_path / "r.db")
    gh = FakeGitHub([run(1), run(2, 5)])
    shipped = []
    ar.tick(gh=gh, db_path=db, run_mode="merge", now=NOW, fixer=_fix(["secopsai/x.py", "tests/test_x.py"], tmp_path / "wt"),
            verifier=lambda worktree, files: {"ok": False, "checks": [{"check": "tests", "ok": False}], "reason": ""},
            shipper=lambda *a, **k: shipped.append(1) or 1)
    item = ar.incidents(db_path=db)[0]
    assert shipped == [] and item["status"] == "open" and item["attempts"] == 1
    assert "verification failed" in item["notes"][-1]["note"]


def test_verify_needs_a_changed_test_and_runs_it(tmp_path):
    calls = []

    class Done:
        returncode, stdout, stderr = 0, "ok", ""

    result = ar.verify(str(tmp_path), ["secopsai/x.py"], run=lambda command, **kwargs: calls.append(command) or Done())
    assert result["ok"] is False and "no test file" in result["reason"]
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_x():\n    assert True\n")
    calls.clear()
    result = ar.verify(str(tmp_path), ["tests/test_x.py"], run=lambda command, **kwargs: calls.append(command) or Done())
    assert result["ok"] is True and any("pytest" in command for command in calls) and any("flake8" in " ".join(command) for command in calls)


def test_an_interrupted_fix_returns_to_the_queue(tmp_path):
    db = str(tmp_path / "r.db")
    for run_id in (1, 2):
        ar.record_failure({**run(run_id), "failed_step": "s"}, DEFECT_LOG, db_path=db, now=NOW)
    incident = ar.incidents(db_path=db)[0]
    ar._update(incident["incident_id"], db, status="fixing", attempts=1)
    ar.housekeeping(gh=FakeGitHub([]), db_path=db, writes=False, now=datetime.now(timezone.utc) + timedelta(hours=3))
    assert ar.incidents(db_path=db)[0]["status"] == "open"


def test_pull_request_failures_are_ignored(tmp_path):
    gh = FakeGitHub([run(1)])
    ar.failed_runs(gh, now=NOW)
    assert ["-b", "main"] == gh.calls[0][4:6], "only main is watched; PR CI belongs to its author"


def test_a_change_that_comes_with_a_blocker_is_never_shipped(tmp_path):
    # 2026-11-13 smoke run: the model said it found no defect, added a test
    # anyway, and that test passed every check.
    db = str(tmp_path / "r.db")
    gh = FakeGitHub([run(1), run(2, 5)])
    shipped, verified = [], []

    def fixer(item, db_path):
        return {"run_id": "SOR-2", "profile": "testing/test-automation-engineer", "worktree": str(tmp_path / "wt"),
                "branch": "b", "files": ["tests/test_new.py"], "output": {"blockers": ["No defect was reproduced."]}}

    ar.tick(gh=gh, db_path=db, run_mode="merge", now=NOW, fixer=fixer,
            verifier=lambda *a: verified.append(1) or {"ok": True, "checks": [], "reason": ""},
            shipper=lambda *a, **k: shipped.append(1) or 1)
    item = ar.incidents(db_path=db)[0]
    assert shipped == [] and verified == [] and item["status"] == "open"
    assert "No defect was reproduced" in item["notes"][-1]["note"]


def test_only_tests_changed_waits_for_a_person():
    allowed, reasons = ar.merge_policy(["tests/test_x.py"], 5)
    assert not allowed and "only tests" in reasons[0]


def test_routing_keeps_code_fixes_with_code_specialists():
    assert ar.choose_profile({"error": "x"}, "engineering/backend-architect") == "engineering/backend-architect"
    assert ar.choose_profile({"error": "FAILED tests/a.py::t"}, "security/incident-responder") == "testing/test-automation-engineer"
    assert ar.choose_profile({"error": "deploy step failed"}, "security/incident-responder") == "engineering/devops-automator"


def _repo(tmp_path, source):
    import subprocess
    repo = tmp_path / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "calc.py").write_text(source)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "base", "--allow-empty"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base"], cwd=repo, check=True)
    return repo


def test_verification_requires_the_test_to_fail_without_the_fix(tmp_path):
    repo = _repo(tmp_path, "def add(a, b):\n    return a - b\n")
    (repo / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (repo / "tests" / "test_calc.py").write_text("from calc import add\n\n\ndef test_add():\n    assert add(2, 2) == 4\n")
    result = ar.verify(str(repo), ["calc.py", "tests/test_calc.py"])
    assert result["ok"], result
    assert {check["check"]: check["ok"] for check in result["checks"]}["fails_without_fix"] is True
    assert "a + b" in (repo / "calc.py").read_text(), "the fix is restored after the check"

    repo2 = _repo(tmp_path / "two", "def add(a, b):\n    return a + b\n")
    (repo2 / "calc.py").write_text("def add(a, b):\n    return b + a\n")
    (repo2 / "tests" / "test_calc.py").write_text("from calc import add\n\n\ndef test_add():\n    assert add(2, 2) == 4\n")
    result = ar.verify(str(repo2), ["calc.py", "tests/test_calc.py"])
    assert not result["ok"], "a test that passes on the original code does not prove the fix"
