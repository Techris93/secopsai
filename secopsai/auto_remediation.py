"""Find recurring SecOpsAI failures, fix them with a specialist, verify, ship.

One ``tick`` (run every 30 minutes by a LaunchAgent on the operator's Mac):

1. Detect: failed GitHub Actions runs on ``main`` become incidents, grouped by
   a fingerprint of workflow, failed step and normalized error line.
2. Triage: GitHub/runner outages and third-party upstream failures are
   ``external`` (recorded, never "fixed" in code). A defect is only worked on
   once it has recurred, so one-off flakes are not chased.
3. Fix: the agency-agents specialist the catalog routes the incident to runs
   in an isolated git worktree through the existing OpenCodex executor.
4. Verify: this module, not the model, runs the changed tests and CI's
   blocking lint on the worktree. Anything that fails is discarded.
5. Ship: a passing fix becomes a branch and pull request. In ``merge`` mode a
   low-risk fix merges itself once every CI check passes; anything touching a
   protected path, or without a test, waits for a person.
6. Confirm: a merged fix is resolved only after the failure stays away for
   48 hours; a recurrence reopens the incident. Two failed attempts hand the
   incident to a person.

Every incident is mirrored to a GitHub issue labelled ``auto-remediation``,
which is where the operator follows it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

REPO_SLUG = os.environ.get("SECOPSAI_REMEDIATION_REPO_SLUG", "Techris93/secopsai")
LABEL = "auto-remediation"
MODES = ("off", "observe", "pr", "merge")
MAX_ATTEMPTS = 2
RECURRENCE_THRESHOLD = 2
QUIET_HOURS_TO_RESOLVE = 48
DETECTION_HOURS = 24
MAX_FIX_FILES = 10
MAX_FIX_LINES = 400
# Changes here never merge themselves: CI and deploy definitions, hosted
# services, access control, schemas, the specialist roster and this module.
PROTECTED_PATHS = (
    ".github/", "cloudflare/", "apps/", "infra/", "deploy/", "scripts/install", "Dockerfile",
    "secopsai/auto_remediation.py", "secopsai/specialist_orchestrator.py", "secopsai/specialists/",
    "secopsai/codex_bridge.py", "secopsai/core_edge_client.py", "secopsai/research_delivery.py",
    "soc_store.py", "requirements", "pyproject.toml", "package.json", "package-lock.json",
)
SAFE_PREFIXES = ("secopsai/", "tests/", "scripts/", "docs/", "rules/", "auto_rules/")
FAILED_CONCLUSIONS = ("failure", "startup_failure", "timed_out")

# Outages outside SecOpsAI. No code change can fix these, so they are only
# recorded and checked again; the fix is to wait for the provider.
EXTERNAL_SIGNATURES = (
    ("github_actions_outage", r"An unexpected error has occurred and we've been automatically notified"),
    ("github_api_outage", r"(?:Server Error \(HTTP 5\d\d\)|HTTP 50[234]|502 Bad Gateway|503 Service Unavailable)"),
    ("runner_lost", r"(?:lost communication with the server|The runner has received a shutdown signal|The operation was canceled)"),
    ("upstream_source_down", r"enabled sources remain outside freshness targets"),
    # The watchdog reporting a failed worker run: the worker's own incident
    # carries the cause, so this one is never fixed separately.
    ("downstream_of_worker", r'"root_cause": "Research Worker run \d+ concluded'),
    ("upstream_timeout", r"(?:Read timed out|Connection timed out|Temporary failure in name resolution|ConnectTimeout)"),
)
_NOISE = (
    (re.compile(r"\d{4}-\d{2}-\d{2}T[\d:.]+Z?"), "<time>"),
    (re.compile(r"\b[0-9a-f]{7,64}\b"), "<hex>"),
    (re.compile(r"\b\d+(?:\.\d+)?\b"), "<n>"),
    (re.compile(r"/(?:home|Users|tmp|private)/\S+"), "<path>"),
    (re.compile(r"\s+"), " "),
)
SECRETISH = re.compile(r"(?i)(token|secret|password|authorization|api[_-]?key)(\W{1,3})\S+")
ERROR_LINE = re.compile(r"(?:##\[error\]|Error:|ERROR|FAILED |AssertionError|Traceback|error:|failed with|exit code [1-9])")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _parse(value: str) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def mode() -> str:
    value = os.environ.get("SECOPSAI_AUTO_REMEDIATION", "observe").strip().lower()
    return value if value in MODES else "observe"


# --- store --------------------------------------------------------------------

def default_db_path() -> str:
    configured = os.environ.get("SECOPSAI_REMEDIATION_DB", "").strip()
    if configured:
        return str(Path(configured).expanduser())
    return str(Path(__file__).resolve().parents[1] / "data" / "remediation" / "remediation.db")


def _connect(db_path: Optional[str]) -> sqlite3.Connection:
    path = Path(db_path or default_db_path())
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(path))
    connection.row_factory = sqlite3.Row
    connection.execute("""CREATE TABLE IF NOT EXISTS remediation_incidents (
        incident_id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, workflow TEXT NOT NULL,
        step TEXT NOT NULL, error TEXT NOT NULL, kind TEXT NOT NULL, status TEXT NOT NULL,
        occurrences INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
        run_ids TEXT NOT NULL DEFAULT '[]', excerpt TEXT NOT NULL DEFAULT '',
        issue_number INTEGER, pr_number INTEGER, branch TEXT, specialist_run_id TEXT,
        merged_at TEXT, notes TEXT NOT NULL DEFAULT '[]',
        first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    connection.execute("""CREATE TABLE IF NOT EXISTS remediation_seen_runs (
        run_id INTEGER PRIMARY KEY, incident_id TEXT, seen_at TEXT NOT NULL)""")
    return connection


def incidents(*, db_path: Optional[str] = None, status: str = "") -> List[Dict[str, Any]]:
    with closing(_connect(db_path)) as connection:
        rows = connection.execute(
            "SELECT * FROM remediation_incidents WHERE (?='' OR status=?) ORDER BY last_seen DESC", (status, status)).fetchall()
    return [{**dict(row), "run_ids": json.loads(row["run_ids"]), "notes": json.loads(row["notes"])} for row in rows]


def _update(incident_id: str, db_path: Optional[str], note: str = "", **fields: Any) -> None:
    with closing(_connect(db_path)) as connection:
        if note:
            notes = json.loads(connection.execute("SELECT notes FROM remediation_incidents WHERE incident_id=?",
                                                  (incident_id,)).fetchone()["notes"])
            fields["notes"] = json.dumps((notes + [{"at": _iso(_now()), "note": note[:1000]}])[-30:])
        fields["updated_at"] = _iso(_now())
        connection.execute(f"UPDATE remediation_incidents SET {', '.join(f'{key}=?' for key in fields)} WHERE incident_id=?",
                           (*fields.values(), incident_id))
        connection.commit()


# --- detect and triage --------------------------------------------------------

def normalize(line: str) -> str:
    text = str(line or "")
    for pattern, replacement in _NOISE:
        text = pattern.sub(replacement, text)
    return text.strip()[:300]


def error_line(log: str) -> str:
    """The first line that names the failure, skipping GitHub's generic exit line."""
    lines = [re.sub(r"^\S*\t\S[^\t]*\t", "", line).strip() for line in str(log or "").splitlines()]
    lines = [re.sub(r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s*", "", line) for line in lines]
    lines = [line for line in lines if not line.startswith("##[warning]") and "is deprecated" not in line]
    # A JSON root cause (watchdog, delivery check) names the failure best.
    root = next((match.group(1) for line in lines for match in [re.search(r'"root_cause": "([^"]+)"', line)] if match), "")
    if root:
        return SECRETISH.sub(r"\1\2[redacted]", root)[:500]
    blockers = next((match.group(1) for line in lines for match in [re.search(r'"delivery_blockers": \["([^"]+)"', line)] if match), "")
    if blockers:
        return SECRETISH.sub(r"\1\2[redacted]", blockers)[:500]
    specific = [line for line in lines if ERROR_LINE.search(line) and "Process completed with exit code" not in line]
    chosen = specific[0] if specific else next((line for line in reversed(lines) if line), "")
    return SECRETISH.sub(r"\1\2[redacted]", chosen)[:500]


def classify(log: str, conclusion: str) -> str:
    if conclusion == "startup_failure":
        return "external:github_actions_outage"
    for name, pattern in EXTERNAL_SIGNATURES:
        if re.search(pattern, log or ""):
            return "external:" + name
    return "defect"


def fingerprint(workflow: str, step: str, error: str) -> str:
    return hashlib.sha256(f"{workflow}\x00{step}\x00{normalize(error)}".encode()).hexdigest()[:20]


def _excerpt(log: str, error: str, size: int = 60) -> str:
    lines = str(log or "").splitlines()
    index = next((i for i, line in enumerate(lines) if error and error[:60] in line), len(lines) - 1)
    window = lines[max(0, index - size // 2): index + size // 2]
    return SECRETISH.sub(r"\1\2[redacted]", "\n".join(window))[-6000:]


def record_failure(run: Dict[str, Any], log: str, *, db_path: Optional[str] = None,
                   now: Optional[datetime] = None) -> Dict[str, Any]:
    """Turn one failed run into a new or recurring incident."""
    current = now or _now()
    workflow = str(run.get("workflowName") or run.get("name") or "")
    step = str(run.get("failed_step") or "")
    error = error_line(log) or str(run.get("conclusion") or "failure")
    kind = classify(log, str(run.get("conclusion") or ""))
    key = fingerprint(workflow, step, error)
    with closing(_connect(db_path)) as connection:
        row = connection.execute("SELECT * FROM remediation_incidents WHERE fingerprint=?", (key,)).fetchone()
        stamp = _iso(current)
        if row is None:
            incident_id = "INC-" + key[:12].upper()
            connection.execute(
                """INSERT INTO remediation_incidents (incident_id, fingerprint, workflow, step, error, kind, status,
                   occurrences, run_ids, excerpt, first_seen, last_seen, updated_at)
                   VALUES (?,?,?,?,?,?,?,1,?,?,?,?,?)""",
                (incident_id, key, workflow, step, error, kind, "external" if kind != "defect" else "watching",
                 json.dumps([run["databaseId"]]), _excerpt(log, error), stamp, stamp, stamp))
        else:
            incident_id = row["incident_id"]
            run_ids = (json.loads(row["run_ids"]) + [run["databaseId"]])[-20:]
            status = row["status"]
            # A merged fix that fails again goes back to work, with the new evidence.
            if status in {"verifying", "resolved"}:
                status = "open" if row["attempts"] < MAX_ATTEMPTS else "needs_human"
            connection.execute(
                """UPDATE remediation_incidents SET occurrences=occurrences+1, run_ids=?, last_seen=?, status=?,
                   excerpt=?, updated_at=? WHERE incident_id=?""",
                (json.dumps(run_ids), stamp, status, _excerpt(log, error), stamp, incident_id))
        connection.execute("INSERT OR IGNORE INTO remediation_seen_runs (run_id, incident_id, seen_at) VALUES (?,?,?)",
                           (run["databaseId"], incident_id, stamp))
        connection.commit()
    return next(item for item in incidents(db_path=db_path) if item["incident_id"] == incident_id)


def promote_recurring(*, db_path: Optional[str] = None) -> List[str]:
    """A defect is worked on only after it recurs; one failure may be a flake."""
    promoted = []
    for item in incidents(db_path=db_path, status="watching"):
        if item["kind"] == "defect" and item["occurrences"] >= RECURRENCE_THRESHOLD:
            _update(item["incident_id"], db_path, status="open",
                    note=f"Recurred {item['occurrences']} times; queued for a specialist fix.")
            promoted.append(item["incident_id"])
    return promoted


# --- GitHub -------------------------------------------------------------------

Runner = Callable[[Sequence[str], Optional[str]], str]


def gh_runner(args: Sequence[str], stdin: Optional[str] = None, *, cwd: Optional[str] = None) -> str:
    completed = subprocess.run(["gh", *args], input=stdin, capture_output=True, text=True, timeout=180, cwd=cwd)
    if completed.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args[:3])} failed: {(completed.stderr or completed.stdout).strip()[:500]}")
    return completed.stdout


def failed_runs(gh: Runner, *, hours: int = DETECTION_HOURS, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Failed runs on main in the window. Pull request CI is left to its author."""
    since = (now or _now()) - timedelta(hours=hours)
    raw = gh(["run", "list", "-R", REPO_SLUG, "-b", "main", "-L", "200", "--json",
              "databaseId,workflowName,conclusion,createdAt,event,headSha"], None)
    return [run for run in json.loads(raw or "[]")
            if run.get("conclusion") in FAILED_CONCLUSIONS and _parse(run["createdAt"]) >= since]


def failed_log(gh: Runner, run: Dict[str, Any]) -> tuple[str, str]:
    """The first failed job's failed step and its log (the API log is complete; ``gh run view --log`` truncates)."""
    if run.get("conclusion") == "startup_failure":
        return "startup", "An unexpected error has occurred and we've been automatically notified (startup_failure)"
    jobs = json.loads(gh(["api", f"repos/{REPO_SLUG}/actions/runs/{run['databaseId']}/jobs"], None) or "{}").get("jobs", [])
    job = next((item for item in jobs if item.get("conclusion") in FAILED_CONCLUSIONS), None)
    if job is None:
        return "", ""
    step = next((item.get("name", "") for item in job.get("steps", []) if item.get("conclusion") in FAILED_CONCLUSIONS), "")
    try:
        log = gh(["api", f"repos/{REPO_SLUG}/actions/jobs/{job['id']}/logs"], None)
    except RuntimeError as exc:
        log = str(exc)
    return f"{job.get('name', '')} / {step}".strip(" /"), log[-400_000:]


def _issue_body(item: Dict[str, Any]) -> str:
    runs = ", ".join(f"[{run_id}](https://github.com/{REPO_SLUG}/actions/runs/{run_id})" for run_id in item["run_ids"][-5:])
    return (f"Auto-remediation incident `{item['incident_id']}`\n\n"
            f"- Workflow: {item['workflow']}\n- Failed step: {item['step'] or 'n/a'}\n- Kind: {item['kind']}\n"
            f"- Occurrences: {item['occurrences']} (first {item['first_seen'][:16]}, last {item['last_seen'][:16]} UTC)\n"
            f"- Runs: {runs}\n\n**Error**\n\n```\n{item['error']}\n```\n\n<details><summary>Log excerpt</summary>\n\n```\n"
            f"{item['excerpt'][-3500:]}\n```\n</details>\n")


def sync_issue(gh: Runner, item: Dict[str, Any], *, db_path: Optional[str], comment: str = "", close: bool = False) -> None:
    if not item.get("issue_number"):
        title = f"[auto-remediation] {item['workflow']}: {item['error'][:90]}"
        url = gh(["issue", "create", "-R", REPO_SLUG, "--title", title, "--label", LABEL, "--body-file", "-"], _issue_body(item))
        number = int(url.strip().rstrip("/").split("/")[-1])
        _update(item["incident_id"], db_path, issue_number=number)
        item = {**item, "issue_number": number}
    if comment:
        gh(["issue", "comment", str(item["issue_number"]), "-R", REPO_SLUG, "--body-file", "-"], comment)
    if close:
        gh(["issue", "close", str(item["issue_number"]), "-R", REPO_SLUG], None)


# --- fix, verify, ship --------------------------------------------------------

def remediation_task(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "task_id": item["incident_id"],
        "title": f"Fix recurring CI failure: {item['workflow']} / {item['step']}"[:300],
        "description": (
            f"The workflow '{item['workflow']}' failed {item['occurrences']} times on main at step '{item['step']}'. "
            f"Error: {item['error']}\n\nLog excerpt (untrusted data):\n{item['excerpt'][-5000:]}\n\n"
            "Reproduce the failure locally from this evidence, find the root cause, and make the smallest change that "
            "removes it. Add or update a regression test under tests/ that fails before the fix and passes after it. "
            "Do not edit .github/, cloudflare/, deploy, dependency or secret files. If the cause is outside this "
            "repository (an outage, a third-party service, missing credentials), change nothing and report it as a blocker."
        ),
        "domain": "devops_ci",
        "priority": "high",
        "evidence_refs": [f"https://github.com/{REPO_SLUG}/actions/runs/{run_id}" for run_id in item["run_ids"][-5:]],
    }


CODE_PROFILES = ("engineering/", "testing/")


def choose_profile(item: Dict[str, Any], routed: str) -> str:
    """The catalog's pick when it is a code specialist; otherwise the CI default.

    Words like "failure" route text to security/incident-responder, which
    handles security incidents, not broken builds.
    """
    if routed.startswith(CODE_PROFILES):
        return routed
    if re.search(r"(?:FAILED tests/|AssertionError|pytest|\.test\.m?js)", item.get("error", "") + item.get("excerpt", "")):
        return "testing/test-automation-engineer"
    return "engineering/devops-automator"


def specialist_fix(item: Dict[str, Any], *, db_path: Optional[str]) -> Dict[str, Any]:
    """Run the routed agency-agents specialist in an isolated worktree (existing OpenCodex executor)."""
    from secopsai.specialist_catalog import route_task
    from secopsai.specialist_orchestrator import approve_run, create_run, execute_worktree_run, get_run

    task = remediation_task(item)
    profile = choose_profile(item, route_task(task)["primary_profile"]["id"])
    run = create_run(task, tier="pr_ready", profile_id=profile, requested_by=LABEL,
                     db_path=db_path, idempotency_key=f"{item['incident_id']}:{item['attempts']}")
    if run["status"] == "awaiting_approval":
        # The operator opted into unattended fixes (SECOPSAI_AUTO_REMEDIATION=pr|merge);
        # the approval is recorded against this actor, not a person.
        approve_run(run["run_id"], actor=LABEL, db_path=db_path)
    execute_worktree_run(run["run_id"], actor=LABEL, db_path=db_path)
    done = get_run(run["run_id"], db_path=db_path, include_local_paths=True)
    return {"run_id": run["run_id"], "profile": profile, "worktree": done["worktree"].get("path"),
            "branch": (done.get("result") or {}).get("git", {}).get("branch"),
            "files": (done.get("result") or {}).get("git", {}).get("files_changed", []),
            "output": (done.get("result") or {}).get("output", {})}


def merge_policy(files: Sequence[str], added_lines: int) -> tuple[bool, List[str]]:
    """Whether a verified fix may merge itself, and why not."""
    reasons = []
    protected = [path for path in files if any(path.startswith(prefix) or path == prefix for prefix in PROTECTED_PATHS)]
    if protected:
        reasons.append("touches protected paths: " + ", ".join(protected[:5]))
    outside = [path for path in files if not path.startswith(SAFE_PREFIXES)]
    if outside:
        reasons.append("changes files outside code, tests and docs: " + ", ".join(outside[:5]))
    if not any(path.startswith("tests/") for path in files):
        reasons.append("adds no regression test")
    elif all(path.startswith("tests/") for path in files):
        reasons.append("changes only tests, so a person checks it addresses the failure")
    if len(files) > MAX_FIX_FILES:
        reasons.append(f"changes {len(files)} files (limit {MAX_FIX_FILES})")
    if added_lines > MAX_FIX_LINES:
        reasons.append(f"changes {added_lines} lines (limit {MAX_FIX_LINES})")
    return not reasons, reasons


def verify(worktree: str, files: Sequence[str], *, run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> Dict[str, Any]:
    """Checks run by this module on the worktree; the model's own claims are not trusted."""
    python = sys.executable
    environment = {**os.environ, "PYTHONPATH": worktree}
    checks = []
    tests = sorted({path for path in files if path.startswith("tests/") and path.endswith(".py")})
    if tests:
        checks.append(("tests", [python, "-m", "pytest", "-q", "-x", *tests]))
    py_files = [path for path in files if path.endswith(".py") and Path(worktree, path).exists()]
    if py_files:
        checks.append(("lint", [python, "-m", "flake8", "--select=E9,F63,F7,F82", *py_files]))
        checks.append(("compile", [python, "-m", "py_compile", *py_files]))
    results = []
    for name, command in checks:
        completed = run(command, cwd=worktree, env=environment, capture_output=True, text=True, timeout=1200)
        results.append({"check": name, "ok": completed.returncode == 0,
                        "output": (completed.stdout + completed.stderr)[-3000:]})
    code = [path for path in files if not path.startswith("tests/")]
    if tests and code and all(item["ok"] for item in results):
        results.append(_fails_without_fix(worktree, code, [python, "-m", "pytest", "-q", "-x", *tests], environment, run))
    reason = "" if tests else "no test file was changed, so the fix cannot be verified"
    return {"ok": bool(tests) and all(item["ok"] for item in results), "checks": results, "reason": reason}


def _fails_without_fix(worktree: str, code: Sequence[str], command: List[str], environment: Dict[str, str],
                       run: Callable[..., subprocess.CompletedProcess]) -> Dict[str, Any]:
    """The new tests must fail on the original code, or they do not prove the fix.

    The changed code files are put back to the base commit, the tests run, and
    the fix is restored. No stash is used: the stash is shared across worktrees.
    """
    saved = {path: Path(worktree, path).read_bytes() if Path(worktree, path).exists() else None for path in code}
    try:
        for path in code:
            original = run(["git", "show", f"HEAD:{path}"], cwd=worktree, capture_output=True, timeout=60)
            target = Path(worktree, path)
            if original.returncode == 0:
                target.write_bytes(original.stdout if isinstance(original.stdout, bytes) else str(original.stdout).encode())
            elif target.exists():
                target.unlink()  # a new file did not exist before the fix
        before = run(command, cwd=worktree, env=environment, capture_output=True, text=True, timeout=1200)
    finally:
        for path, content in saved.items():
            target = Path(worktree, path)
            if content is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(content)
    return {"check": "fails_without_fix", "ok": before.returncode != 0,
            "output": "the tests failed on the original code, as they should" if before.returncode != 0
            else "the tests also pass on the original code, so they do not show the fix works"}


def _git(args: Sequence[str], cwd: str) -> str:
    completed = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=180)
    if completed.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {(completed.stderr or completed.stdout).strip()[:500]}")
    return completed.stdout


def ship(item: Dict[str, Any], fix: Dict[str, Any], verification: Dict[str, Any], *, gh: Runner, git=_git) -> int:
    """Commit the verified worktree, push it, and open the pull request."""
    worktree, branch = fix["worktree"], fix["branch"]
    git(["add", "-A"], worktree)
    summary = str(fix["output"].get("summary") or "fix recurring CI failure").splitlines()[0][:72]
    git(["commit", "-m", f"auto-remediation: {summary}", "-m",
         f"Incident {item['incident_id']}: {item['workflow']} / {item['step']}.\n{item['error'][:300]}"], worktree)
    git(["push", "-u", "origin", branch], worktree)
    checks = "\n".join(f"- {check['check']}: {'passed' if check['ok'] else 'failed'}" for check in verification["checks"])
    body = (f"Automatic fix for incident `{item['incident_id']}` (#{item['issue_number']}) by `{fix['profile']}`.\n\n"
            f"**Failure:** {item['workflow']} / {item['step']}: `{item['error'][:300]}`\n\n"
            f"**Specialist summary:** {str(fix['output'].get('summary') or '')[:3000]}\n\n"
            f"**Verified on the worktree before opening:**\n{checks}\n\n"
            f"Closes #{item['issue_number']} only after the failure stays away for {QUIET_HOURS_TO_RESOLVE} hours.")
    url = gh(["pr", "create", "-R", REPO_SLUG, "--base", "main", "--head", branch,
              "--title", f"auto-remediation: {summary}", "--label", LABEL, "--body-file", "-"], body)
    return int(url.strip().rstrip("/").split("/")[-1])


def _cleanup(fix: Dict[str, Any]) -> None:
    """Remove the worktree once its branch is pushed (or the attempt failed)."""
    path = fix.get("worktree")
    if path and Path(path).exists():
        repo = str(Path(__file__).resolve().parents[1])
        subprocess.run(["git", "worktree", "remove", "--force", path], cwd=repo, capture_output=True, timeout=60)
        shutil.rmtree(path, ignore_errors=True)
        subprocess.run(["git", "worktree", "prune"], cwd=repo, capture_output=True, timeout=60)


def work_on(item: Dict[str, Any], *, gh: Runner, db_path: Optional[str], fixer=specialist_fix,
            verifier=verify, shipper=ship) -> str:
    """One fix attempt for an open defect. Returns the incident's new status."""
    attempt = item["attempts"] + 1
    _update(item["incident_id"], db_path, attempts=attempt, status="fixing", note=f"Attempt {attempt} started.")
    fix: Dict[str, Any] = {}
    try:
        fix = fixer(item, db_path=db_path)
        _update(item["incident_id"], db_path, specialist_run_id=fix["run_id"])
        blockers = [str(value) for value in fix["output"].get("blockers") or [] if str(value).strip()]
        # A change that comes with a blocker is the model saying it did not
        # find the defect; it is never shipped, however clean it looks.
        if not fix["files"] or blockers:
            status = "needs_human" if attempt >= MAX_ATTEMPTS else "open"
            reason = "; ".join(blockers) or "the specialist made no change"
            _update(item["incident_id"], db_path, status=status, note=f"No fix shipped: {reason[:900]}")
            sync_issue(gh, item, db_path=db_path, comment=f"Attempt {attempt} ({fix['profile']}): nothing shipped. {reason[:1500]}")
            return status
        verification = verifier(fix["worktree"], fix["files"])
        if not verification["ok"]:
            failed = verification["reason"] or "; ".join(check["check"] for check in verification["checks"] if not check["ok"])
            status = "needs_human" if attempt >= MAX_ATTEMPTS else "open"
            _update(item["incident_id"], db_path, status=status, note=f"Fix discarded, verification failed: {failed}")
            sync_issue(gh, item, db_path=db_path, comment=f"Attempt {attempt}: fix discarded, verification failed ({failed}).")
            return status
        pr = shipper(item, fix, verification, gh=gh)
        _update(item["incident_id"], db_path, status="pr_open", pr_number=pr, branch=fix["branch"],
                note=f"PR #{pr} opened after verification passed.")
        sync_issue(gh, item, db_path=db_path, comment=f"Attempt {attempt}: verified fix opened as #{pr}.")
        return "pr_open"
    except Exception as exc:  # noqa: BLE001 - every failure is recorded on the incident
        status = "needs_human" if attempt >= MAX_ATTEMPTS else "open"
        _update(item["incident_id"], db_path, status=status, note=f"Attempt {attempt} failed: {type(exc).__name__}: {str(exc)[:600]}")
        return status
    finally:
        _cleanup(fix)


def follow_pr(item: Dict[str, Any], *, gh: Runner, db_path: Optional[str], run_mode: str) -> str:
    """Merge a green, low-risk fix; close a red one and count the attempt."""
    raw = json.loads(gh(["pr", "view", str(item["pr_number"]), "-R", REPO_SLUG, "--json",
                         "state,files,additions,statusCheckRollup"], None))
    if raw["state"] == "MERGED":
        _update(item["incident_id"], db_path, status="verifying", merged_at=_iso(_now()), note="PR merged.")
        return "verifying"
    if raw["state"] == "CLOSED":
        status = "needs_human" if item["attempts"] >= MAX_ATTEMPTS else "open"
        _update(item["incident_id"], db_path, status=status, note="PR closed without merging.")
        return status
    checks = raw.get("statusCheckRollup") or []
    states = [str(check.get("conclusion") or check.get("state") or "").upper() for check in checks]
    if not checks or any(state in {"", "PENDING", "IN_PROGRESS", "QUEUED", "EXPECTED"} for state in states):
        return "pr_open"
    if any(state in {"FAILURE", "ERROR", "CANCELLED", "TIMED_OUT", "ACTION_REQUIRED", "STARTUP_FAILURE"} for state in states):
        gh(["pr", "close", str(item["pr_number"]), "-R", REPO_SLUG, "--delete-branch", "--comment",
            "CI failed on the automatic fix; closing it. The incident goes back for another attempt."], None)
        status = "needs_human" if item["attempts"] >= MAX_ATTEMPTS else "open"
        _update(item["incident_id"], db_path, status=status, note=f"CI failed on PR #{item['pr_number']}; closed.")
        sync_issue(gh, item, db_path=db_path, comment=f"CI failed on #{item['pr_number']}; closed it.")
        return status
    allowed, reasons = merge_policy([file["path"] for file in raw.get("files") or []], int(raw.get("additions") or 0))
    if run_mode != "merge" or not allowed:
        why = "merge mode is off" if run_mode != "merge" else "; ".join(reasons)
        if not any("waiting for a person" in note["note"] for note in item["notes"]):
            _update(item["incident_id"], db_path, note=f"CI passed; waiting for a person to merge ({why}).")
            sync_issue(gh, item, db_path=db_path, comment=f"CI passed on #{item['pr_number']}. Waiting for a person to merge: {why}.")
        return "pr_open"
    gh(["pr", "merge", str(item["pr_number"]), "-R", REPO_SLUG, "--squash", "--delete-branch"], None)
    _update(item["incident_id"], db_path, status="verifying", merged_at=_iso(_now()),
            note=f"CI passed; PR #{item['pr_number']} merged automatically.")
    sync_issue(gh, item, db_path=db_path,
               comment=f"CI passed; merged #{item['pr_number']}. Watching for {QUIET_HOURS_TO_RESOLVE} hours before closing.")
    return "verifying"


def confirm(item: Dict[str, Any], *, gh: Runner, db_path: Optional[str], now: Optional[datetime] = None) -> str:
    """Resolve a merged fix once the failure has stayed away long enough."""
    current = now or _now()
    quiet_since = max(_parse(item["merged_at"]), _parse(item["last_seen"])) if item.get("merged_at") else current
    if current - quiet_since < timedelta(hours=QUIET_HOURS_TO_RESOLVE):
        return "verifying"
    _update(item["incident_id"], db_path, status="resolved", note=f"No recurrence for {QUIET_HOURS_TO_RESOLVE} hours.")
    sync_issue(gh, item, db_path=db_path, comment=f"No recurrence for {QUIET_HOURS_TO_RESOLVE} hours after the fix; resolved.",
               close=True)
    return "resolved"


def housekeeping(*, gh: Runner, db_path: Optional[str], writes: bool, now: Optional[datetime] = None) -> List[str]:
    """Unstick interrupted fixes, close ended outages, expire one-off failures."""
    current = now or _now()
    actions = []
    for item in incidents(db_path=db_path, status="fixing"):
        if current - _parse(item["updated_at"]) > timedelta(hours=2):
            status = "needs_human" if item["attempts"] >= MAX_ATTEMPTS else "open"
            _update(item["incident_id"], db_path, status=status, note="The fix attempt was interrupted; returned to the queue.")
            actions.append(f"{item['incident_id']}: unstuck to {status}")
    for item in incidents(db_path=db_path, status="external"):
        if current - _parse(item["last_seen"]) > timedelta(hours=24):
            _update(item["incident_id"], db_path, status="resolved", note="No recurrence for 24 hours; the outage ended.")
            if writes and item.get("issue_number"):
                sync_issue(gh, item, db_path=db_path, comment="No recurrence for 24 hours; the outage has ended.", close=True)
            actions.append(f"{item['incident_id']}: outage ended")
    for item in incidents(db_path=db_path, status="watching"):
        if current - _parse(item["last_seen"]) > timedelta(days=7):
            _update(item["incident_id"], db_path, status="expired", note="Did not recur within 7 days.")
            actions.append(f"{item['incident_id']}: expired")
    return actions


def ensure_label(gh: Runner) -> None:
    try:
        gh(["label", "create", LABEL, "-R", REPO_SLUG, "--color", "B60205",
            "--description", "Found and handled by SecOpsAI auto-remediation"], None)
    except RuntimeError:
        pass  # it already exists


# --- tick ---------------------------------------------------------------------

def tick(*, gh: Runner = gh_runner, db_path: Optional[str] = None, run_mode: Optional[str] = None,
         now: Optional[datetime] = None, fixer=specialist_fix, verifier=verify, shipper=ship) -> Dict[str, Any]:
    """One pass: detect, triage, follow open work, start at most one new fix."""
    current_mode = run_mode or mode()
    summary: Dict[str, Any] = {"mode": current_mode, "new_failures": 0, "incidents": {}, "actions": []}
    if current_mode == "off":
        return summary
    writes = current_mode != "observe"
    if writes:
        ensure_label(gh)
    with closing(_connect(db_path)) as connection:
        seen = {row[0] for row in connection.execute("SELECT run_id FROM remediation_seen_runs")}
    for run in failed_runs(gh, now=now):
        if run["databaseId"] in seen:
            continue
        step, log = failed_log(gh, run)
        item = record_failure({**run, "failed_step": step}, log, db_path=db_path, now=now)
        summary["new_failures"] += 1
        if writes and (item["occurrences"] >= RECURRENCE_THRESHOLD or item["kind"] != "defect") and not item.get("issue_number"):
            sync_issue(gh, item, db_path=db_path)
    summary["actions"] += [f"promoted {incident}" for incident in promote_recurring(db_path=db_path)]
    summary["actions"] += housekeeping(gh=gh, db_path=db_path, writes=writes, now=now)
    if writes:
        for item in incidents(db_path=db_path, status="pr_open"):
            summary["actions"].append(f"{item['incident_id']}: {follow_pr(item, gh=gh, db_path=db_path, run_mode=current_mode)}")
        for item in incidents(db_path=db_path, status="verifying"):
            summary["actions"].append(f"{item['incident_id']}: {confirm(item, gh=gh, db_path=db_path, now=now)}")
        # One new fix per tick keeps the bridge and CI from being flooded.
        candidates = [item for item in incidents(db_path=db_path, status="open") if item["kind"] == "defect"]
        if candidates and not incidents(db_path=db_path, status="fixing"):
            item = candidates[-1]
            if not item.get("issue_number"):
                sync_issue(gh, item, db_path=db_path)
                item = next(entry for entry in incidents(db_path=db_path) if entry["incident_id"] == item["incident_id"])
            summary["actions"].append(f"{item['incident_id']}: {work_on(item, gh=gh, db_path=db_path, fixer=fixer, verifier=verifier, shipper=shipper)}")
    for item in incidents(db_path=db_path):
        summary["incidents"][item["status"]] = summary["incidents"].get(item["status"], 0) + 1
    return summary
