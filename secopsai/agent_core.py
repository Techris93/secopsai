from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from secopsai.sessions import load_session


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JOB_DIR = ROOT / "data" / "agent_jobs"
VALID_TOOL_MODES = {"read", "write", "expensive"}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def stable_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    mode: str = "read"
    description: str = ""
    keywords: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.mode not in VALID_TOOL_MODES:
            raise ValueError(f"invalid tool mode: {self.mode}")


class ToolRouter:
    """Routes an operator intent to read/write/expensive tools with explicit gates."""

    def __init__(self, tools: Optional[Iterable[ToolSpec]] = None) -> None:
        self.tools: Dict[str, ToolSpec] = {}
        for tool in tools or default_tools():
            self.register(tool)

    def register(self, tool: ToolSpec) -> None:
        self.tools[tool.name] = tool

    def route(
        self,
        task: str,
        *,
        allow_writes: bool = False,
        allow_expensive: bool = False,
    ) -> Dict[str, Any]:
        lowered = str(task or "").lower()
        candidates: List[Dict[str, Any]] = []
        blocked: List[Dict[str, Any]] = []
        for tool in self.tools.values():
            score = sum(1 for keyword in tool.keywords if keyword.lower() in lowered)
            if score <= 0:
                continue
            row = {"tool": asdict(tool), "score": score}
            if tool.mode == "write" and not allow_writes:
                blocked.append({**row, "reason": "write_gate"})
            elif tool.mode == "expensive" and not allow_expensive:
                blocked.append({**row, "reason": "expensive_gate"})
            else:
                candidates.append(row)
        candidates.sort(key=lambda item: (-int(item["score"]), item["tool"]["name"]))
        blocked.sort(key=lambda item: (-int(item["score"]), item["tool"]["name"]))
        return {
            "task": task,
            "allow_writes": allow_writes,
            "allow_expensive": allow_expensive,
            "selected": candidates,
            "blocked": blocked,
        }


def default_tools() -> List[ToolSpec]:
    return [
        ToolSpec(
            "research.preflight",
            "read",
            "Inspect freshness, schema, source coverage, replay health, and intel readiness.",
            ["preflight", "freshness", "stale", "schema", "coverage", "replay", "health"],
        ),
        ToolSpec(
            "research.finding",
            "read",
            "Build a source-backed finding report.",
            ["finding", "investigate", "source", "research", "cve", "ghsa", "kev"],
        ),
        ToolSpec(
            "research.package",
            "read",
            "Build a source-backed package or release report.",
            ["package", "release", "pypi", "npm", "supply-chain", "registry"],
        ),
        ToolSpec(
            "triage.request_approval",
            "write",
            "Request approval for a close decision or queued triage action.",
            ["approve", "approval", "close", "apply", "action", "allowlist"],
        ),
        ToolSpec(
            "triage.resolve_approval",
            "write",
            "Resolve and optionally apply an approved session action.",
            ["resolve", "approved", "apply", "close", "decision"],
        ),
        ToolSpec(
            "experiments.run_job",
            "expensive",
            "Run isolated adaptive-intel, replay, or regression experiments.",
            ["experiment", "adaptive", "replay", "regression", "benchmark", "train", "sweep"],
        ),
    ]


class DoomLoopDetector:
    def __init__(self, threshold: int = 3) -> None:
        self.threshold = threshold

    @staticmethod
    def signature(event: Dict[str, Any]) -> str:
        text = "|".join(
            str(event.get(key) or "")
            for key in ("type", "message", "tool", "command", "status")
        )
        return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]

    def analyze(self, events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
        streak = 0
        previous = None
        repeated: List[Dict[str, Any]] = []
        for event in events:
            sig = self.signature(event)
            streak = streak + 1 if sig == previous else 1
            previous = sig
            if streak >= self.threshold:
                repeated.append({"signature": sig, "streak": streak, "event": event})
        return {
            "ok": not repeated,
            "threshold": self.threshold,
            "repeated": repeated,
            "summary": "No doom-loop pattern found." if not repeated else "Repeated agent pattern detected.",
        }


def compact_session_context(
    session_id: str,
    *,
    session_dir: Optional[str] = None,
    max_events: int = 12,
    max_artifacts: int = 12,
) -> Dict[str, Any]:
    session = load_session(session_id, session_dir)
    events = session.get("events") if isinstance(session.get("events"), list) else []
    artifacts = session.get("artifacts") if isinstance(session.get("artifacts"), list) else []
    plan = session.get("plan") if isinstance(session.get("plan"), list) else []
    approvals = session.get("approvals") if isinstance(session.get("approvals"), list) else []
    pending = [item for item in approvals if str(item.get("state") or "").lower() == "pending"]
    completed_steps = [item for item in plan if str(item.get("status") or "").lower() == "completed"]
    summary = {
        "session_id": session.get("session_id"),
        "kind": session.get("kind"),
        "status": session.get("status"),
        "title": session.get("title"),
        "subject": session.get("subject") or {},
        "progress": {
            "plan_total": len(plan),
            "plan_completed": len(completed_steps),
            "pending_approvals": len(pending),
            "artifact_count": len(artifacts),
            "event_count": len(events),
        },
        "plan": plan,
        "pending_approvals": pending,
        "recent_events": events[-max_events:],
        "recent_artifacts": artifacts[-max_artifacts:],
    }
    summary["doom_loop"] = DoomLoopDetector().analyze(summary["recent_events"])
    return summary


def job_dir(path: Optional[str] = None) -> Path:
    return Path(path).expanduser().resolve() if path else DEFAULT_JOB_DIR


def _safe_command(command: List[str]) -> None:
    if not command:
        raise ValueError("job command is required")
    executable = Path(command[0]).name
    if executable not in {"secopsai", "python", "python3"}:
        raise ValueError("agent jobs only allow secopsai/python commands by default")
    allowed_python_targets = ("secopsai", "evaluate.py", "scripts/docs_source_agent.py", "scripts/verify_docs_examples.py")
    if executable.startswith("python") and not any(any(target in part for target in allowed_python_targets) for part in command[1:]):
        raise ValueError("python jobs must target SecOpsAI modules or evaluate.py")


def run_isolated_job(
    *,
    name: str,
    command: List[str],
    cwd: Optional[str] = None,
    timeout: int = 900,
    path: Optional[str] = None,
) -> Dict[str, Any]:
    _safe_command(command)
    root = job_dir(path)
    root.mkdir(parents=True, exist_ok=True)
    job_id = stable_id("JOB")
    target = root / job_id
    target.mkdir(parents=True, exist_ok=False)
    started_at = utc_now()
    env = os.environ.copy()
    env["SECOPSAI_AGENT_JOB_ID"] = job_id
    env["SECOPSAI_AGENT_JOB_DIR"] = str(target)
    result = subprocess.run(
        command,
        cwd=str(Path(cwd).expanduser().resolve()) if cwd else str(ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env=env,
    )
    ended_at = utc_now()
    (target / "stdout.log").write_text(result.stdout, encoding="utf-8")
    (target / "stderr.log").write_text(result.stderr, encoding="utf-8")
    payload = {
        "job_id": job_id,
        "name": name,
        "command": command,
        "cwd": str(Path(cwd).expanduser().resolve()) if cwd else str(ROOT),
        "status": "completed" if result.returncode == 0 else "failed",
        "returncode": result.returncode,
        "started_at": started_at,
        "ended_at": ended_at,
        "path": str(target),
        "stdout_path": str(target / "stdout.log"),
        "stderr_path": str(target / "stderr.log"),
    }
    (target / "job.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return payload


def list_jobs(*, path: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
    root = job_dir(path)
    if not root.exists():
        return []
    rows: List[Dict[str, Any]] = []
    for candidate in root.glob("JOB-*"):
        payload_path = candidate / "job.json"
        if not payload_path.exists():
            continue
        try:
            payload = json.loads(payload_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(payload, dict):
            rows.append(payload)
    rows.sort(key=lambda item: str(item.get("started_at") or ""), reverse=True)
    return rows[:limit]
