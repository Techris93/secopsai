from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_QUEUE_PATH = ROOT / "data" / "triage" / "action_queue.json"


def queue_path(path: Optional[str] = None) -> Path:
    configured = path or os.environ.get("SECOPS_TRIAGE_QUEUE_PATH")
    return Path(configured).expanduser().resolve() if configured else DEFAULT_QUEUE_PATH


def load_actions(path: Optional[str] = None) -> List[Dict[str, Any]]:
    target = queue_path(path)
    if not target.exists():
        return []
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(payload, list):
        return []
    return [item for item in payload if isinstance(item, dict)]


def save_actions(actions: List[Dict[str, Any]], path: Optional[str] = None) -> Path:
    target = queue_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(actions, indent=2, sort_keys=True), encoding="utf-8")
    return target


def _next_action_id(actions: List[Dict[str, Any]]) -> str:
    highest = 0
    for action in actions:
        raw = str(action.get("action_id") or "")
        if raw.startswith("ACT-"):
            try:
                highest = max(highest, int(raw.split("-", 1)[1]))
            except Exception:
                continue
    return f"ACT-{highest + 1:04d}"


def enqueue_action(action: Dict[str, Any], path: Optional[str] = None) -> Dict[str, Any]:
    actions = load_actions(path)
    queued = dict(action)
    queued.setdefault("action_id", _next_action_id(actions))
    queued.setdefault("status", "pending")
    queued.setdefault("created_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    queued.setdefault("updated_at", queued["created_at"])
    actions.append(queued)
    save_actions(actions, path)
    return queued


def list_actions(*, status: Optional[str] = None, path: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    actions = load_actions(path)
    if status:
        actions = [item for item in actions if str(item.get("status") or "").lower() == status.lower()]
    return actions[:limit]


def get_action(action_id: str, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    for action in load_actions(path):
        if str(action.get("action_id") or "") == action_id:
            return action
    return None


def update_action(action_id: str, updates: Dict[str, Any], path: Optional[str] = None) -> Dict[str, Any]:
    actions = load_actions(path)
    for index, action in enumerate(actions):
        if str(action.get("action_id") or "") != action_id:
            continue
        merged = dict(action)
        merged.update(updates)
        merged["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        actions[index] = merged
        save_actions(actions, path)
        return merged
    raise ValueError(f"action not found: {action_id}")
