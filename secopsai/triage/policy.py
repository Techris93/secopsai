from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Dict, Optional


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_POLICY_PATH = ROOT / "config" / "triage_orchestrator.toml"
DEFAULT_POLICY = {
    "safety": {
        "auto_close_expected_behavior": True,
        "auto_close_allowlisted_false_positive": True,
        "auto_start_in_review": True,
        "reconcile_on_policy_change": True,
    },
    "limits": {
        "max_findings_per_run": 20,
    },
}


def policy_path(path: Optional[str] = None) -> Path:
    configured = path or os.environ.get("SECOPS_TRIAGE_POLICY")
    return Path(configured).expanduser().resolve() if configured else DEFAULT_POLICY_PATH


def load_policy(path: Optional[str] = None) -> Dict[str, Any]:
    target = policy_path(path)
    payload: Dict[str, Any] = {"safety": dict(DEFAULT_POLICY["safety"]), "limits": dict(DEFAULT_POLICY["limits"])}
    if target.exists():
        try:
            loaded = tomllib.loads(target.read_text(encoding="utf-8"))
        except Exception:
            loaded = {}
        payload["safety"].update(loaded.get("safety", {}))
        payload["limits"].update(loaded.get("limits", {}))
    return payload
