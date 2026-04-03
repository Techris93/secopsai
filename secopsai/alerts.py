from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SLACK_CONFIG = REPO_ROOT / "config" / "slack.json"
ALERTS_DIR = REPO_ROOT / "data" / "alerts"
SLACK_STATE_PATH = ALERTS_DIR / "slack_alert_state.json"
SUPPLY_CHAIN_SLACK_STATE_PATH = ALERTS_DIR / "supply_chain_slack_state.json"


def _load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def load_slack_config() -> Dict[str, Any] | None:
    env_path = os.environ.get("SECOPS_SLACK_CONFIG")
    if env_path:
        path = Path(env_path)
    else:
        path = DEFAULT_SLACK_CONFIG
    payload = _load_json(path, None)
    if not isinstance(payload, dict):
        return None
    if not payload.get("bot_token") or not payload.get("channel"):
        return None
    return payload


def send_slack_message(message: str) -> bool:
    config = load_slack_config()
    if not config:
        return False

    import requests

    response = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={"Authorization": f"Bearer {config['bot_token']}"},
        data={"channel": config["channel"], "text": message},
        timeout=30,
    )
    try:
        payload = response.json()
    except Exception:
        return False
    return bool(payload.get("ok"))


def load_slack_state(path: Path | None = None) -> Dict[str, Any]:
    path = path or SLACK_STATE_PATH
    payload = _load_json(path, {"finding_ids": []})
    if not isinstance(payload, dict):
        return {"finding_ids": []}
    ids = payload.get("finding_ids", [])
    if not isinstance(ids, list):
        ids = []
    return {"finding_ids": [str(item) for item in ids]}


def save_slack_state(state: Dict[str, Any], path: Path | None = None) -> None:
    path = path or SLACK_STATE_PATH
    _write_json(path, state)


def _format_openclaw_message(findings: List[Dict[str, Any]]) -> str:
    lines = ["🚨 SecOpsAI OpenClaw Alert", ""]
    lines.append(f"New high-severity findings: {len(findings)}")
    lines.append("")
    for finding in findings[:10]:
        lines.append(
            "- {fid} | {sev} | {title}".format(
                fid=finding.get("finding_id", ""),
                sev=str(finding.get("severity", "")).upper(),
                title=finding.get("title", ""),
            )
        )
    if len(findings) > 10:
        lines.append("")
        lines.append(f"... plus {len(findings) - 10} more findings")
    return "\n".join(lines)


def alert_new_openclaw_findings(findings: Iterable[Dict[str, Any]], min_severity: str = "high") -> Dict[str, Any]:
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    threshold = order[min_severity]
    state = load_slack_state()
    already_sent = set(state["finding_ids"])

    eligible = [
        finding for finding in findings
        if order.get(str(finding.get("severity", "info")).lower(), 0) >= threshold
    ]
    new_findings = [
        finding for finding in eligible
        if str(finding.get("finding_id", "")) not in already_sent
    ]

    sent = False
    if new_findings:
        sent = send_slack_message(_format_openclaw_message(new_findings))
        if sent:
            state["finding_ids"] = sorted(already_sent | {str(f["finding_id"]) for f in new_findings})
            save_slack_state(state)

    return {
        "eligible": len(eligible),
        "new_findings": len(new_findings),
        "sent": sent,
    }


def _format_supply_chain_message(findings: List[Dict[str, Any]]) -> str:
    lines = ["🚨 SecOpsAI Supply Chain Alert", ""]
    lines.append(f"New malicious package findings: {len(findings)}")
    lines.append("")
    for finding in findings[:10]:
        lines.append(
            "- {fid} | {eco} | {pkg}@{ver}".format(
                fid=finding.get("finding_id", ""),
                eco=str(finding.get("ecosystem", "")).upper(),
                pkg=finding.get("package", ""),
                ver=finding.get("new_version", ""),
            )
        )
    if len(findings) > 10:
        lines.append("")
        lines.append(f"... plus {len(findings) - 10} more findings")
    return "\n".join(lines)


def alert_new_supply_chain_findings(findings: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    state = load_slack_state(SUPPLY_CHAIN_SLACK_STATE_PATH)
    already_sent = set(state["finding_ids"])
    findings = list(findings)
    new_findings = [finding for finding in findings if str(finding.get("finding_id", "")) not in already_sent]

    sent = False
    if new_findings:
        sent = send_slack_message(_format_supply_chain_message(new_findings))
        if sent:
            state["finding_ids"] = sorted(already_sent | {str(f["finding_id"]) for f in new_findings})
            save_slack_state(state, SUPPLY_CHAIN_SLACK_STATE_PATH)

    return {
        "eligible": len(findings),
        "new_findings": len(new_findings),
        "sent": sent,
    }
