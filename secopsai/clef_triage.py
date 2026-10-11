"""Triage with Cloudflare Clef, a decision model on Workers AI.

Clef takes a ``state`` (the content to judge) and typed questions, and
returns a probability per answer.  For a flagged release we ask:

- ``malicious`` (noul): probability the release is malicious;
- ``disposition`` (choice): malicious / benign / needs_review.

The state is the same minimized triage context the chat model gets (rule
findings with their code, install-time files, manifest, behaviour flags),
capped in size.  Billing is per input token on the Cloudflare account; no
output tokens are charged.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional

import requests

ENDPOINT = "https://api.cloudflare.com/client/v4/accounts/{account}/ai/run/@cf/cloudflare/{model}"
MAX_STATE_CHARS = 32_000
QUESTIONS = {
    "malicious": {
        "type": "noul",
        "instructions": (
            "Is this package release malicious: does it act against the person or system that installs or uses it, for example by "
            "collecting data and sending it off the machine, reading credentials or wallets, downloading and running a payload, or "
            "running hidden or obfuscated code at install time? Ordinary networking, shell use, configuration reads and build steps "
            "in legitimate software are not malicious."
        ),
    },
    "disposition": {
        "type": "choice",
        "instructions": "How should a supply-chain analyst treat this flagged release?",
        "criteria": {
            "malicious": "The code shows malicious behaviour.",
            "benign": "The flagged behaviour is ordinary for this kind of software.",
            "needs_review": "The supplied code cannot settle it.",
        },
    },
}


def build_state(context: Dict[str, Any], limit: int = MAX_STATE_CHARS) -> str:
    """Compact, labelled text of a triage context, most decisive parts first."""
    parts = [f"Package: {context.get('ecosystem')}:{context.get('package')}@{context.get('version')}",
             f"Rule score: {context.get('rule_score')} ({context.get('rule_level')})"]
    flags = [signal.get("flags") for signal in context.get("metadata_signals") or [] if isinstance(signal, dict) and signal.get("flags")]
    if flags:
        parts.append("Behaviour flags: " + ", ".join(flags[0][:40]))
    for item in context.get("install_time_files") or []:
        parts.append(f"--- install-time file {item.get('path')}{' (truncated)' if item.get('truncated') else ''} ---\n{item.get('content', '')}")
    for finding in context.get("findings") or []:
        parts.append(f"--- finding {finding.get('rule_id')} in {finding.get('file_path')} ({finding.get('matched_indicator')}) ---\n"
                     f"{finding.get('safe_context', '')}")
    manifest = context.get("manifest") or {}
    if manifest:
        parts.append("Manifest: " + json.dumps(manifest)[:2000])
    return "\n\n".join(str(part) for part in parts)[:limit]


def classify(context: Dict[str, Any], *, model: str = "clef", account_id: Optional[str] = None, api_token: Optional[str] = None,
             session: Optional[Any] = None, timeout: int = 60) -> Dict[str, Any]:
    """Ask Clef about one triage context; returns probability (0-100), choice and token usage."""
    account = account_id or os.environ["CLOUDFLARE_ACCOUNT_ID"]
    token = api_token or os.environ["CLOUDFLARE_API_TOKEN"]
    http = session or requests
    response = http.post(
        ENDPOINT.format(account=account, model=model),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        json={"model": model, "state": build_state(context), "questions": QUESTIONS},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    body = payload.get("result", payload) if isinstance(payload, dict) else {}
    answers = body.get("answers") or {}
    malicious = answers.get("malicious") or {}
    disposition = answers.get("disposition") or {}
    return {
        "probability": round(100 * float(malicious.get("noul", 0.0))),
        "choice": disposition.get("choice"),
        "choice_probabilities": disposition.get("probabilities") or {},
        "input_tokens": int((body.get("usage") or {}).get("input_tokens") or 0),
        "model": body.get("model") or model,
    }
