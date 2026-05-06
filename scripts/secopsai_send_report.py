#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CHAT_ID = "623118122"
TELEGRAM_LIMIT = 4096
SAFE_CHUNK_SIZE = 3800


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _openclaw_telegram_token(config_path: Path) -> str:
    payload = _load_json(config_path.expanduser())
    channels = payload.get("channels") if isinstance(payload.get("channels"), dict) else {}
    telegram = channels.get("telegram") if isinstance(channels.get("telegram"), dict) else {}
    token = telegram.get("botToken")
    return str(token or "").strip()


def _telegram_token(args: argparse.Namespace) -> str:
    token = str(os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    if token:
        return token
    return _openclaw_telegram_token(Path(args.openclaw_config))


def _run_report(args: argparse.Namespace) -> str:
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "secopsai_render_report.py"),
        "--kind",
        args.kind,
        "--repo",
        str(ROOT),
    ]
    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or f"exit code {proc.returncode}"
        raise RuntimeError(f"report renderer failed: {message}")
    return proc.stdout.strip()


def _chunk_text(text: str) -> list[str]:
    if len(text) <= TELEGRAM_LIMIT:
        return [text]

    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    for line in text.splitlines():
        line_len = len(line) + 1
        if current and current_len + line_len > SAFE_CHUNK_SIZE:
            chunks.append("\n".join(current).strip())
            current = []
            current_len = 0
        if line_len > SAFE_CHUNK_SIZE:
            start = 0
            while start < len(line):
                if current:
                    chunks.append("\n".join(current).strip())
                    current = []
                    current_len = 0
                chunks.append(line[start:start + SAFE_CHUNK_SIZE])
                start += SAFE_CHUNK_SIZE
            continue
        current.append(line)
        current_len += line_len
    if current:
        chunks.append("\n".join(current).strip())
    return [chunk for chunk in chunks if chunk]


def _send_telegram(token: str, chat_id: str, text: str) -> None:
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    chunks = _chunk_text(text)
    for index, chunk in enumerate(chunks, start=1):
        payload_text = chunk
        if len(chunks) > 1:
            payload_text = f"{chunk}\n\nPart {index}/{len(chunks)}"
        payload = json.dumps(
            {
                "chat_id": chat_id,
                "text": payload_text,
                "disable_web_page_preview": True,
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                body = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"telegram send failed: HTTP {exc.code}: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"telegram send failed: {exc}") from exc
        result = json.loads(body)
        if not result.get("ok"):
            raise RuntimeError(f"telegram send failed: {body}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render and send deterministic SecOpsAI reports")
    parser.add_argument("--kind", required=True, choices=["daily-intel", "status-summary", "daily-brief"])
    parser.add_argument("--chat-id", default=os.environ.get("TELEGRAM_CHAT_ID", DEFAULT_CHAT_ID))
    parser.add_argument("--openclaw-config", default=str(Path.home() / ".openclaw" / "openclaw.json"))
    parser.add_argument("--dry-run", action="store_true", help="Render only; do not send to Telegram")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report = _run_report(args)
    if args.dry_run:
        print(report)
        return 0

    token = _telegram_token(args)
    if not token:
        raise SystemExit("missing TELEGRAM_BOT_TOKEN and OpenClaw telegram botToken")
    _send_telegram(token, str(args.chat_id), report)
    print(f"sent kind={args.kind} chat_id={args.chat_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
