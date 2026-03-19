"""
WhatsApp-style command router for OpenClaw security checks.

This is an integration-ready bridge:
- Local CLI mode for immediate use.
- HTTP webhook mode for providers (Twilio/Meta/etc.) later.

Security note:
- If SECOPS_WHATSAPP_TOKEN is set, HTTP requests must include header
  X-Webhook-Token: <value>.

Examples:
  python whatsapp_openclaw_router.py --message "check malware"
  python whatsapp_openclaw_router.py --message "check exfil"
  python whatsapp_openclaw_router.py --message "show OCF-41B2A43C8D2C24EA"
  python whatsapp_openclaw_router.py --serve --port 8090
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import openclaw_plugin


SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _render_help() -> str:
    return (
        "OpenClaw Security Commands:\n"
        "- check malware\n"
        "- check exfil\n"
        "- check both\n"
        "- list high\n"
        "- show FINDING_ID\n"
        "- help"
    )


def _summarize_check(payload: dict) -> str:
    lines = [
        f"Check: {payload.get('check_type')}",
        f"Matched findings: {payload.get('matched_count')} of {payload.get('findings_total')}",
        f"High+: {payload.get('high_or_above')}",
    ]
    top = payload.get("top_matches", [])
    if top:
        lines.append("Top matches:")
        for row in top[:3]:
            lines.append(
                f"- {row.get('finding_id')} | {row.get('severity')} | {row.get('status')} | {row.get('title')}"
            )
    else:
        lines.append("No matches in current findings store.")
    return "\n".join(lines)


def _severity_at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER.get(severity.lower(), 0) >= SEVERITY_ORDER.get(threshold.lower(), 0)


def _top_rows(findings: list[dict], max_rows: int = 10) -> list[dict]:
    rows = sorted(
        findings,
        key=lambda row: (
            -SEVERITY_ORDER.get(str(row.get("severity", "info")).lower(), 0),
            str(row.get("first_seen", "")),
        ),
    )
    return rows[:max_rows]


def handle_message(message: str) -> str:
    normalized = " ".join(message.strip().lower().split())
    if not normalized or normalized == "help":
        return _render_help()

    if normalized.startswith("check "):
        check_type = normalized.replace("check ", "", 1).strip()
        if check_type not in {"malware", "exfil", "both"}:
            return "Unknown check type. Use: malware, exfil, or both."

        result = openclaw_plugin.check_presence(check_type=check_type, min_severity="low")
        payload = {
            "check_type": result.check_type,
            "findings_total": result.findings_total,
            "matched_count": result.matched_count,
            "high_or_above": result.high_or_above,
            "top_matches": result.top_matches,
        }
        return _summarize_check(payload)

    if normalized == "list high":
        rows = _top_rows(
            [
                row
                for row in openclaw_plugin.soc_store.list_findings()
                if _severity_at_least(str(row.get("severity", "info")), "high")
            ],
            max_rows=10,
        )
        if not rows:
            return "No high-severity findings right now."
        lines = ["High findings:"]
        for row in rows:
            lines.append(f"- {row.get('finding_id')} | {row.get('severity')} | {row.get('title')}")
        return "\n".join(lines)

    if normalized.startswith("show "):
        finding_id = message.strip().split(maxsplit=1)[1]
        finding = openclaw_plugin.soc_store.get_finding(finding_id)
        if not finding:
            return f"Finding not found: {finding_id}"
        return (
            f"{finding.get('finding_id')}\n"
            f"Severity: {finding.get('severity')}\n"
            f"Status: {finding.get('status')}\n"
            f"Disposition: {finding.get('disposition')}\n"
            f"Title: {finding.get('title')}\n"
            f"Summary: {finding.get('summary')}"
        )

    return "Unknown command. Send 'help' to see supported commands."


class _WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        token = os.environ.get("SECOPS_WHATSAPP_TOKEN", "").strip()
        received_token = self.headers.get("X-Webhook-Token", "").strip()
        if not token or not hmac.compare_digest(received_token, token):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"forbidden")
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(content_length)

        message = ""
        content_type = self.headers.get("Content-Type", "")
        if "application/json" in content_type:
            payload = json.loads(body.decode("utf-8") or "{}")
            message = str(payload.get("message") or payload.get("Body") or payload.get("text") or "")
        else:
            parsed = parse_qs(body.decode("utf-8"))
            message = str((parsed.get("Body") or parsed.get("message") or [""])[0])

        reply = handle_message(message)
        encoded = json.dumps({"reply": reply}).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="WhatsApp command router for OpenClaw")
    parser.add_argument("--message", help="One-shot local message simulation")
    parser.add_argument("--serve", action="store_true", help="Run local webhook server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8090)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.message:
        print(handle_message(args.message))
        return 0

    if args.serve:
        if not os.environ.get("SECOPS_WHATSAPP_TOKEN", "").strip():
            print("SECOPS_WHATSAPP_TOKEN must be set before starting webhook mode.", file=sys.stderr)
            return 2
        server = HTTPServer((args.host, args.port), _WebhookHandler)
        print(f"Listening on http://{args.host}:{args.port}")
        print("POST message as JSON {'message': 'check malware'}")
        server.serve_forever()

    print(_render_help())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
