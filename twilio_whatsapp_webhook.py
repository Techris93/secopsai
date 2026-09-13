"""
Twilio WhatsApp webhook bridge for OpenClaw security commands.

This adapter receives Twilio webhook requests, validates signatures,
routes message text to whatsapp_openclaw_router.handle_message, and returns
TwiML so Twilio can deliver a reply to WhatsApp.

The sender allowlist is checked after the Twilio signature. Finding list/show
commands return a generic Mission Control pointer so provider message history
does not contain finding IDs, titles, or summaries.

Environment variables:
  SECOPS_TWILIO_AUTH_TOKEN   Required for signature validation in production.
  SECOPS_PUBLIC_WEBHOOK_URL  Optional full public URL Twilio calls (recommended
                             when using tunnels), e.g.
                             https://abc123.ngrok-free.app/twilio/whatsapp
  SECOPS_TWILIO_ALLOWED_SENDERS  Comma-separated exact WhatsApp sender IDs
                                 (for example ``whatsapp:+15551234567``).
  SECOPS_ALLOW_UNSIGNED      Set to "1" only for local testing without Twilio.

Usage:
  python twilio_whatsapp_webhook.py --host 127.0.0.1 --port 8091
"""

from __future__ import annotations

import argparse
import base64
import hmac
import html
import os
from hashlib import sha1
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict
from urllib.parse import parse_qs

from whatsapp_openclaw_router import handle_message


MAX_REQUEST_BODY_BYTES = 32 * 1024


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    return normalized in {"127.0.0.1", "localhost", "::1"}


def _build_signature_base(url: str, params: Dict[str, str]) -> str:
    # Twilio signature base string: URL + concatenated sorted key/value pairs.
    chunks = [url]
    for key in sorted(params.keys()):
        chunks.append(key)
        chunks.append(params[key])
    return "".join(chunks)


def _expected_signature(url: str, params: Dict[str, str], auth_token: str) -> str:
    data = _build_signature_base(url, params).encode("utf-8")
    digest = hmac.new(auth_token.encode("utf-8"), data, sha1).digest()
    return base64.b64encode(digest).decode("utf-8")


def _request_url(handler: BaseHTTPRequestHandler) -> str:
    configured = os.environ.get("SECOPS_PUBLIC_WEBHOOK_URL", "").strip()
    if configured:
        return configured
    host = handler.headers.get("Host", "127.0.0.1")
    scheme = "https" if os.environ.get("SECOPS_ASSUME_HTTPS", "1") == "1" else "http"
    return f"{scheme}://{host}{handler.path}"


def _validate_twilio_signature(handler: BaseHTTPRequestHandler, params: Dict[str, str]) -> bool:
    allow_unsigned = os.environ.get("SECOPS_ALLOW_UNSIGNED", "0") == "1"
    if allow_unsigned:
        server_host = str(handler.server.server_address[0])
        return _is_loopback_host(server_host)

    auth_token = os.environ.get("SECOPS_TWILIO_AUTH_TOKEN", "").strip()
    received = handler.headers.get("X-Twilio-Signature", "").strip()
    if not auth_token or not received:
        return False

    expected = _expected_signature(_request_url(handler), params, auth_token)
    return hmac.compare_digest(received, expected)


def _normalize_sender(value: str) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _sender_authorized(params: Dict[str, str]) -> bool:
    """Require an explicit allowlist after authenticating Twilio's request.

    Provider signatures authenticate Twilio as the sender of the HTTP request;
    they do not authenticate the human who sent the WhatsApp message.  Keep
    the allowlist exact and fail closed when it has not been configured.
    """
    raw = os.environ.get("SECOPS_TWILIO_ALLOWED_SENDERS", "").strip()
    allowed = {_normalize_sender(item) for item in raw.split(",") if _normalize_sender(item)}
    sender = _normalize_sender(params.get("From", ""))
    return bool(sender and allowed and sender in allowed)


def _twiml_message(text: str) -> bytes:
    safe = html.escape(text)
    payload = f"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Response><Message>{safe}</Message></Response>"
    return payload.encode("utf-8")


class _TwilioHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/twilio/whatsapp":
            self.send_response(404)
            self.end_headers()
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_response(400)
            self.end_headers()
            return

        if content_length < 0 or content_length > MAX_REQUEST_BODY_BYTES:
            self.send_response(413)
            self.end_headers()
            return

        self.connection.settimeout(5)
        try:
            body = self.rfile.read(content_length).decode("utf-8")
        except (OSError, TimeoutError, UnicodeDecodeError):
            self.send_response(400)
            self.end_headers()
            return

        parsed = parse_qs(body)

        params = {k: (v[0] if v else "") for k, v in parsed.items()}
        if not _validate_twilio_signature(self, params):
            self.send_response(403)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"forbidden")
            return

        if not _sender_authorized(params):
            self.send_response(403)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"sender_not_authorized")
            return

        inbound_message = params.get("Body", "")
        reply = handle_message(inbound_message)
        twiml = _twiml_message(reply)

        self.send_response(200)
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(twiml)))
        self.end_headers()
        self.wfile.write(twiml)

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(b'{"status":"ok","service":"twilio-whatsapp-bridge"}')

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Twilio WhatsApp bridge")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8091)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    allow_unsigned = os.environ.get("SECOPS_ALLOW_UNSIGNED", "0") == "1"
    if allow_unsigned and not _is_loopback_host(args.host):
        print("SECOPS_ALLOW_UNSIGNED=1 is only permitted when binding to localhost.")
        return 2
    server = ThreadingHTTPServer((args.host, args.port), _TwilioHandler)
    print(f"Twilio bridge listening on http://{args.host}:{args.port}/twilio/whatsapp")
    print("Configure Twilio Sandbox webhook to POST to /twilio/whatsapp")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
