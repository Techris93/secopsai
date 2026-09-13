from __future__ import annotations

from twilio_whatsapp_webhook import _sender_authorized
from whatsapp_openclaw_router import handle_message


def test_list_high_returns_generic_console_pointer_without_querying_store(monkeypatch):
    def fail_if_called():
        raise AssertionError("messaging list must not read sensitive finding rows")

    monkeypatch.setattr("openclaw_plugin.soc_store.list_findings", fail_if_called)
    reply = handle_message("list high")

    assert reply == "High-severity findings are available in the authenticated Mission Control console."
    assert "OCF-SECRET-1" not in reply
    assert "Sensitive title" not in reply
    assert "private summary" not in reply


def test_show_returns_generic_console_pointer_without_echoing_requested_id(monkeypatch):
    def fail_if_called(_finding_id):
        raise AssertionError("messaging show must not read sensitive finding rows")

    monkeypatch.setattr("openclaw_plugin.soc_store.get_finding", fail_if_called)
    reply = handle_message("show OCF-SECRET-1")

    assert reply == "Finding details are available in the authenticated Mission Control console."
    assert "OCF-SECRET-1" not in reply
    assert "title" not in reply.lower()
    assert "summary" not in reply.lower()


def test_twilio_sender_allowlist_fails_closed_and_matches_exact_normalized_id(monkeypatch):
    monkeypatch.delenv("SECOPS_TWILIO_ALLOWED_SENDERS", raising=False)
    assert _sender_authorized({"From": "whatsapp:+15551234567"}) is False

    monkeypatch.setenv("SECOPS_TWILIO_ALLOWED_SENDERS", " whatsapp:+15551234567 ")
    assert _sender_authorized({"From": "WhatsApp:+15551234567"}) is True
    assert _sender_authorized({"From": "whatsapp:+15551234568"}) is False
