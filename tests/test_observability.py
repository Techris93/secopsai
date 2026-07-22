import sys
from types import SimpleNamespace

from secopsai import observability


def test_observability_is_disabled_without_dsn(monkeypatch):
    monkeypatch.delenv("SECOPSAI_SENTRY_DSN", raising=False)
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    monkeypatch.setattr(observability, "_INITIALIZED", False)
    assert observability.initialize_observability(service="test") is False


def test_observability_uses_privacy_preserving_defaults(monkeypatch):
    calls = {}

    def init(**kwargs):
        calls["init"] = kwargs

    def set_tag(key, value):
        calls["tag"] = (key, value)

    fake_sdk = SimpleNamespace(init=init, set_tag=set_tag)
    monkeypatch.setitem(sys.modules, "sentry_sdk", fake_sdk)
    monkeypatch.setenv("SECOPSAI_SENTRY_DSN", "https://public@example.invalid/1")
    monkeypatch.setenv("SECOPSAI_CORE_ENVIRONMENT", "production")
    monkeypatch.setattr(observability, "_INITIALIZED", False)

    assert observability.initialize_observability(service="research-worker") is True
    assert calls["init"]["send_default_pii"] is False
    assert calls["init"]["include_local_variables"] is False
    assert calls["init"]["traces_sample_rate"] == 0.0
    assert calls["tag"] == ("secopsai.service", "research-worker")
