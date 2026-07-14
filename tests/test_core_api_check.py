from __future__ import annotations

from secopsai.core_api_check import _safe_origin, run_check


def test_safe_origin_rejects_credentials_and_non_https_urls():
    for value in (
        "http://core.example",
        "https://user:pass@core.example",
        "https://core.example/path",
        "https://core.example?token=secret",
    ):
        try:
            _safe_origin(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"accepted unsafe Core URL: {value}")


def test_run_check_records_only_non_secret_hosted_evidence(monkeypatch):
    payloads = {
        "/healthz": (200, {"status": "ok", "version": "0.1.0"}, None),
        "/readyz": (200, {"status": "ready", "data_store": "sqlite"}, None),
        "/api/v1/workspace?limit=1": (
            200,
            {
                "schema_version": "secopsai.core.workspace.v1",
                "summary": {"assets": 2, "findings": 1},
                "assets": [{"node_id": "asset:1", "ip_address": "192.168.1.10"}],
            },
            None,
        ),
    }

    def fake_request(origin, path, token, timeout):
        assert origin == "https://core.example"
        if path == "/api/v1/workspace?limit=1":
            assert token == "read-secret"
        else:
            assert token is None
        assert timeout == 5
        return payloads[path]

    monkeypatch.setattr("secopsai.core_api_check._request_json", fake_request)
    evidence = run_check("https://core.example", "read-secret", timeout=5)

    assert evidence["ok"] is True
    assert [item["name"] for item in evidence["checks"]] == ["healthz", "readyz", "workspace"]
    assert evidence["checks"][2]["summary_keys"] == ["assets", "findings"]
    assert "read-secret" not in str(evidence)


def test_run_check_rejects_raw_telemetry_in_workspace(monkeypatch):
    payloads = {
        "/healthz": (200, {"status": "ok"}, None),
        "/readyz": (200, {"status": "ready"}, None),
        "/api/v1/workspace?limit=1": (
            200,
            {"schema_version": "secopsai.core.workspace.v1", "assets": [{"mac_address": "secret"}]},
            None,
        ),
    }
    monkeypatch.setattr(
        "secopsai.core_api_check._request_json",
        lambda origin, path, token, timeout: payloads[path],
    )

    evidence = run_check("https://core.example", "read-secret")

    assert evidence["ok"] is False
    assert evidence["checks"][2] == {
        "name": "workspace",
        "ok": False,
        "status": 200,
        "error": "raw_telemetry_exposed",
    }
