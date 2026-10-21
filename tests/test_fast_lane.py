import importlib.util
from datetime import datetime, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location("fast_lane", Path(__file__).resolve().parents[1] / "scripts" / "fast_lane.py")
fast_lane = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fast_lane)


def _result(*, hooks_left=None, hooks_right=None, changed=False, left_ids=(), right_ids=(), yara_level="none", publisher_changed=False):
    return {
        "verdict": "suspicious",
        "comparison": {
            "lifecycle_scripts": {"left": hooks_left or {}, "right": hooks_right or {}, "changed": changed},
            "indicators": {"left": [{"indicator_id": i} for i in left_ids], "right": [{"indicator_id": i} for i in right_ids]},
            "metadata": {"publisher_changed": publisher_changed},
            "members": {"added": ["package/setup.js"]},
        },
        "scan": {"yara": {"level": yara_level, "score": 85 if yara_level == "alert" else 0, "rules_matched": ["SUSP_X"] if yara_level != "none" else []},
                 "findings": [{"rule_id": "YARA:SUSP_X", "rule_author": "Florian Roth", "safe_context": "..."}] if yara_level != "none" else []},
    }


def test_hijacked_release_with_new_install_hook_and_egress_is_critical():
    decision = fast_lane.assess(_result(hooks_right={"postinstall": "node setup.js"}, right_ids=("outbound-network", "credential-access"), yara_level="warning"))
    assert decision["severity"] == "critical"
    assert any("install-time script" in reason for reason in decision["reasons"])
    assert decision["yara_findings"][0]["rule_author"] == "Florian Roth", "DRL attribution travels with the alert"


def test_unchanged_hooks_and_no_new_behaviour_raise_nothing():
    decision = fast_lane.assess(_result(hooks_left={"postinstall": "node x.js"}, hooks_right={"postinstall": "node x.js"}, left_ids=("network-endpoint",), right_ids=("network-endpoint",)))
    assert decision["severity"] == "none" and decision["reasons"] == []


def test_yara_alert_alone_is_high_and_payload_records_latency():
    decision = fast_lane.assess(_result(yara_level="alert"))
    assert decision["severity"] == "high"
    release = {"version": "1.0.1", "previous_version": "1.0.0", "published_at": "2026-10-10T10:00:00Z"}
    payload = fast_lane.alert_payload({"ecosystem": "npm", "package": "demo"}, release, decision, datetime(2026, 10, 10, 10, 4, 30, tzinfo=timezone.utc))
    assert payload["alert_type"] == "registry_release_anomaly"
    assert payload["evidence"]["publish_to_verdict_seconds"] == 270
    assert payload["alert_id"] == "FASTLANE-npm:demo@1.0.1"


class _Fetcher:
    def __init__(self, documents):
        self.documents = documents

    def get(self, url, **_kwargs):
        return url, {}, __import__("json").dumps(self.documents[url]).encode()


def test_pypi_release_missing_from_cached_project_document_uses_version_document():
    fetcher = _Fetcher({
        "https://pypi.org/pypi/rjsmin/json": {"info": {"version": "1.2.5"}, "releases": {"1.2.5": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}]}},
        "https://pypi.org/pypi/rjsmin/1.3.0/json": {"urls": [{"upload_time_iso_8601": "2026-10-10T16:32:12Z"}]},
    })
    release = fast_lane.resolve_release(fetcher, "pypi", "rjsmin", "1.3.0")
    assert release == {"version": "1.3.0", "published_at": "2026-10-10T16:32:12Z", "previous_version": "1.2.5"}


def test_pypi_adapter_falls_back_to_sdist_when_wheel_exceeds_cap():
    from secopsai.research_intake import MAX_ARTIFACT_BYTES, PyPiAdapter

    url = "https://pypi.org/pypi/homeassistant/2026.10.1/json"
    fetcher = _Fetcher({url: {"info": {}, "urls": [
        {"url": "https://files.pythonhosted.org/ha.whl", "packagetype": "bdist_wheel", "size": MAX_ARTIFACT_BYTES + 1},
        {"url": "https://files.pythonhosted.org/ha.tar.gz", "packagetype": "sdist", "size": 38_000_000},
    ]}})
    assert PyPiAdapter().resolve("homeassistant", "2026.10.1", fetcher).artifact_url.endswith("ha.tar.gz")


def test_resource_limit_is_explicit_incomplete_coverage_and_transient_http_is_retryable(tmp_path, monkeypatch):
    import json
    from secopsai.research_intake import ArtifactResourceLimitError, RegistryHTTPError

    monkeypatch.setenv("FAST_LANE_TARGETS", json.dumps([{"ecosystem": "pypi", "package": "fixture", "version": "1.0", "_queue_id": "a" * 64}]))
    monkeypatch.setenv("FAST_LANE_REPORT_PATH", str(tmp_path / "report.json"))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    monkeypatch.setattr(fast_lane, "STALE_AFTER_SECONDS", 10**9)
    monkeypatch.setattr(fast_lane, "resolve_release", lambda *_: {"version": "1.0", "published_at": "2026-10-18T00:00:00Z", "previous_version": "0.9"})
    monkeypatch.setattr(fast_lane, "investigate", lambda *_: (_ for _ in ()).throw(ArtifactResourceLimitError("archive expanded-size limit exceeded")))
    assert fast_lane.main() == 0, "bounded incomplete evidence is a recorded review outcome"
    result = json.loads((tmp_path / "report.json").read_text())["results"][0]
    assert result["status"] == "incomplete" and result["failure_category"] == "artifact_resource_limit"
    assert "no clean verdict" in result["reasons"]

    monkeypatch.setattr(fast_lane, "investigate", lambda *_: (_ for _ in ()).throw(RegistryHTTPError(503)))
    assert fast_lane.main() == 0, "queue-backed transient failure is durably scheduled for retry"
    result = json.loads((tmp_path / "report.json").read_text())["results"][0]
    assert result["status"] == "retryable_failure" and result["http_status"] == 503


def test_traversal_archive_is_reported_as_unsafe_incomplete_and_unqueued_retry_fails(tmp_path, monkeypatch):
    import json
    from secopsai.research_intake import RegistryHTTPError, UnsafeArchiveError

    monkeypatch.setenv("FAST_LANE_TARGETS", json.dumps([{"ecosystem": "npm", "package": "fixture", "version": "1.0", "_queue_id": "b" * 64}]))
    monkeypatch.setenv("FAST_LANE_REPORT_PATH", str(tmp_path / "report.json"))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    monkeypatch.setattr(fast_lane, "STALE_AFTER_SECONDS", 10**9)
    monkeypatch.setattr(fast_lane, "resolve_release", lambda *_: {"version": "1.0", "published_at": "2026-10-18T00:00:00Z", "previous_version": "0.9"})
    monkeypatch.setattr(fast_lane, "investigate", lambda *_: (_ for _ in ()).throw(UnsafeArchiveError("archive contains traversal path")))
    assert fast_lane.main() == 0
    result = json.loads((tmp_path / "report.json").read_text())["results"][0]
    assert result["status"] == "incomplete" and result["failure_category"] == "unsafe_archive"

    monkeypatch.setenv("FAST_LANE_TARGETS", json.dumps([{"ecosystem": "npm", "package": "fixture", "version": "1.0"}]))
    monkeypatch.setattr(fast_lane, "investigate", lambda *_: (_ for _ in ()).throw(RegistryHTTPError(503)))
    assert fast_lane.main() == 1, "without a durable queue id, transient work must not be reported as handled"


def test_permanent_registry_http_failure_is_explicit_incomplete(tmp_path, monkeypatch):
    import json
    from secopsai.research_intake import RegistryHTTPError

    monkeypatch.setenv("FAST_LANE_TARGETS", json.dumps([{"ecosystem": "npm", "package": "fixture", "version": "1.0", "_queue_id": "c" * 64}]))
    monkeypatch.setenv("FAST_LANE_REPORT_PATH", str(tmp_path / "report.json"))
    monkeypatch.setattr(fast_lane, "STALE_AFTER_SECONDS", 10**9)
    monkeypatch.setattr(fast_lane, "resolve_release", lambda *_: {"version": "1.0", "published_at": "2026-10-18T00:00:00Z", "previous_version": "0.9"})
    monkeypatch.setattr(fast_lane, "investigate", lambda *_: (_ for _ in ()).throw(RegistryHTTPError(403)))

    assert fast_lane.main() == 0
    result = json.loads((tmp_path / "report.json").read_text())["results"][0]
    assert result["status"] == "incomplete" and result["http_status"] == 403
    assert result["retryable"] is False and "no clean verdict" in result["reasons"]
