import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

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


def test_pypi_adapter_marks_release_with_only_oversized_artifacts_as_incomplete():
    from secopsai.research_intake import ArtifactResourceLimitError, MAX_ARTIFACT_BYTES, PyPiAdapter

    url = "https://pypi.org/pypi/libtpu/0.0.51/json"
    fetcher = _Fetcher({url: {"info": {}, "urls": [
        {"url": "https://files.pythonhosted.org/libtpu.whl", "packagetype": "bdist_wheel", "size": MAX_ARTIFACT_BYTES + 1},
        {"url": "https://files.pythonhosted.org/libtpu.tar.gz", "packagetype": "sdist", "size": MAX_ARTIFACT_BYTES + 2},
    ]}})

    with pytest.raises(ArtifactResourceLimitError) as raised:
        PyPiAdapter().resolve("libtpu", "0.0.51", fetcher)

    assert raised.value.failure_category == "artifact_resource_limit"
    assert "configured download limit" in str(raised.value)


def test_large_npm_packument_uses_bounded_npm_limit_and_preserves_publish_times():
    from secopsai.research_intake import MAX_METADATA_BYTES, MAX_NPM_METADATA_BYTES, NpmAdapter, SafeFetcher

    package_url = "https://registry.npmjs.org/@pulumi/pulumi"
    publish_time = "2026-10-21T17:22:58.401Z"
    document = {
        "dist-tags": {"latest": "3.271.0"},
        "time": {"3.270.0": "2026-10-20T12:00:00.000Z", "3.271.0": publish_time},
        "versions": {
            "3.270.0": {
                "version": "3.270.0",
                "dist": {"tarball": "https://registry.npmjs.org/@pulumi/pulumi/-/pulumi-3.270.0.tgz"},
            },
            "3.271.0": {
                "version": "3.271.0",
                "dist": {"tarball": "https://registry.npmjs.org/@pulumi/pulumi/-/pulumi-3.271.0.tgz"},
            },
        },
        # Model the large full packument seen in production without storing a fixture file.
        "readme": "x" * (MAX_METADATA_BYTES + 64),
    }
    body = json.dumps(document).encode()
    assert len(body) > MAX_METADATA_BYTES
    requested_bounds = []

    def fetch(url, max_bytes):
        assert url == package_url
        requested_bounds.append(max_bytes)
        return 200, {"content-type": "application/json"}, body

    metadata = NpmAdapter().resolve("@pulumi/pulumi", "3.271.0", SafeFetcher(fetch=fetch))
    assert requested_bounds == [MAX_NPM_METADATA_BYTES]
    assert metadata.version == "3.271.0"
    assert metadata.published_at == publish_time
    assert metadata.artifact_url.endswith("pulumi-3.271.0.tgz")


def test_safe_fetcher_reports_oversized_registry_response_as_typed_limit():
    from secopsai.research_intake import IntakeResponseLimitError, SafeFetcher

    fetcher = SafeFetcher(fetch=lambda *_: (200, {}, b"123456"))
    with pytest.raises(IntakeResponseLimitError) as raised:
        fetcher.get("https://registry.npmjs.org/fixture", allowed_hosts=("registry.npmjs.org",), max_bytes=5)
    assert raised.value.failure_category == "response_size_limit"


def test_resource_limit_is_explicit_incomplete_coverage_and_transient_http_is_retryable(tmp_path, monkeypatch):
    import json
    from secopsai.research_intake import ArtifactResourceLimitError, IntakeResponseLimitError, RegistryHTTPError

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

    monkeypatch.setattr(
        fast_lane,
        "investigate",
        lambda *_: (_ for _ in ()).throw(IntakeResponseLimitError("response limit")),
    )
    assert fast_lane.main() == 0, "a bounded response limit is an explicit incomplete outcome"
    result = json.loads((tmp_path / "report.json").read_text())["results"][0]
    assert result["status"] == "incomplete" and result["failure_category"] == "response_size_limit"
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


def _run_one(tmp_path, monkeypatch, investigate):
    monkeypatch.setenv("FAST_LANE_TARGETS", json.dumps([{"ecosystem": "pypi", "package": "fixture", "version": "1.0", "_queue_id": "b" * 64}]))
    monkeypatch.setenv("FAST_LANE_REPORT_PATH", str(tmp_path / "report.json"))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    monkeypatch.setattr(fast_lane, "STALE_AFTER_SECONDS", 10**9)
    monkeypatch.setattr(fast_lane, "resolve_release", lambda *_: {"version": "1.0", "published_at": "2026-10-22T00:00:00Z", "previous_version": "0.9"})
    monkeypatch.setattr(fast_lane, "investigate", investigate)
    code = fast_lane.main()
    return code, json.loads((tmp_path / "report.json").read_text())["results"][0]


def test_partial_scan_is_analyzed_but_never_reported_as_complete(tmp_path, monkeypatch):
    result = _result()
    result["scan"]["coverage"] = {"partial": True, "reason": "file-count budget reached", "members_total": 9000,
                                  "members_read": 5000, "members_skipped": 4000, "bytes_declared": 1, "bytes_read": 1}
    code, row = _run_one(tmp_path, monkeypatch, lambda *_: result)
    assert code == 0
    assert row["status"] == "analyzed" and row["coverage"] == "partial"
    assert row["reasons"].startswith("partial scan (5000 of 9000 files read; file-count budget reached)")


def test_unknown_errors_name_the_failing_check_in_the_report(tmp_path, monkeypatch):
    code, row = _run_one(tmp_path, monkeypatch, lambda *_: (_ for _ in ()).throw(ValueError("artifact contains\nan odd entry")))
    assert code == 1, "a genuinely unknown analyzer failure still fails the run"
    assert row["failure_detail"] == "artifact contains an odd entry"
    assert "ValueError: artifact contains an odd entry" in row["reasons"]


def _completion_module():
    spec = importlib.util.spec_from_file_location("fast_lane_complete", Path(__file__).resolve().parents[1] / "scripts" / "fast_lane_complete.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_completion_acknowledgement_retries_transient_failures(tmp_path, monkeypatch):
    """Run 39658957559 failed on one unacknowledged completion; resends are idempotent."""
    import io
    import urllib.error

    complete = _completion_module()
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"schema_version": "secopsai.fast-lane.results.v1", "results": [{"queue_id": "c" * 64, "status": "analyzed"}]}))
    monkeypatch.setenv("FAST_LANE_REPORT_PATH", str(report))
    monkeypatch.setenv("LEDGER_STORE_TOKEN", "tok")
    monkeypatch.setattr(complete.time, "sleep", lambda _s: None)
    calls = []

    class Ok(io.BytesIO):
        status = 200
        def __enter__(self): return self
        def __exit__(self, *_): return False

    def urlopen(request, timeout=None):
        calls.append(request.full_url)
        if len(calls) == 1:
            raise urllib.error.URLError("timed out")
        if len(calls) == 2:
            raise urllib.error.HTTPError(request.full_url, 503, "busy", {}, io.BytesIO(b""))
        return Ok(b'{"status":"stored","completed":1,"retried":0,"unresolved":0}')

    monkeypatch.setattr(complete.urllib.request, "urlopen", urlopen)
    assert complete.main() == 0
    assert len(calls) == 3

    calls.clear()
    def rejected(request, timeout=None):
        calls.append(request.full_url)
        raise urllib.error.HTTPError(request.full_url, 400, "bad", {}, io.BytesIO(b""))
    monkeypatch.setattr(complete.urllib.request, "urlopen", rejected)
    assert complete.main() == 1
    assert len(calls) == 1, "a rejected batch is not retried"


def test_completion_failure_names_the_server_reason(tmp_path, monkeypatch, capsys):
    import io
    import urllib.error

    complete = _completion_module()
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"schema_version": "secopsai.fast-lane.results.v1", "results": [{"queue_id": "c" * 64, "status": "analyzed"}]}))
    monkeypatch.setenv("FAST_LANE_REPORT_PATH", str(report))
    monkeypatch.setenv("LEDGER_STORE_TOKEN", "tok")

    def refused(request, timeout=None):
        raise urllib.error.HTTPError(request.full_url, 422, "refused", {}, io.BytesIO(b'{"error":"unknown fast-lane target"}'))

    monkeypatch.setattr(complete.urllib.request, "urlopen", refused)
    assert complete.main() == 1
    assert "HTTP 422: unknown fast-lane target" in capsys.readouterr().err


def test_a_release_without_a_publish_time_yet_is_retried_and_stays_queued(tmp_path, monkeypatch):
    monkeypatch.setenv("FAST_LANE_TARGETS", json.dumps([{"ecosystem": "npm", "package": "fixture", "version": "1.0", "_queue_id": "d" * 64}]))
    monkeypatch.setenv("FAST_LANE_REPORT_PATH", str(tmp_path / "report.json"))
    monkeypatch.setattr(fast_lane, "NOT_FOUND_DELAY_SECONDS", 0)
    calls = []

    def lagging(*_):
        calls.append(1)
        raise fast_lane.PublishTimePending("fixture@1.0 has no publish time yet")

    monkeypatch.setattr(fast_lane, "resolve_release", lagging)
    assert fast_lane.main() == 0
    result = json.loads((tmp_path / "report.json").read_text())["results"][0]
    assert len(calls) == fast_lane.NOT_FOUND_RETRIES + 1
    assert result["status"] == "retryable_failure" and result["retryable"] is True
    assert result["failure_category"] == "publish_time_pending"


def test_a_lagging_publish_time_is_picked_up_on_a_later_attempt(tmp_path, monkeypatch):
    from secopsai.research_intake import RegistryHTTPError

    monkeypatch.setenv("FAST_LANE_TARGETS", json.dumps([{"ecosystem": "npm", "package": "fixture", "version": "1.0", "_queue_id": "e" * 64}]))
    monkeypatch.setenv("FAST_LANE_REPORT_PATH", str(tmp_path / "report.json"))
    monkeypatch.setattr(fast_lane, "NOT_FOUND_DELAY_SECONDS", 0)
    monkeypatch.setattr(fast_lane, "STALE_AFTER_SECONDS", 10**9)
    answers = [fast_lane.PublishTimePending("fixture@1.0 has no publish time yet"), {"version": "1.0", "published_at": "2026-10-18T00:00:00Z", "previous_version": "0.9"}]

    def lagging(*_):
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(fast_lane, "resolve_release", lagging)
    monkeypatch.setattr(fast_lane, "investigate", lambda *_: (_ for _ in ()).throw(RegistryHTTPError(403)))
    assert fast_lane.main() == 0
    assert json.loads((tmp_path / "report.json").read_text())["results"][0]["http_status"] == 403


def test_npm_release_missing_from_the_time_map_is_pending():
    fetcher = _Fetcher({"https://registry.npmjs.org/fixture": {"dist-tags": {"latest": "1.0"}, "time": {"0.9": "2026-10-01T00:00:00Z"}}})
    with pytest.raises(fast_lane.PublishTimePending):
        fast_lane.resolve_release(fetcher, "npm", "fixture", "1.0")



@pytest.mark.parametrize("severity,paused,emailed", [("critical", False, True), ("high", False, False), ("critical", True, False)])
def test_only_critical_emails_immediately_and_every_alert_reaches_the_digest(monkeypatch, severity, paused, emailed):
    import secopsai.research_delivery as delivery

    sent = []
    monkeypatch.setattr(delivery, "send_email", lambda **kwargs: sent.append(kwargs) or {"status": "sent"})
    monkeypatch.setattr(delivery, "send_signed_webhook", lambda **kwargs: {"status": "sent"})
    monkeypatch.setenv("SECOPSAI_RESEARCH_ALERT_EMAIL", "research@example.test")
    monkeypatch.setenv("SECOPSAI_SMTP_PASSWORD", "x")
    monkeypatch.delenv("SECOPSAI_RESEARCH_ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.setenv("SECOPSAI_EMAIL_PAUSED", "true" if paused else "")
    monkeypatch.setattr(fast_lane, "release_status", lambda *args: "listed")
    decision = {"severity": severity, "reasons": ["new install hook"], "new_indicators": [], "added_files": [], "install_hooks": ["postinstall"],
                "publisher_changed": False, "yara": [], "yara_findings": [], "pipeline_verdict": None}
    release = {"version": "2.0.0", "previous_version": "1.0.0", "published_at": "2026-11-15T10:00:00Z"}
    out = fast_lane.deliver({"ecosystem": "npm", "package": "demo"}, release, decision, datetime(2026, 11, 15, 10, 5, tzinfo=timezone.utc))
    assert bool(sent) is emailed
    assert out["digest"]["emailed"] is emailed and out["digest"]["package"] == "demo"
    assert out["digest"]["dashboard_id"].startswith("RAL-WEB-")
    if emailed:
        assert "dashboard.secopsai.dev" in sent[0]["body"]
def test_npm_unpublished_time_entries_are_not_releases_or_previous_versions():
    # npm keeps "time" entries for unpublished versions. Such a version has no
    # tarball in "versions", so it can be neither the target nor the comparison base.
    fetcher = _Fetcher({
        "https://registry.npmjs.org/@wild-framework%2Fopenapi": {
            "dist-tags": {"latest": "0.2.20"},
            "time": {
                "0.2.18": "2026-10-01T00:00:00.000Z",
                "0.2.19": "2026-10-10T00:00:00.000Z",
                "0.2.20": "2026-11-16T21:00:00.000Z",
            },
            "versions": {"0.2.18": {"dist": {}}, "0.2.20": {"dist": {}}},
        },
    })
    release = fast_lane.resolve_release(fetcher, "npm", "@wild-framework/openapi", "0.2.20")
    assert release == {"version": "0.2.20", "published_at": "2026-11-16T21:00:00.000Z", "previous_version": "0.2.18"}

    unpublished_target = _Fetcher({
        "https://registry.npmjs.org/fixture": {
            "dist-tags": {"latest": "1.0.0"},
            "time": {"1.0.0": "2026-11-16T21:00:00.000Z", "1.0.1": "2026-11-16T21:05:00.000Z"},
            "versions": {"1.0.0": {"dist": {}}},
        },
    })
    with pytest.raises(fast_lane.PublishTimePending):
        fast_lane.resolve_release(unpublished_target, "npm", "fixture", "1.0.1")


def test_a_yara_warning_with_nothing_else_new_is_low():
    # 81% judged benign by model triage (2026-11-15..18); still triaged and shown.
    assert fast_lane.assess(_result(yara_level="warning"))["severity"] == "low"
    assert fast_lane.assess(_result(yara_level="warning", right_ids=("outbound-network",)))["severity"] == "medium"
    assert fast_lane.assess(_result(yara_level="warning", publisher_changed=True))["severity"] == "medium"
    assert fast_lane.assess(_result(yara_level="alert"))["severity"] == "high"



# ---------------------------------------------------------------- urgent auto-check

VERDICT = {"finding_verdict": "false_positive", "malicious_probability": 15, "finding_confidence": 70,
           "summary": "Secrets match is an exclusion list."}


def _decision(diff, publisher_changed=False):
    return {"severity": "critical", "reasons": ["behaviour rules: BEH_PTH_STARTUP_HARVEST"], "new_indicators": [], "added_files": [],
            "install_hooks": [], "publisher_changed": publisher_changed, "yara": {}, "yara_findings": [],
            "behaviour_findings": [{"rule_id": "BEHAVIOUR:BEH_PTH_STARTUP_HARVEST"}], "pipeline_verdict": None,
            "triage_prescan": {"status": "hit", "diff": diff}}


SAME = {"previous_version": "0.2.25", "new_flags": []}
ADDED = {"previous_version": "1.26.0", "new_flags": ["pth_startup_code", "pth_chain_network"]}


@pytest.mark.parametrize("diff,publisher,status,verdict,reading", [
    (SAME, False, "listed", {"status": "ready", "verdict": "false_positive", "probability": 15, "confidence": 70}, "likely benign"),
    (ADDED, False, "listed", {"status": "ready", "verdict": "true_positive", "probability": 95, "confidence": 90}, "likely malicious"),
    (ADDED, True, "listed", {}, "likely malicious"),
    (ADDED, False, "listed", {"status": "ready", "verdict": "false_positive", "probability": 10, "confidence": 60}, "needs review"),
    (SAME, False, "listed", {}, "needs review"),
    (SAME, True, "listed", {"status": "ready", "verdict": "false_positive", "probability": 10, "confidence": 60}, "needs review"),
    (SAME, False, "listed", {"status": "ready", "verdict": "false_positive", "probability": 40, "confidence": 60}, "needs review"),
    ({"note": "first release"}, False, "listed", {"status": "ready", "verdict": "false_positive", "probability": 5, "confidence": 80}, "needs review"),
])
def test_auto_check_reading(diff, publisher, status, verdict, reading):
    check = fast_lane.auto_check(_decision(diff, publisher), status, verdict)
    assert check["reading"].startswith(reading)
    assert [item["check"] for item in check["checks"]] == ["registry", "new", "publisher", "source", "model"]


@pytest.mark.parametrize("source,model,reading", [
    ({"result": "differs", "repository": "o/r", "tag": "v1", "files": [{"path": "w/x.pth", "outcome": "missing", "install_time": True}]},
     {}, "likely malicious"),  # new hook not in the repository
    ({"result": "differs", "repository": "o/r", "tag": "v1", "files": []},
     {"status": "ready", "verdict": "false_positive", "probability": 5, "confidence": 80}, "needs review"),
])
def test_a_hook_missing_from_the_repository_weighs_against_the_release(source, model, reading):
    decision = {**_decision(ADDED if not model else SAME), "source_match": source}
    check = fast_lane.auto_check(decision, "listed", model)
    assert check["reading"].startswith(reading)
    assert [item for item in check["checks"] if item["check"] == "source"][0]["result"] == "bad"


def test_auto_check_marks_a_removed_release():
    check = fast_lane.auto_check(_decision(SAME), "removed", {})
    assert check["checks"][0] == {"check": "registry", "result": "bad", "detail": "removed from the registry (often: already reported)"}


def test_release_status_reads_the_registry():
    from secopsai.research_intake import RegistryHTTPError

    class Gone:
        def get(self, url, **kwargs):
            raise RegistryHTTPError(404)

    assert fast_lane.release_status(Gone(), "pypi", "x", "1.0") == "removed"
    assert fast_lane.release_status(_Fetcher({"https://pypi.org/pypi/x/1.0/json": {"urls": [{"yanked": True}]}}), "pypi", "x", "1.0") == "yanked"
    assert fast_lane.release_status(_Fetcher({"https://pypi.org/pypi/x/1.0/json": {"urls": [{"yanked": False}]}}), "pypi", "x", "1.0") == "listed"
    npm = _Fetcher({"https://registry.npmjs.org/x": {"versions": {"1.0": {}, "2.0": {"deprecated": "do not use"}}}})
    assert [fast_lane.release_status(npm, "npm", "x", v) for v in ("1.0", "2.0", "3.0")] == ["listed", "deprecated", "removed"]


class _Core:
    def __init__(self, pages):
        self.pages, self.calls = list(pages), []

    def triage_results(self, *, since="", limit=100):
        self.calls.append(since)
        return self.pages.pop(0) if self.pages else {"results": []}


def test_wait_for_verdict_finds_the_job_across_pages(monkeypatch):
    monkeypatch.setattr(fast_lane, "VERDICT_POLL_SECONDS", 0)
    other = [{"artifact_id": f"other-{i}", "status": "succeeded", "result": {}} for i in range(200)]
    core = _Core([{"results": other, "truncated": True, "next_since": "t2"},
                  {"results": [{"artifact_id": "FASTLANE-1", "status": "succeeded", "result": VERDICT}]}])
    monkeypatch.setattr("secopsai.decision_contracts.validate_action_result", lambda action, result: None)
    found = fast_lane.wait_for_verdict(core, "FASTLANE-1", "t1", 0)
    assert core.calls == ["t1", "t2"]
    assert found["status"] == "ready" and found["verdict"] == "false_positive"


def test_wait_for_verdict_returns_a_valid_verdict_and_gives_up_in_time(monkeypatch):
    monkeypatch.setattr(fast_lane, "VERDICT_POLL_SECONDS", 0)
    monkeypatch.setattr("secopsai.decision_contracts.validate_action_result", lambda action, result: None)
    core = _Core([{"results": [{"artifact_id": "FASTLANE-1", "status": "succeeded", "result": VERDICT}]}])
    assert fast_lane.wait_for_verdict(core, "FASTLANE-1", "t1", 0) == {
        "status": "ready", "verdict": "false_positive", "probability": 15, "confidence": 70, "summary": "Secrets match is an exclusion list."}
    assert fast_lane.wait_for_verdict(_Core([]), "FASTLANE-1", "t1", 0) == {}
    assert fast_lane.wait_for_verdict(_Core([{"results": [{"artifact_id": "FASTLANE-1", "status": "failed"}]}]), "FASTLANE-1", "t1", 0) == {"status": "failed"}


def test_wait_for_verdict_rejects_an_answer_that_fails_the_contract():
    core = _Core([{"results": [{"artifact_id": "FASTLANE-1", "status": "succeeded", "result": {"finding_verdict": "false_positive"}}]}])
    assert fast_lane.wait_for_verdict(core, "FASTLANE-1", "t1", 0) == {"status": "invalid"}


def test_urgent_email_leads_with_the_auto_check_and_is_never_suppressed(monkeypatch):
    import secopsai.research_delivery as delivery

    sent = []
    monkeypatch.setattr(delivery, "send_email", lambda **kwargs: sent.append(kwargs) or {"status": "sent"})
    monkeypatch.setattr(delivery, "send_signed_webhook", lambda **kwargs: {"status": "sent"})
    monkeypatch.setenv("SECOPSAI_RESEARCH_ALERT_EMAIL", "research@example.test")
    monkeypatch.setenv("SECOPSAI_SMTP_PASSWORD", "x")
    monkeypatch.setenv("SECOPSAI_URGENT_FINDING_EMAIL", "1")
    monkeypatch.setenv("SECOPSAI_EMAIL_PAUSED", "true")
    monkeypatch.delenv("SECOPSAI_RESEARCH_ALERT_WEBHOOK_URL", raising=False)
    monkeypatch.setattr(fast_lane, "release_status", lambda *args: "listed")
    monkeypatch.setattr(fast_lane, "source_check", lambda *args: {"result": "matches", "repository": "pirateface/pirateface_cli", "tag": "v0.2.26",
                                                                   "files": [{"path": "w/pirateface.pth", "outcome": "same", "install_time": True}]})
    monkeypatch.setattr(fast_lane, "wait_for_verdict", lambda *args: {"status": "ready", "verdict": "false_positive", "probability": 15,
                                                                       "confidence": 70, "summary": "Exclusion list."})

    class Client:
        enabled = True

        def __init__(self):
            pass

        def queue_triage_jobs(self, jobs):
            return {"count": len(jobs)}

    monkeypatch.setattr("secopsai.core_edge_client.CoreEdgeClient", Client)
    release = {"version": "0.2.26", "previous_version": "0.2.25", "published_at": "2026-11-18T08:52:16Z"}
    out = fast_lane.deliver({"ecosystem": "pypi", "package": "pirateface"}, release, _decision(SAME), datetime(2026, 11, 18, 9, 40, tzinfo=timezone.utc))
    assert out["email"] == "sent" and out["auto_check"]["reading"].startswith("likely benign")
    assert sent[0]["subject"] == "[SecOpsAI fast lane] URGENT (likely benign) CRITICAL: pirateface@0.2.26"
    body = sent[0]["body"]
    assert body.startswith("Auto-check: likely benign: confirm and close")
    assert "[ok] nothing risky is new since 0.2.25" in body and "[ok] model: false positive, 15% likely malicious" in body
    assert "Nothing was closed automatically" in body
    assert "[ok] start-up/flagged files match pirateface/pirateface_cli at v0.2.26" in body
    assert out["source_match"]["result"] == "matches"
