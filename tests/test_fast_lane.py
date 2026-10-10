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
