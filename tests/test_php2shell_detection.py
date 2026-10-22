"""RULE-311: PHP2Shell (CVE-2026-109618/109619) request indicators.

Indicators follow Corelight's php2shell-detect Zeek package (BSD-3-Clause).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detect import DETECTION_RULES, detect_php2shell, run_detection  # noqa: E402

PROGRESS = ('------x\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nabc\r\n'
            '------x\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\nAAAA\r\n------x--')


def _http(event_id, ts="2026-10-21T10:00:00Z", **fields):
    return {"event_id": event_id, "event_type": "http", "timestamp": ts, "src_ip": "37.19.200.5", **fields}


def test_upload_progress_followed_by_a_request_in_the_same_session_is_the_crash_sequence():
    cookie = {"Cookie": "PHPSESSID=abc123"}
    events = [
        _http("trigger", method="POST", url="/index.php", body=PROGRESS, headers=cookie),
        _http("followup", ts="2026-10-21T10:00:20Z", method="GET", url="/index.php", headers=cookie),
    ]
    assert detect_php2shell(events) == ["trigger", "followup"]


def test_a_lone_upload_progress_bar_or_a_late_request_is_not_reported():
    cookie = {"Cookie": "PHPSESSID=abc123"}
    assert detect_php2shell([_http("bar", method="POST", body=PROGRESS, headers=cookie)]) == []
    late = [_http("bar", method="POST", body=PROGRESS, headers=cookie),
            _http("late", ts="2026-10-21T10:05:00Z", method="GET", headers=cookie)]
    assert detect_php2shell(late) == []
    other_session = [_http("bar", method="POST", body=PROGRESS, headers=cookie),
                     _http("other", ts="2026-10-21T10:00:10Z", method="GET", headers={"Cookie": "PHPSESSID=zzz"})]
    assert detect_php2shell(other_session) == []


def test_field_name_match_is_exact_and_case_sensitive():
    lower = PROGRESS.replace("PHP_SESSION_UPLOAD_PROGRESS", "php_session_upload_progress")
    events = [_http("t", method="POST", body=lower, headers={"Cookie": "PHPSESSID=a"}),
              _http("f", ts="2026-10-21T10:00:05Z", method="GET", headers={"Cookie": "PHPSESSID=a"})]
    assert detect_php2shell(events) == []


def test_request_level_indicators_fire_on_their_own():
    flood = "\r\n".join(["------x", 'Content-Disposition: form-data; name="a"'] + ["X: Y"] * 128)
    events = [
        _http("header-flood", method="POST", body=flood),
        _http("integer-overflow", method="POST", body='a:1:{i:123456789012345678901;s:1:"x";}'),
        _http("integer-collisions", method="POST", body="a:3:{i:0;N;i:4294967296;N;i:8589934592;N;}"),
        _http("large-form-key", method="POST", body="k" * 65536 + "=1"),
        _http("ordinary", method="POST", body="user=a&pass=b"),
        _http("small-flood", method="POST", body="\r\n".join(["X: Y"] * 10)),
    ]
    assert detect_php2shell(events) == ["header-flood", "integer-overflow", "integer-collisions", "large-form-key"]


def test_rule_is_registered_and_runs_in_the_pipeline():
    rule = next(item for item in DETECTION_RULES if item["id"] == "RULE-311")
    assert rule["mitre"] == "T1190"
    result = run_detection([_http("pipeline", method="POST", body="a:1:{i:99999999999999999999;N;}")])
    assert "pipeline" in result["rule_results"].get("RULE-311", [])
