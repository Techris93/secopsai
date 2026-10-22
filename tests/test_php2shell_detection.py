"""RULE-311: PHP2Shell (CVE-2026-109618/109619) session upload-progress abuse."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detect import DETECTION_RULES, detect_php2shell, run_detection  # noqa: E402

MULTIPART = ('------x\r\nContent-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\nabc\r\n'
             '------x\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\n\r\nAAAA\r\n------x--')


def _http(event_id, **fields):
    return {"event_id": event_id, "event_type": "http", "timestamp": "2026-10-21T10:00:00Z", "src_ip": "37.19.200.5", **fields}


def test_multipart_upload_progress_post_is_detected():
    events = [
        _http("hit-body", method="POST", url="/index.php", body=MULTIPART,
              headers={"Content-Type": "multipart/form-data; boundary=----x", "Cookie": "PHPSESSID=abc"}),
        _http("hit-request-line", request="POST /upload.php HTTP/1.1", body="php_session_upload_progress=1"),
    ]
    assert detect_php2shell(events) == ["hit-body", "hit-request-line"]


def test_ordinary_traffic_and_get_requests_are_not_detected():
    events = [
        _http("get", method="GET", url="/?PHP_SESSION_UPLOAD_PROGRESS=1"),
        _http("plain-post", method="POST", url="/login.php", body="user=a&pass=b"),
        {"event_id": "not-http", "event_type": "process", "command": "echo PHP_SESSION_UPLOAD_PROGRESS"},
    ]
    assert detect_php2shell(events) == []


def test_rule_is_registered_and_runs_in_the_pipeline():
    rule = next(item for item in DETECTION_RULES if item["id"] == "RULE-311")
    assert rule["mitre"] == "T1190"
    result = run_detection([_http("pipeline", method="POST", url="/index.php", body=MULTIPART)])
    assert "pipeline" in result["rule_results"].get("RULE-311", [])
