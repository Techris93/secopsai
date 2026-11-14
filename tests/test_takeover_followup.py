import json
from datetime import datetime, timezone

from secopsai import takeover_followup

NOW = datetime(2026, 11, 20, tzinfo=timezone.utc)
START = datetime(2026, 11, 14, tzinfo=timezone.utc)


def _write(path, ident, eco, name, versions, published):
    path.write_text(json.dumps({"id": ident, "published": published,
                                "affected": [{"package": {"ecosystem": eco, "name": name}, "versions": versions}]}))


def test_precision_and_recall_from_later_reports(tmp_path):
    _write(tmp_path / "a.json", "MAL-1", "npm", "hijacked", ["2.0.1"], "2026-11-15T10:00:00Z")
    _write(tmp_path / "b.json", "MAL-2", "PyPI", "Missed_Pkg", ["0.3"], "2026-11-16T10:00:00Z")
    _write(tmp_path / "c.json", "MAL-3", "npm", "old-typo", ["1.0.0"], "2025-01-01T00:00:00Z")
    corpus = takeover_followup.reports([tmp_path], since=START)
    flagged = [
        {"ecosystem": "npm", "package": "hijacked", "version": "2.0.1", "published_at": "2026-11-15T09:00:00Z"},
        {"ecosystem": "npm", "package": "benign", "version": "1.1.0", "published_at": "2026-11-15T09:00:00Z"},
        {"ecosystem": "pypi", "package": "too-new", "version": "1.0", "published_at": "2026-11-19T09:00:00Z"},
    ]
    result = takeover_followup.evaluate(flagged, corpus, stream_start=START, now=NOW)
    assert (result["settled"], result["confirmed"], result["precision"]) == (2, 1, 0.5)
    assert (result["reports_in_window"], result["reports_flagged"], result["recall"]) == (2, 1, 0.5)


def test_nothing_to_judge_is_not_a_score(tmp_path):
    result = takeover_followup.evaluate([], takeover_followup.reports([tmp_path], since=START), stream_start=START, now=NOW)
    assert result["precision"] is None and result["recall"] is None
