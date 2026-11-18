"""Shadow test of automatic closure (scripts/closure_shadow.py): read-only."""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("closure_shadow", Path(__file__).resolve().parents[1] / "scripts" / "closure_shadow.py")
shadow = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shadow)

NOW = dt.datetime(2026, 11, 18, tzinfo=dt.timezone.utc)
OLD, NEW = "2026-10-20T00:00:00Z", "2026-11-15T00:00:00Z"


def _result(p=5, c=80, verdict="false_positive", complete=True):
    return {"assessment_version": "decision-v2", "finding_verdict": verdict, "malicious_probability": p, "finding_confidence": c,
            "disposition_recommendation": "false_positive", "automatic_closure_eligible": complete,
            "evidence_coverage": {"complete": complete, "contract": "context-v5"}, "provider": "opencodex:anthropic", "model_version": "m"}


def _row(name, result, when=OLD, ecosystem="npm"):
    return {"ecosystem": ecosystem, "package": name, "version": "1.0.0", "result_json": json.dumps(result), "updated_at": when}


def test_only_settled_benign_confident_complete_verdicts_would_close():
    rows = [_row("a", _result()), _row("b", _result(p=11)), _row("c", _result(c=69)), _row("d", _result(complete=False)),
            _row("e", _result(verdict="true_positive")), _row("f", _result(), when=NEW), _row("g", _result(), ecosystem="crates")]
    records = {r["package"]: r for r in shadow.classify(rows, now=NOW, settle_days=14)}
    assert [n for n, r in records.items() if r["would_close"]] == ["a", "f", "g"]
    assert records["a"]["settled"] and not records["f"]["settled"]
    assert records["d"]["reason"] == "incomplete_evidence" and records["b"]["reason"] == "review_required"
    assert not records["g"]["evaluated_ecosystem"]


def test_a_closure_later_marked_malicious_fails_the_shadow():
    rows = [_row(f"p{i}", _result()) for i in range(shadow.MIN_SETTLED_CLOSES)]
    records = shadow.classify(rows, now=NOW, settle_days=14)
    clean = shadow.report(records, {}, {}, settle_days=14)
    assert clean["shadow_clean"] and clean["would_close_settled"] == shadow.MIN_SETTLED_CLOSES
    failed = shadow.report(records, {3: ["MAL-2026-1"]}, {7: "removed", 8: "listed"}, settle_days=14)
    assert not failed["shadow_clean"] and failed["verdict"].startswith("failed")
    assert failed["wrong_closures"][0]["package"] == "p3" and failed["wrong_closures"][0]["mal_ids"] == ["MAL-2026-1"]
    assert [r["package"] for r in failed["removed_from_registry"]] == ["p7"]
    assert "Wrong closures" in shadow.markdown(failed)
    short = shadow.report(records[:10], {}, {}, settle_days=14)
    assert not short["shadow_clean"] and short["verdict"].startswith("insufficient")


def test_osv_is_asked_for_exact_versions_and_a_short_answer_is_an_error():
    items = [{"ecosystem": "npm", "package": "a", "version": "1.0.0"}, {"ecosystem": "pypi", "package": "b", "version": "2.0"}]
    sent = []

    def post(body):
        sent.append(body)
        return {"results": [{"vulns": [{"id": "GHSA-x"}]}, {"vulns": [{"id": "MAL-2026-9"}]}]}

    assert shadow.osv_malicious(items, post=post) == {1: ["MAL-2026-9"]}
    assert sent[0]["queries"][1] == {"package": {"name": "b", "ecosystem": "PyPI"}, "version": "2.0"}
    with pytest.raises(ValueError):
        shadow.osv_malicious(items, post=lambda body: {"results": []})


class _Response:
    def __init__(self, status, body=None):
        self.status_code, self.body = status, body or {}

    def json(self):
        return self.body


@pytest.mark.parametrize("item,response,expected", [
    ({"ecosystem": "pypi", "package": "a", "version": "1"}, _Response(404), "removed"),
    ({"ecosystem": "pypi", "package": "a", "version": "1"}, _Response(200, {"urls": [{"yanked": True}]}), "removed"),
    ({"ecosystem": "pypi", "package": "a", "version": "1"}, _Response(200, {"urls": [{"yanked": False}]}), "listed"),
    ({"ecosystem": "npm", "package": "@s/a", "version": "1"}, _Response(200, {"versions": {"2": {}}}), "removed"),
    ({"ecosystem": "npm", "package": "@s/a", "version": "1"}, _Response(200, {"versions": {"1": {}}}), "listed"),
])
def test_registry_status(item, response, expected):
    assert shadow.registry_status(item, get=lambda url: response) == expected
    assert shadow.registry_status(item, get=lambda url: (_ for _ in ()).throw(OSError())) == "unknown"
