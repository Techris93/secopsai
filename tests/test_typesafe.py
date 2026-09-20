from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from secopsai.codex_bridge import BridgeSettings, _invoke_codex, _provider_for_model, list_models
from secopsai.intelligence import validate_bridge_result
from secopsai.typesafe_adapter import (
    TYPESAFE_API_URL,
    build_prioritize_questions,
    build_publication_safety_questions,
    build_triage_questions,
    evaluate_system_one,
    get_typesafe_api_key,
    invoke_typesafe_action,
    is_typesafe_available,
    probe_typesafe,
    set_typesafe_api_key,
)


def test_typesafe_availability(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert not is_typesafe_available()
    assert get_typesafe_api_key() == ""

    monkeypatch.setenv("TYPESAFE_API_KEY", "ts_test_key_12345")
    assert is_typesafe_available()
    assert get_typesafe_api_key() == "ts_test_key_12345"


def test_set_typesafe_api_key(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    monkeypatch.setattr("pathlib.Path.cwd", lambda: tmp_path)

    # Test user scope (~/.secopsai/typesafe.key)
    path = set_typesafe_api_key("ts_persisted_user_key", scope="user")
    assert "typesafe.key" in path
    assert get_typesafe_api_key() == "ts_persisted_user_key"

    # Test env scope (.env)
    env_path = set_typesafe_api_key("ts_persisted_env_key", scope="local")
    assert ".env" in env_path
    # Environment variable takes precedence if set
    monkeypatch.setenv("TYPESAFE_API_KEY", "ts_override")
    assert get_typesafe_api_key() == "ts_override"
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    assert get_typesafe_api_key() in ("ts_persisted_env_key", "ts_persisted_user_key")


def test_probe_typesafe_unconfigured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    res = probe_typesafe()
    assert res["status"] == "unconfigured"
    assert res["ready"] is False


def test_probe_typesafe_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "ts_test_key_12345")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch("requests.post", return_value=mock_resp) as mock_post:
        res = probe_typesafe()
        assert res["status"] == "ready"
        assert res["ready"] is True
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert args[0] == TYPESAFE_API_URL
        assert kwargs["headers"]["Authorization"] == "Bearer ts_test_key_12345"


def test_build_question_suites() -> None:
    triage = build_triage_questions()
    assert "finding_verdict" in triage
    assert triage["finding_verdict"]["type"] == "choice"
    assert "true_positive" in triage["finding_verdict"]["criteria"]
    assert triage["risk_severity"]["type"] == "score"
    assert triage["containment_needed"]["type"] == "noul"

    pub_safety = build_publication_safety_questions()
    assert "safe_to_publish" in pub_safety
    assert pub_safety["safe_to_publish"]["type"] == "noul"
    assert pub_safety["verdict_recommendation"]["type"] == "choice"
    assert pub_safety["publication_risk"]["type"] == "score"

    prio = build_prioritize_questions()
    assert "priority_tier" in prio
    assert prio["priority_tier"]["type"] == "choice"


def test_evaluate_system_one_requires_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    with pytest.raises(ValueError, match="TYPESAFE_API_KEY is required"):
        evaluate_system_one(state="test state", questions={"q": {"type": "noul", "instructions": "test"}})


def test_evaluate_system_one_mocked_response() -> None:
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {
        "model": "jev-latest",
        "answers": {
            "is_malicious": {"type": "noul", "noul": 0.95},
        },
        "usage": {"input_tokens": 100, "output_tokens": 20},
    }
    with patch("requests.post", return_value=mock_resp):
        res = evaluate_system_one(
            state="test finding",
            questions={"is_malicious": {"type": "noul", "instructions": "Is it malicious?"}},
            api_key="ts_test_123",
        )
        assert res["model"] == "jev-latest"
        assert res["answers"]["is_malicious"]["noul"] == 0.95


def test_invoke_typesafe_triage_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "ts_test_123")
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {
        "model": "jev-latest",
        "answers": {
            "finding_verdict": {
                "type": "choice",
                "choice": "true_positive",
                "probabilities": {"true_positive": 0.92, "false_positive": 0.03, "benign_expected": 0.05},
                "confidence": 0.89,
            },
            "exposure_assessment": {
                "type": "choice",
                "choice": "affected",
                "confidence": 0.94,
            },
            "automation_recommendation": {
                "type": "choice",
                "choice": "escalate",
                "confidence": 0.88,
            },
            "risk_severity": {
                "type": "score",
                "score": 3.4,
                "confidence": 0.85,
            },
            "containment_needed": {
                "type": "noul",
                "noul": 0.82,
            },
        },
    }
    with patch("requests.post", return_value=mock_resp):
        req = {
            "action": {"name": "triage_finding"},
            "context": {
                "finding_id": "FINDING-99",
                "title": "Exposed AWS Access Key in Public S3 Bucket",
                "severity": "critical",
            },
        }
        res = invoke_typesafe_action(req)
        assert res["finding_verdict"] == "true_positive"
        assert res["disposition_recommendation"] == "true_positive"
        assert res["exposure_assessment"] == "affected"
        assert res["automation_recommendation"] == "escalate"
        assert res["verdict_recommendation"] == "credible"
        assert res["finding_confidence"] == 89
        assert any("containment" in act.lower() for act in res["recommended_actions"])
        # Validate that the formatted dictionary passes SecOpsAI schema validation
        validated = validate_bridge_result("triage_finding", res, provider="typesafe_ai:jev")
        assert validated["provider"] == "typesafe_ai:jev"
        assert validated["data"]["finding_verdict"] == "true_positive"


def test_invoke_typesafe_publication_safety(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "ts_test_123")
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {
        "model": "jev-latest",
        "answers": {
            "safe_to_publish": {"type": "noul", "noul": 0.92},
            "credential_leakage": {"type": "noul", "noul": 0.01},
            "verdict_recommendation": {
                "type": "choice",
                "choice": "credible",
                "confidence": 0.90,
            },
            "publication_risk": {
                "type": "score",
                "score": 0.8,
                "confidence": 0.91,
            },
        },
    }
    with patch("requests.post", return_value=mock_resp):
        req = {
            "action": {"name": "review_publication_safety"},
            "context": {
                "case_id": "RSC-001",
                "title": "Coordinated Disclosure of Zero-Day in Gateway",
                "severity": "high",
            },
        }
        res = invoke_typesafe_action(req)
        assert res["verdict_recommendation"] == "credible"
        assert res["verdict_confidence"] == 90
        assert "APPROVED" in res["summary"]
        assert len(res["publication_risks"]) == 0
        validated = validate_bridge_result("review_publication_safety", res, provider="typesafe_ai:jev")
        assert validated["provider"] == "typesafe_ai:jev"


def test_codex_bridge_includes_typesafe_in_catalog() -> None:
    models = list_models()
    matching = [m for m in models["models"] if m["id"] == "typesafe/jev-latest"]
    assert len(matching) == 1
    assert matching[0]["provider"] == "typesafe_ai"
    assert matching[0]["name"] == "TypeSafe Jev (System One)"


def test_provider_for_model_resolves_typesafe() -> None:
    assert _provider_for_model("typesafe/jev-latest", {}) == "typesafe_ai:jev"
    assert _provider_for_model("typesafe-ai/jev", {}) == "typesafe_ai:jev"


def test_codex_bridge_routes_to_typesafe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TYPESAFE_API_KEY", "ts_test_123")
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {
        "model": "jev-latest",
        "answers": {
            "finding_verdict": {"type": "choice", "choice": "false_positive", "confidence": 0.95},
            "exposure_assessment": {"type": "choice", "choice": "not_observed", "confidence": 0.90},
            "automation_recommendation": {"type": "choice", "choice": "suppress_once", "confidence": 0.92},
            "risk_severity": {"type": "score", "score": 0.2, "confidence": 0.95},
            "containment_needed": {"type": "noul", "noul": 0.01},
        },
    }
    with patch("requests.post", return_value=mock_resp):
        settings = BridgeSettings(model="typesafe/jev-latest")
        req = {
            "action": {"name": "triage_finding"},
            "context": {"title": "Noise Alert", "severity": "low"},
        }
        res = _invoke_codex(req, settings, MagicMock(), model="typesafe/jev-latest")
        assert res["finding_verdict"] == "false_positive"
        assert res["disposition_recommendation"] == "false_positive"
        assert res["automation_recommendation"] == "suppress_once"
