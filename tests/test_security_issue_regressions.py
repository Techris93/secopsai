from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yaml

import adaptive_intelligence_pipeline as pipeline_mod
import adaptive_rule_validator as validator_mod


ROOT = Path(__file__).resolve().parents[1]


def _load_send_report_module():
    path = ROOT / "scripts" / "secopsai_send_report.py"
    spec = importlib.util.spec_from_file_location("secopsai_send_report", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_telegram_report_delivery_requires_explicit_chat_id(monkeypatch):
    send_report = _load_send_report_module()

    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "dummy-token")
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    monkeypatch.setattr(
        "sys.argv",
        ["secopsai_send_report.py", "--kind", "status-summary"],
    )

    with mock.patch.object(send_report, "_run_report") as run_report:
        with mock.patch.object(send_report, "_send_telegram") as send_telegram:
            try:
                send_report.main()
            except SystemExit as exc:
                assert str(exc) == "missing --chat-id or TELEGRAM_CHAT_ID; report delivery is disabled by default"
            else:
                raise AssertionError("missing chat ID should abort report delivery")

    run_report.assert_not_called()
    send_telegram.assert_not_called()


def test_committed_configs_do_not_contain_fixed_telegram_chat_id():
    fixed_chat_id = "".join(["623", "118", "122"])
    checked_paths = [
        ROOT / "scripts" / "secopsai_send_report.py",
        ROOT / "com.openclaw.secopsai.adaptive-intel.plist",
    ]

    for path in checked_paths:
        assert fixed_chat_id not in path.read_text(encoding="utf-8")


def test_adaptive_validator_writes_review_manifest_and_restores_detect(tmp_path, monkeypatch):
    detect_path = tmp_path / "detect.py"
    original_detect = "DETECTION_RULES = []\n\n\ndef run_detection(events):\n    return {'total_detections': 0}\n"
    detect_path.write_text(original_detect, encoding="utf-8")

    rules_dir = tmp_path / "auto_rules"
    rules_dir.mkdir()
    (rules_dir / "auto_rule_auto_001.py").write_text("def detect_auto_001(events):\n    return []\n", encoding="utf-8")
    manifest_path = rules_dir / "review_required.json"

    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(list(cmd))
        if len(calls) == 1:
            return SimpleNamespace(returncode=0, stdout=">>> F1_SCORE=0.500000 <<<\n", stderr="")
        return SimpleNamespace(returncode=0, stdout=">>> F1_SCORE=0.700000 <<<\n", stderr="")

    monkeypatch.setattr(validator_mod, "AUTO_RULES_DIR", str(rules_dir))
    monkeypatch.setattr(validator_mod, "DETECT_PY_PATH", str(detect_path))
    monkeypatch.setattr(validator_mod, "REVIEW_MANIFEST_PATH", str(manifest_path))
    monkeypatch.setattr(validator_mod.subprocess, "run", fake_run)

    validator = validator_mod.RuleValidator()
    assert validator.run() is True

    assert detect_path.read_text(encoding="utf-8") == original_detect
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["status"] == "needs_human_review"
    assert manifest["candidate_rule_files"] == ["auto_rule_auto_001.py"]
    assert abs(manifest["improvement"] - 0.2) < 0.000001
    assert all(call[0] == "python3" and call[1] == "evaluate.py" for call in calls)


def test_adaptive_pipeline_baseline_eval_failure_blocks_validation(monkeypatch, tmp_path):
    monkeypatch.setattr(pipeline_mod, "WORKSPACE_DIR", tmp_path)
    pipeline = pipeline_mod.AdaptiveIntelligencePipeline()

    monkeypatch.setattr(
        pipeline_mod.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=2, stdout="", stderr="boom"),
    )

    assert pipeline.step_3_validate() is False
    assert "Validation: evaluate.py exited 2" in pipeline.results["errors"]


def test_release_workflows_do_not_allow_known_bad_artifacts_to_publish():
    test_build = (ROOT / ".github" / "workflows" / "test-and-build.yml").read_text(encoding="utf-8")
    security = (ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    security_scan = (ROOT / ".github" / "workflows" / "security-scan.yml").read_text(encoding="utf-8")

    assert "Type check with mypy\n        continue-on-error" not in test_build
    assert "Test detection rules\n        run:" in test_build
    assert "python -m pytest tests/ -v --cov=detect" in test_build
    assert "exit-code: \"0\"" not in security
    assert "scanners: \"secret\"" in security
    assert "scan-type: \"secret\"" not in security
    assert "sarif_file: |\n" not in security
    assert "hashFiles('trivy-fs-results.sarif') != ''" in security
    assert "hashFiles('trivy-secret-results.sarif') != ''" in security
    assert "hashFiles('trivy-config-results.sarif') != ''" in security
    assert "pip-audit -r requirements.txt --desc" in security
    assert "pip-audit --desc" not in security
    assert "safety check" not in security
    assert "--enablePackageAudit" not in security
    assert "--failOnCVSS 7.0" in security
    assert "--severity-level high" in security
    assert "pip-audit --desc || true" not in security
    assert "safety check -r requirements.txt --output json > safety-report.json ||" not in security
    assert "bandit -r . -x ./.git,./.venv,./__pycache__,./data,./tests -f json -o bandit-report.json ||" not in security
    assert "Run Semgrep\n        continue-on-error: true" not in security_scan
    assert "aquasecurity/trivy-action@master" not in security_scan
    assert "aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1" in security_scan

    workflow = yaml.safe_load(security)
    security_steps = workflow["jobs"]["security"]["steps"]
    upload_steps = [step for step in security_steps if str(step.get("name", "")).startswith("Upload Trivy")]
    assert len(upload_steps) == 3
    for step in upload_steps:
        assert "hashFiles(" in step["if"]
        assert "\n" not in step["with"]["sarif_file"]

    categories = []
    for step in security_steps:
        if step.get("uses", "").startswith("github/codeql-action/upload-sarif"):
            cat = step.get("with", {}).get("category")
            assert cat is not None, f"Step '{step.get('name')}' is missing a category"
            categories.append(cat)
    assert len(categories) == len(set(categories))
    assert "trivy-fs" in categories
    assert "trivy-secret" in categories
    assert "trivy-config" in categories
    assert "dependency-check" in categories

    build_workflow = yaml.safe_load(test_build)
    build_steps = build_workflow["jobs"]["build-container"]["steps"]
    image_scan_step = next(step for step in build_steps if step.get("name") == "Scan image with Trivy")
    assert "ignore-unfixed" not in image_scan_step["with"]
    image_upload_step = next(step for step in build_steps if step.get("name") == "Upload Trivy results to GitHub Security tab")
    assert image_upload_step["with"]["category"] == "trivy-image"

    eval_harness = (ROOT / ".github" / "workflows" / "eval-harness-v2.yml").read_text(encoding="utf-8")
    assert "EVAL_TYPE=\"${{ github.event.inputs.evaluation_type" not in eval_harness
    assert "EVAL_TYPE: ${{ github.event.inputs.evaluation_type" in eval_harness


def test_container_and_playbook_security_gates_stay_clean():
    dockerfile = (ROOT / "Dockerfile").read_text()
    playbook = (ROOT / "supply-chain/playbooks/incident_response.py").read_text()

    assert "apk add --no-cache" in dockerfile
    assert "shell=True" not in playbook


def test_additional_sast_and_container_security_fixes():
    common_py = (ROOT / "openclaw_adapters" / "common.py").read_text(encoding="utf-8")
    findings_py = (ROOT / "openclaw_findings.py").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    # Assert SHA1 is not used for record IDs in openclaw_adapters/common.py
    assert "hashlib.sha1" not in common_py
    assert "hashlib.sha256" in common_py

    # Assert chmod statements are bypassed with proper annotations
    assert "os.chmod(directory, 0o700)  # nosec B103  # nosem" in common_py
    assert "os.chmod(output_dir, 0o700)  # nosec B103  # nosem" in findings_py

    # Assert Dockerfile upgrades dependencies and uses alpine
    assert "FROM python:3.10-alpine" in dockerfile
    assert "apk upgrade" in dockerfile
    assert "pip install --no-cache-dir --upgrade pip setuptools wheel" in dockerfile
