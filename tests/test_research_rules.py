from pathlib import Path

from secopsai.research_rules import evaluate_rule


def test_rule_validation_is_safe_and_reports_missing_tool(tmp_path: Path):
    fixture = tmp_path / "fixture.txt"
    fixture.write_text("safe fixture", encoding="utf-8")
    result = evaluate_rule(rule_type="yara", content="rule demo { strings: $a = \"safe\" condition: $a }", fixtures=[str(fixture)])
    assert result["validation"]["status"] == "passed"
    assert result["safety"] == {"package_execution": False, "network_access": False, "filesystem_write": False}
    assert result["fixtures"][0]["sha256"]


def test_invalid_rule_never_executes():
    result = evaluate_rule(rule_type="sigma", content="not: a mapping")
    assert result["validation"]["status"] == "failed"
    assert result["execution"]["performed"] is False
