import io
import json
import zipfile

import soc_store
from secopsai.research_analysis import compare_intakes, correlate_candidates, inspect_nuget_archive


def _intake(package, version, publisher, members, indicators):
    return {
        "metadata": {"ecosystem": "nuget", "package": package, "version": version, "publisher": publisher, "artifact_sha256": version * 64},
        "analysis": {"members": [{"path": item} for item in members], "lifecycle_scripts": {}, "indicators": [{"indicator_id": item} for item in indicators]},
    }


def test_package_comparison_is_static_and_persisted(tmp_path):
    db = str(tmp_path / "research.db")
    left = _intake("Braintree.Net", "1.0.0", "Legitimate", ["lib/net/Braintree.dll"], [])
    right = _intake("Braintree.Net", "1.0.1", "Unexpected", ["lib/net/Braintree.dll", "tools/setup.exe"], ["process-execution"])
    result = compare_intakes(left, right, db_path=db)
    assert result["members"]["added"] == ["tools/setup.exe"]
    assert result["indicators"]["added"] == ["process-execution"]
    assert result["safety"]["execution_performed"] is False
    with soc_store.connect(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM research_comparisons").fetchone()[0] == 1


def test_nuget_archive_inspection_does_not_load_or_execute_assemblies():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("Braintree.nuspec", "<package />")
        archive.writestr("lib/net8.0/Braintree.dll", b"MZ System.Diagnostics.Process HttpClient DllImport")
    result = inspect_nuget_archive(output.getvalue())
    assert result["dotnet"]["assembly_count"] == 1
    assert result["dotnet"]["assemblies"][0]["executed"] is False
    assert {"process", "network", "native"} <= set(result["dotnet"]["assemblies"][0]["static_signals"])
    assert result["safety"]["assemblies_loaded"] is False


def _candidate(db, *, candidate_id, package, version, reference, evidence):
    with soc_store.connect(db) as connection:
        connection.execute(
            """INSERT INTO research_candidates
               (candidate_id, ecosystem, package, version, reference_identifier, score,
                score_components_json, reason, status, evidence_json, first_seen, last_seen,
                algorithm_version)
               VALUES (?, 'npm', ?, ?, ?, 99, '{}', 'fixture', 'new', ?, '2026-10-18', '2026-10-18', 'test')""",
            (candidate_id, package, version, reference, json.dumps(evidence)),
        )
        connection.commit()


def test_candidate_correlation_is_exact_and_idempotent(tmp_path):
    db = str(tmp_path / "research.db")
    soc_store.init_db(db)
    _candidate(db, candidate_id="CAN-A", package="alpha", version="1.0.0", reference="brand-a", evidence={"publisher": "same publisher"})
    _candidate(db, candidate_id="CAN-B", package="beta", version="2.0.0", reference="brand-b", evidence={"publisher": "same publisher"})
    assert correlate_candidates(db_path=db) == []

    _candidate(db, candidate_id="CAN-C", package="alpha", version="1.0.0", reference="brand-c", evidence={"publisher": "another publisher"})
    first = correlate_candidates(db_path=db)
    second = correlate_candidates(db_path=db)
    assert len(first) == 1
    assert first[0]["relationship"] == "same_release"
    assert first[0]["confidence"] == 0
    assert first[0]["attribution_inferred"] is False
    assert second[0]["campaign_id"] == first[0]["campaign_id"]
    with soc_store.connect(db) as connection:
        assert connection.execute("SELECT COUNT(*) FROM research_campaigns").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM research_campaign_links").fetchone()[0] == 2
