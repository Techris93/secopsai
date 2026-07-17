import json
from pathlib import Path

import soc_store
from secopsai.research_discovery import (
    CAPABILITIES,
    create_monitor,
    create_watchlist,
    get_candidate,
    ingest_registry_metadata,
    list_candidates,
    list_monitors,
    list_alerts,
    normalize_identifier,
    run_monitor,
    run_due_monitors,
    similarity_score,
)
from secopsai.research_intake import RegistryMetadata, SafeFetcher


def _metadata_fetcher():
    payload = {
        "name": "chalk-tempalte",
        "dist-tags": {"latest": "1.2.0"},
        "versions": {
            "1.2.0": {
                "version": "1.2.0",
                "author": {"name": "Unexpected publisher"},
                "dist": {"tarball": "https://registry.npmjs.org/chalk-tempalte/-/chalk-tempalte-1.2.0.tgz"},
            }
        },
    }

    def fetch(url, max_bytes):
        return 200, {"content-type": "application/json"}, json.dumps(payload).encode()

    return SafeFetcher(fetch=fetch)


def test_capability_registry_covers_requested_ecosystems():
    assert {"npm", "pypi", "nuget", "maven", "rubygems", "packagist", "go", "open-vsx"} <= set(CAPABILITIES)
    fixture = json.loads((Path(__file__).parent / "fixtures" / "research_discovery" / "capabilities.json").read_text())
    assert fixture["schema_version"] == "secopsai.research.ecosystem-capabilities.v1"
    assert {item["ecosystem"] for item in fixture["ecosystems"]} == set(CAPABILITIES)


def test_normalization_and_similarity_are_explainable():
    assert normalize_identifier("pypi", "Example_Package.name") == "example-package-name"
    result = similarity_score("chalk-tempalte", "chalk-template")
    assert result["score"] >= 70
    assert "damerau_distance" in result["components"]
    assert result["algorithm_version"] == "similarity-1"


def test_watchlist_monitor_creates_idempotent_candidate(tmp_path):
    db = str(tmp_path / "research.db")
    soc_store.init_db(db)
    watchlist = create_watchlist(
        ecosystem="npm",
        watch_type="package",
        identifier="chalk-template",
        threshold=70,
        reason="brand protection",
        db_path=db,
    )
    monitor = create_monitor(ecosystem="npm", watchlist_id=watchlist["watchlist_id"], interval_seconds=900, db_path=db)
    observed = RegistryMetadata("npm", "chalk-tempalte", "1.2.0", "https://registry.npmjs.org/chalk-tempalte", "https://registry.npmjs.org/chalk-tempalte/-/chalk-tempalte-1.2.0.tgz", "Unexpected publisher", "", {}, {}, {})
    first = ingest_registry_metadata(metadata=observed, source_id="REG-NPM", db_path=db, monitor=monitor)
    second = ingest_registry_metadata(metadata=observed, source_id="REG-NPM", db_path=db, monitor=monitor)
    assert first["matched_watchlists"] == 1
    assert second["matched_watchlists"] == 1
    candidates = list_candidates(db_path=db)
    assert len(candidates) == 1
    assert candidates[0]["package"] == "chalk-tempalte"
    assert get_candidate(candidates[0]["candidate_id"], db_path=db)["score"] >= 70
    assert list_monitors(db_path=db)[0]["coverage"] == {}
    assert list_alerts(db_path=db) == []


def test_due_monitor_runner_records_success_and_next_run(tmp_path):
    db = str(tmp_path / "research.db")
    soc_store.init_db(db)
    watchlist = create_watchlist(ecosystem="npm", watch_type="package", identifier="chalk-template", db_path=db)
    monitor = create_monitor(ecosystem="npm", watchlist_id=watchlist["watchlist_id"], interval_seconds=900, db_path=db)
    result = run_due_monitors(db_path=db, fetcher=_metadata_fetcher())
    assert result["due"] == 1
    assert result["succeeded"] == 1
    assert result["failed"] == 0
    assert list_monitors(db_path=db)[0]["last_success_at"]
    assert list_monitors(db_path=db)[0]["next_run_at"]
