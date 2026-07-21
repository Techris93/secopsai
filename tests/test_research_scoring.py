import json

import soc_store
from secopsai.research_discovery import (
    create_watchlist,
    list_alerts,
    list_candidates,
    similarity_score,
)
from secopsai.research_scoring import score_pending_events
from secopsai.research_surveillance import ensure_collectors


def _db(tmp_path):
    return str(tmp_path / "scoring.db")


def _insert_feed_event(
    db_path,
    *,
    ecosystem="rubygems",
    package,
    version="1.0.0",
    event_type="published",
    registry_ts="2026-07-21T12:00:00.000Z",
    metadata=None,
    collector_id=None,
):
    ensure_collectors(db_path=db_path)
    collector = collector_id or {
        "rubygems": "COL-RUBYGEMS-TIMEFRAME",
        "nuget": "COL-NUGET-CATALOG",
        "packagist": "COL-PACKAGIST-CHANGES",
        "pypi": "COL-PYPI-INDEX",
    }[ecosystem]
    connection = soc_store.connect(db_path)
    try:
        connection.execute(
            """INSERT INTO registry_feed_events
            (feed_event_id, collector_id, ecosystem, package, version, event_type,
             registry_timestamp, page_url, leaf_url, leaf_fetched, metadata_json,
             idempotency_key, collected_at, processing_state)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'https://feed/', 'https://leaf/', 0, ?, ?, '2026-07-21T12:00:01.000Z', 'pending')""",
            (
                f"RFE-TEST-{ecosystem}-{package}-{version}-{event_type}".upper().replace("/", "_"),
                collector,
                ecosystem,
                package,
                version,
                event_type,
                registry_ts,
                json.dumps(metadata or {}),
                f"{ecosystem}|{package}|{version}|{registry_ts}|{event_type}",
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _event_state(db_path, package):
    connection = soc_store.connect(db_path)
    try:
        row = connection.execute(
            "SELECT processing_state FROM registry_feed_events WHERE package = ?", (package,)
        ).fetchone()
        return row["processing_state"] if row else None
    finally:
        connection.close()


def _brand_watchlist(db_path, **overrides):
    options = {
        "ecosystem": "rubygems",
        "watch_type": "brand",
        "identifier": "acme-tools",
        "threshold": 70.0,
    }
    options.update(overrides)
    return create_watchlist(**options, db_path=db_path)


def test_typosquat_event_becomes_candidate_with_alert(tmp_path):
    db_path = _db(tmp_path)
    _brand_watchlist(db_path)
    _insert_feed_event(db_path, package="acme-toools")
    result = score_pending_events(ecosystem="rubygems", db_path=db_path)
    assert result["processed"] == 1
    assert result["candidates_created"] == 1
    assert _event_state(db_path, "acme-toools") == "candidate"

    candidates = list_candidates(ecosystem="rubygems", db_path=db_path)
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate["package"] == "acme-toools"
    assert candidate["reference_identifier"] == "acme-tools"
    expected = similarity_score("acme-toools", "acme-tools")["score"]
    assert candidate["score"] == expected
    if expected >= 85:
        assert list_alerts(db_path=db_path)


def test_exact_name_with_known_publisher_is_suppressed(tmp_path):
    db_path = _db(tmp_path)
    _brand_watchlist(db_path, known_publishers=["Acme"])
    _insert_feed_event(db_path, package="acme-tools", metadata={"authors": "Acme"})
    result = score_pending_events(ecosystem="rubygems", db_path=db_path)
    assert result["candidates_created"] == 0
    assert _event_state(db_path, "acme-tools") == "scored"
    assert list_candidates(ecosystem="rubygems", db_path=db_path) == []


def test_exact_name_with_unknown_publisher_is_flagged(tmp_path):
    db_path = _db(tmp_path)
    _brand_watchlist(db_path, known_publishers=["Acme"])
    _insert_feed_event(db_path, package="acme-tools", metadata={"authors": "Mysterious"})
    result = score_pending_events(ecosystem="rubygems", db_path=db_path)
    assert result["candidates_created"] == 1
    assert _event_state(db_path, "acme-tools") == "candidate"


def test_exact_name_with_missing_publisher_is_suppressed(tmp_path):
    db_path = _db(tmp_path)
    _brand_watchlist(db_path, known_publishers=["Acme"])
    # Feeds without publisher data (e.g. Packagist actions) must not flag
    # the legitimate exact-name package as an impersonator.
    _insert_feed_event(db_path, package="acme-tools", metadata={})
    result = score_pending_events(ecosystem="rubygems", db_path=db_path)
    assert result["candidates_created"] == 0
    assert _event_state(db_path, "acme-tools") == "scored"


def test_excluded_name_is_suppressed(tmp_path):
    db_path = _db(tmp_path)
    _brand_watchlist(db_path, exclusions=["acme-tools-plugin"])
    _insert_feed_event(db_path, package="acme-tools-plugin")
    result = score_pending_events(ecosystem="rubygems", db_path=db_path)
    assert result["candidates_created"] == 0
    assert _event_state(db_path, "acme-tools-plugin") == "scored"


def test_unrelated_package_is_scored_without_candidate(tmp_path):
    db_path = _db(tmp_path)
    _brand_watchlist(db_path)
    _insert_feed_event(db_path, package="totally-different-lib")
    result = score_pending_events(ecosystem="rubygems", db_path=db_path)
    assert result["candidates_created"] == 0
    assert result["scored"] == 1
    assert _event_state(db_path, "totally-different-lib") == "scored"


def test_removal_events_are_ignored(tmp_path):
    db_path = _db(tmp_path)
    _brand_watchlist(db_path)
    _insert_feed_event(db_path, package="acme-toools", version="1.0.0", event_type="yanked")
    _insert_feed_event(db_path, package="acme-toools", version="1.0.1", event_type="deleted")
    result = score_pending_events(ecosystem="rubygems", db_path=db_path)
    assert result["candidates_created"] == 0
    assert result["ignored"] == 2
    assert list_candidates(ecosystem="rubygems", db_path=db_path) == []


def test_second_run_processes_nothing(tmp_path):
    db_path = _db(tmp_path)
    _brand_watchlist(db_path)
    _insert_feed_event(db_path, package="acme-toools")
    score_pending_events(ecosystem="rubygems", db_path=db_path)
    result = score_pending_events(ecosystem="rubygems", db_path=db_path)
    assert result["processed"] == 0
    assert len(list_candidates(ecosystem="rubygems", db_path=db_path)) == 1


def test_ecosystem_filter_leaves_other_events_pending(tmp_path):
    db_path = _db(tmp_path)
    _brand_watchlist(db_path)
    _insert_feed_event(db_path, package="acme-toools")
    _insert_feed_event(db_path, ecosystem="nuget", package="Acme.Toools")
    result = score_pending_events(ecosystem="rubygems", db_path=db_path)
    assert result["processed"] == 1
    assert _event_state(db_path, "Acme.Toools") == "pending"
