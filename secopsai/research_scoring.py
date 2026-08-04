"""Detection pipeline: score surveillance feed events into candidates.

Collectors in ``research_surveillance`` write an append-only ledger of
registry events. This module converts pending ledger entries into
``RegistryMetadata`` and passes them through the centralized watchlist
scoring path in ``research_discovery``, so global feed events and
watchlist observations share identical candidate semantics, suppression
rules, and alert behavior. Scoring is metadata-only and deterministic;
artifact-backed signals arrive later through the bounded intake path.
"""

from __future__ import annotations

from contextlib import closing
from typing import Any, Dict, List, Optional

import soc_store
from secopsai.research_discovery import ingest_registry_metadata
from secopsai.research_intake import RegistryMetadata
from secopsai.research_surveillance import ensure_collectors

# Event types that describe something newly present in the ecosystem.
# Removals (deleted, yanked, project_removed, extension_removed) stay
# in the ledger for audit but never produce candidates.
SCORABLE_EVENT_TYPES = {"published", "project_added", "extension_added", "version_updated", "version_observed"}

_ARTIFACT_SUFFIXES = (".gem", ".nupkg", ".tgz", ".whl", ".tar.gz", ".zip", ".vsix")


def _event_to_metadata(event: Dict[str, Any]) -> RegistryMetadata:
    metadata = event.get("metadata") or {}
    leaf_url = str(event.get("leaf_url") or "")
    metadata_url = str(metadata.get("metadata_url") or event.get("page_url") or leaf_url)
    artifact_url = str(metadata.get("artifact_url") or (leaf_url if leaf_url.endswith(_ARTIFACT_SUFFIXES) else ""))
    return RegistryMetadata(
        ecosystem=str(event["ecosystem"]),
        package=str(event["package"]),
        version=str(event.get("version") or ""),
        metadata_url=metadata_url,
        artifact_url=artifact_url,
        publisher=str(metadata.get("publisher") or metadata.get("authors") or ""),
        published_at=str(event.get("registry_timestamp") or ""),
        dependencies={},
        integrity={"sha256": str(metadata.get("sha256") or "")},
        raw={
            "feed_event_id": event.get("feed_event_id"),
            "event_type": event.get("event_type"),
            "collector_id": event.get("collector_id"),
            "feed_metadata": metadata,
        },
    )


def score_pending_events(
    *,
    ecosystem: Optional[str] = None,
    limit: int = 200,
    db_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Score pending surveillance events against active watchlists.

    Each event is scored exactly once: matched events become candidates
    through the centralized path, unmatched events are marked scored, and
    removal events are ignored. Candidate creation is idempotent, so a
    crashed batch can simply be rerun.
    """
    ensure_collectors(db_path=db_path)
    limit = max(1, min(int(limit), 2000))
    clauses = ["processing_state = 'pending'"]
    params: List[Any] = []
    if ecosystem:
        clauses.append("ecosystem = ?")
        params.append(ecosystem)
    with closing(soc_store.connect(db_path)) as connection:
        rows = connection.execute(
            f"""SELECT * FROM registry_feed_events
            WHERE {' AND '.join(clauses)}
            ORDER BY registry_timestamp ASC LIMIT ?""",
            (*params, limit),
        ).fetchall()

    counts = {"processed": 0, "candidates": 0, "scored": 0, "ignored": 0}
    candidate_ids: List[str] = []
    for row in rows:
        event = dict(row)
        event["metadata"] = _decode_metadata(event.get("metadata_json"))
        if event["event_type"] not in SCORABLE_EVENT_TYPES:
            new_state = "ignored"
            counts["ignored"] += 1
        else:
            source_id = f"REG-{event['ecosystem'].upper().replace('-', '_')}"
            result = ingest_registry_metadata(
                metadata=_event_to_metadata(event), source_id=source_id, db_path=db_path
            )
            if int(result.get("matched_watchlists") or 0) > 0:
                new_state = "candidate"
                for candidate in result.get("candidates", []):
                    counts["candidates"] += 1
                    candidate_ids.append(str(candidate.get("candidate_id")))
            else:
                new_state = "scored"
                counts["scored"] += 1
        with closing(soc_store.connect(db_path)) as connection:
            with connection:
                connection.execute(
                    "UPDATE registry_feed_events SET processing_state = ? WHERE feed_event_id = ?",
                    (new_state, event["feed_event_id"]),
                )
        counts["processed"] += 1

    return {
        "processed": counts["processed"],
        "candidates_created": counts["candidates"],
        "scored": counts["scored"],
        "ignored": counts["ignored"],
        "candidate_ids": candidate_ids,
        "ecosystem": ecosystem,
        "limit": limit,
    }


def _decode_metadata(raw: Any) -> Dict[str, Any]:
    import json

    try:
        value = json.loads(raw) if raw else {}
    except (TypeError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}
