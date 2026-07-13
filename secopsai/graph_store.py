from __future__ import annotations

import json
from typing import Any, Iterable

import soc_store


SOURCE_EDGE = "secopsai_edge"


def upsert_graph(
    *,
    nodes: Iterable[dict[str, Any]],
    edges: Iterable[dict[str, Any]],
    source: str = SOURCE_EDGE,
    db_path: str | None = None,
) -> dict[str, int]:
    soc_store.init_db(db_path)
    now = soc_store.utc_now()
    node_count = 0
    edge_count = 0
    with soc_store.connect(db_path) as connection:
        for node in nodes:
            node_count += 1
            properties = dict(node.get("properties") or {})
            timestamp = str(properties.get("last_seen_at") or properties.get("completed_at") or now)
            connection.execute(
                """
                INSERT INTO asset_graph_nodes (
                    node_id, node_type, label, source, source_id, properties_json,
                    first_seen, last_seen, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET
                    node_type = excluded.node_type,
                    label = excluded.label,
                    source = excluded.source,
                    source_id = excluded.source_id,
                    properties_json = excluded.properties_json,
                    last_seen = excluded.last_seen,
                    updated_at = excluded.updated_at
                """,
                (
                    str(node["id"]),
                    str(node["type"]),
                    str(node.get("label") or node["id"]),
                    source,
                    str(node.get("source_id") or ""),
                    json.dumps(properties, sort_keys=True),
                    timestamp,
                    timestamp,
                    now,
                ),
            )

        for edge in edges:
            edge_count += 1
            properties = dict(edge.get("properties") or {})
            timestamp = str(properties.get("observed_at") or now)
            connection.execute(
                """
                INSERT INTO asset_graph_edges (
                    edge_id, edge_type, from_node_id, to_node_id, source,
                    properties_json, first_seen, last_seen, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(edge_id) DO UPDATE SET
                    edge_type = excluded.edge_type,
                    from_node_id = excluded.from_node_id,
                    to_node_id = excluded.to_node_id,
                    source = excluded.source,
                    properties_json = excluded.properties_json,
                    last_seen = excluded.last_seen,
                    updated_at = excluded.updated_at
                """,
                (
                    str(edge["id"]),
                    str(edge["type"]),
                    str(edge["from"]),
                    str(edge["to"]),
                    source,
                    json.dumps(properties, sort_keys=True),
                    timestamp,
                    timestamp,
                    now,
                ),
            )
        connection.commit()
    return {"nodes": node_count, "edges": edge_count}


def list_assets(*, db_path: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT node_id, label, properties_json, last_seen
            FROM asset_graph_nodes
            WHERE node_type = 'asset'
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    return [_asset_row(row) for row in rows]


def show_node(identifier: str, *, db_path: str | None = None) -> dict[str, Any] | None:
    soc_store.init_db(db_path)
    node = _find_node(identifier, db_path=db_path)
    if node is None:
        return None
    with soc_store.connect(db_path) as connection:
        edge_rows = connection.execute(
            """
            SELECT edge_id, edge_type, from_node_id, to_node_id, properties_json, last_seen
            FROM asset_graph_edges
            WHERE from_node_id = ? OR to_node_id = ?
            ORDER BY last_seen DESC
            """,
            (node["node_id"], node["node_id"]),
        ).fetchall()
    return {
        "node": node,
        "edges": [_edge_row(row) for row in edge_rows],
    }


def list_changes(*, db_path: str | None = None, limit: int = 20) -> dict[str, list[dict[str, Any]]]:
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        node_rows = connection.execute(
            """
            SELECT node_id, node_type, label, properties_json, last_seen, updated_at
            FROM asset_graph_nodes
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
        edge_rows = connection.execute(
            """
            SELECT edge_id, edge_type, from_node_id, to_node_id, properties_json, last_seen
            FROM asset_graph_edges
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    return {
        "nodes": [_node_row(row) for row in node_rows],
        "edges": [_edge_row(row) for row in edge_rows],
    }


def save_sync_state(
    *,
    source_instance: str,
    schema_version: str,
    cursor: dict[str, Any],
    bundle_exported_at: str | None,
    db_path: str | None = None,
) -> None:
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        connection.execute(
            """
            INSERT INTO edge_sync_state (
                source_instance, schema_version, cursor_json, bundle_exported_at, last_synced_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(source_instance) DO UPDATE SET
                schema_version = excluded.schema_version,
                cursor_json = excluded.cursor_json,
                bundle_exported_at = excluded.bundle_exported_at,
                last_synced_at = excluded.last_synced_at
            """,
            (
                source_instance,
                schema_version,
                json.dumps(cursor, sort_keys=True),
                bundle_exported_at,
                soc_store.utc_now(),
            ),
        )
        connection.commit()


def list_sync_state(*, db_path: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """Return recent Edge-to-Core sync records without raw telemetry."""
    soc_store.init_db(db_path)
    with soc_store.connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT source_instance, schema_version, cursor_json, bundle_exported_at, last_synced_at
            FROM edge_sync_state
            ORDER BY last_synced_at DESC
            LIMIT ?
            """,
            (max(1, min(int(limit), 500)),),
        ).fetchall()
    return [
        {
            "source_instance": str(row["source_instance"]),
            "schema_version": str(row["schema_version"]),
            "cursor": _loads(row["cursor_json"]),
            "bundle_exported_at": row["bundle_exported_at"],
            "last_synced_at": row["last_synced_at"],
        }
        for row in rows
    ]


def _find_node(identifier: str, *, db_path: str | None = None) -> dict[str, Any] | None:
    with soc_store.connect(db_path) as connection:
        direct = connection.execute(
            """
            SELECT node_id, node_type, label, properties_json, last_seen, updated_at
            FROM asset_graph_nodes
            WHERE node_id = ? OR source_id = ? OR label = ?
            LIMIT 1
            """,
            (identifier, identifier, identifier),
        ).fetchone()
        if direct is not None:
            return _node_row(direct)

        asset_rows = connection.execute(
            """
            SELECT node_id, node_type, label, properties_json, last_seen, updated_at
            FROM asset_graph_nodes
            WHERE node_type = 'asset'
            """
        ).fetchall()
    for row in asset_rows:
        node = _node_row(row)
        if str(node["properties"].get("ip_address") or "") == identifier:
            return node
    return None


def _node_row(row: Any) -> dict[str, Any]:
    return {
        "node_id": str(row["node_id"]),
        "type": str(row["node_type"]),
        "label": str(row["label"]),
        "properties": _loads(row["properties_json"]),
        "last_seen": str(row["last_seen"]),
        "updated_at": str(row["updated_at"]),
    }


def _asset_row(row: Any) -> dict[str, Any]:
    properties = _loads(row["properties_json"])
    return {
        "node_id": str(row["node_id"]),
        "ip_address": properties.get("ip_address"),
        "hostname": properties.get("hostname"),
        "vendor": properties.get("vendor"),
        "device_type": properties.get("device_type"),
        "status": properties.get("status"),
        "last_seen": str(row["last_seen"]),
        "label": str(row["label"]),
    }


def _edge_row(row: Any) -> dict[str, Any]:
    return {
        "edge_id": str(row["edge_id"]),
        "type": str(row["edge_type"]),
        "from": str(row["from_node_id"]),
        "to": str(row["to_node_id"]),
        "properties": _loads(row["properties_json"]),
        "last_seen": str(row["last_seen"]),
    }


def _loads(value: str) -> dict[str, Any]:
    try:
        payload = json.loads(value or "{}")
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}
