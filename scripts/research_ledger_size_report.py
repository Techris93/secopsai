"""Read-only size report of the production research ledger, restored into disposable storage.

Measures what fills the ledger, how much the configured retention would remove,
how fast it grows, and how long the post-cycle ontology snapshot queries take.
Only aggregate counts and sizes are reported; no row contents."""
from contextlib import closing
import argparse
import importlib.util
import inspect
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _timed(report, name, fn):
    started = time.monotonic()
    try:
        report[name] = fn()
    except Exception as exc:
        report[name] = {"error": f"{type(exc).__name__}: {exc}"[:300]}
    report.setdefault("seconds", {})[name] = round(time.monotonic() - started, 1)
    print(json.dumps({"step": name, "seconds": report["seconds"][name]}), flush=True)


def measure(db, report):
    from secopsai import ontology, research_storage

    def connect():
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def pages():
        with closing(connect()) as conn:
            return {key: conn.execute(f"PRAGMA {key}").fetchone()[0] for key in ("page_size", "page_count", "freelist_count")}

    def objects():
        with closing(connect()) as conn:
            rows = conn.execute("SELECT name, SUM(pgsize) AS bytes, COUNT(*) AS pages FROM dbstat GROUP BY name ORDER BY bytes DESC").fetchall()
            owners = {row["name"]: (row["type"], row["tbl_name"]) for row in conn.execute("SELECT name, type, tbl_name FROM sqlite_master")}
        return [{"name": row["name"], "type": owners.get(row["name"], ("", ""))[0], "table": owners.get(row["name"], ("", ""))[1],
                 "bytes": row["bytes"], "pages": row["pages"]} for row in rows[:60]]

    def row_counts():
        names = [item["table"] for item in report.get("objects") or [] if isinstance(item, dict) and item.get("type") == "table"][:15]
        with closing(connect()) as conn:
            return {name: conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0] for name in names}

    def retention():
        result = []
        with closing(connect()) as conn:
            for table, predicate, params in research_storage._prune_rules(include_high_volume=True):
                started = time.monotonic()
                count = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {predicate}", params).fetchone()[0]
                result.append({"table": table, "predicate": predicate, "cutoff": list(params), "would_delete": count,
                               "seconds": round(time.monotonic() - started, 1)})
        return result

    def feed_growth():
        with closing(connect()) as conn:
            by_state = [dict(row) for row in conn.execute(
                "SELECT processing_state, COUNT(*) AS rows, MIN(collected_at) AS oldest, MAX(collected_at) AS newest "
                "FROM registry_feed_events GROUP BY processing_state")]
            by_day = [dict(row) for row in conn.execute(
                "SELECT substr(collected_at, 1, 10) AS day, COUNT(*) AS rows, SUM(length(metadata_json)) AS metadata_bytes "
                "FROM registry_feed_events WHERE collected_at >= strftime('%Y-%m-%dT%H:%M:%S', 'now', '-14 days') GROUP BY day ORDER BY day")]
        return {"by_state": by_state, "by_day": by_day}

    def snapshot_queries():
        source = inspect.getsource(ontology.materialize_recent)
        result = []
        with closing(connect()) as conn:
            for sql in re.findall(r'"(SELECT [^"]+? LIMIT \?)"', source):
                plan = [row[3] for row in conn.execute("EXPLAIN QUERY PLAN " + sql, (100,))]
                started = time.monotonic()
                conn.execute(sql, (100,)).fetchall()
                result.append({"from": re.search(r"FROM (\w+)", sql).group(1), "seconds": round(time.monotonic() - started, 2), "plan": plan})
        return result

    def npm_snapshots():
        """Where snapshot bytes go, and how far a stored previous version lags."""
        import random
        with closing(connect()) as conn:
            totals = dict(conn.execute(
                "SELECT COUNT(*) AS rows, SUM(length(versions_json)) AS versions_bytes, SUM(length(known_versions_json)) AS known_bytes, "
                "SUM(length(source_url) + length(metadata_sha256) + length(latest_version)) AS other_bytes FROM research_npm_package_snapshots").fetchone())
            rowids = [row[0] for row in conn.execute("SELECT rowid FROM research_npm_package_snapshots")]
            sample = random.Random(7).sample(rowids, min(2000, len(rowids)))
            fields, summaries, per_row = {}, 0, []
            for rowid in sample:
                versions = json.loads(conn.execute("SELECT versions_json FROM research_npm_package_snapshots WHERE rowid=?", (rowid,)).fetchone()[0] or "{}")
                per_row.append(len(versions))
                for summary in versions.values():
                    summaries += 1
                    for key, value in summary.items():
                        fields[key] = fields.get(key, 0) + len(json.dumps(value))
            per_row.sort()
            # How many releases arrive between enrichment and static ranking:
            # versions published per package in the last 7 days, from the feed.
            bursts = [row[0] for row in conn.execute(
                "SELECT COUNT(*) FROM registry_feed_events WHERE ecosystem='npm' AND version<>'' "
                "AND collected_at >= strftime('%Y-%m-%dT%H:%M:%S','now','-7 days') GROUP BY package")]
        bursts.sort()
        pick = lambda values, q: values[min(len(values) - 1, int(q * len(values)))] if values else None
        return {**totals, "sample_rows": len(sample), "sample_summaries": summaries,
                "summary_field_bytes": dict(sorted(fields.items(), key=lambda item: -item[1])),
                "summaries_per_row": {q: pick(per_row, q) for q in (0.5, 0.9, 0.99)} | {"max": per_row[-1] if per_row else None},
                "npm_versions_per_package_7d": {q: pick(bursts, q) for q in (0.5, 0.9, 0.99, 0.999)} | {"max": bursts[-1] if bursts else None, "packages": len(bursts)}}

    _timed(report, "npm_snapshots", npm_snapshots)
    _timed(report, "pages", pages)
    _timed(report, "objects", objects)
    _timed(report, "row_counts", row_counts)
    _timed(report, "retention", retention)
    _timed(report, "feed_growth", feed_growth)
    _timed(report, "snapshot_queries", snapshot_queries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("secopsai_checkpoint_supervisor", ROOT / "cloudflare/secopsai-research-runner/container/supervisor.py")
    supervisor = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(supervisor)
    store = supervisor.LedgerStore(os.environ["LEDGER_STORE_URL"], os.environ["LEDGER_STORE_TOKEN"])
    manifest = json.loads(store._request("GET", "/checkpoint-manifest", deadline=time.monotonic() + 60))
    if not supervisor.valid_manifest(manifest):
        raise ValueError("invalid production manifest")
    base = manifest.get("base") or manifest
    report = {"production_modified": False, "manifest": {
        "version": manifest["version"], "captured_at": manifest["captured_at"], "size_bytes": manifest["size_bytes"],
        "base_chunks": len(base["chunks"]), "patches": len(manifest.get("patches") or []),
        "max_objects": 900, "max_size_bytes": 900 * 28 * 1024 * 1024}}
    print(json.dumps(report["manifest"]), flush=True)
    os.environ["SECOPSAI_INCREMENTAL_CHECKPOINTS"] = "1"
    with tempfile.TemporaryDirectory(prefix="secopsai-size-") as directory:
        os.chmod(directory, 0o700)
        if shutil.disk_usage(directory).free < manifest["size_bytes"] * 1.2:
            raise ValueError("insufficient disposable capacity")
        db = Path(directory) / "ledger.db"
        _timed(report, "restore", lambda: bool(store.download_chunked(db, manifest)))
        report["file_bytes"] = db.stat().st_size
        measure(db, report)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, default=str))
    print(json.dumps(report, default=str)[:20000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
