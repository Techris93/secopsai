from __future__ import annotations

import json
from pathlib import Path
from secopsai.content_packs import generate_content_pack, list_content_packs

def test_generate_and_list_content_packs(tmp_path: Path):
    manifest = generate_content_pack("TEST-PKG-01", output_dir=str(tmp_path))
    assert manifest["pack_id"] == "CPK-TEST-PKG-01"
    assert "twitter_thread" in manifest["files"]
    assert "reddit_post" in manifest["files"]
    assert "linkedin_post" in manifest["files"]
    assert len(manifest["files"]["assets"]) >= 3

    # Check files exist on disk
    assert Path(manifest["files"]["twitter_thread"]).exists()
    assert Path(manifest["files"]["reddit_post"]).exists()
    assert Path(manifest["files"]["linkedin_post"]).exists()

    # Test listing
    packs = list_content_packs(output_dir=str(tmp_path))
    assert len(packs) == 1
    assert packs[0]["pack_id"] == "CPK-TEST-PKG-01"
