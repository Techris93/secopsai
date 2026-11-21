"""Stylesheet and script URLs carry a content hash on secopsai.dev and the docs."""
import hashlib
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:12]


def test_docs_hook_versions_local_assets_and_leaves_theme_bundles(tmp_path):
    hook = _load("asset_versions", "scripts/mkdocs_hooks/asset_versions.py")
    (tmp_path / "assets/stylesheets").mkdir(parents=True)
    (tmp_path / "assets/stylesheets/extra.css").write_bytes(b"body{}")
    (tmp_path / "assets/stylesheets/main.484c7ddc.min.css").write_bytes(b"x")
    (tmp_path / "guide").mkdir()
    page = tmp_path / "guide/index.html"
    page.write_text('<link href="../assets/stylesheets/extra.css?v=old"><link href="../assets/stylesheets/main.484c7ddc.min.css">'
                    '<script src="../assets/javascripts/missing.js"></script>', encoding="utf-8")
    assert hook.version_assets(tmp_path) == 1
    html = page.read_text(encoding="utf-8")
    assert f'href="../assets/stylesheets/extra.css?v={_digest(b"body{}")}"' in html
    assert 'href="../assets/stylesheets/main.484c7ddc.min.css"' in html, "fingerprinted bundles keep their URL"
    assert 'src="../assets/javascripts/missing.js"' in html, "a missing file is left alone"


def test_site_script_versions_main_site_assets(tmp_path, monkeypatch):
    script = _load("version_site_assets", "scripts/version_site_assets.py")
    site = tmp_path / "www"
    (site / "assets").mkdir(parents=True)
    (site / "assets/site.js").write_bytes(b"console.log(1)")
    page = site / "index.html"
    page.write_text('<script src="/assets/site.js" defer></script>', encoding="utf-8")
    assert script.versioned(site, page.read_text()) == f'<script src="/assets/site.js?v={_digest(b"console.log(1)")}" defer></script>'


def test_committed_main_site_pages_are_current():
    script = _load("version_site_assets", "scripts/version_site_assets.py")
    for name in script.SITES:
        site = ROOT / name
        for page in site.rglob("*.html"):
            text = page.read_text(encoding="utf-8")
            assert script.versioned(site, text) == text, f"run python scripts/version_site_assets.py ({page.relative_to(ROOT)})"
