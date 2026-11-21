"""MkDocs hook: add a content hash to the docs' own stylesheet and script URLs.

Browsers may keep /assets files for hours (the zone sends max-age=14400), so a
deploy could pair new HTML with an old cached extra.css or share.js. After the
build, every link to a local stylesheet or script under assets/ gets
``?v=<sha256[:12]>`` of the file, so a changed file has a new URL. Theme
bundles that already carry a hash in their file name are left alone.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

ASSET_REF = re.compile(r'(?P<attr>\b(?:href|src)=")(?P<url>[^"?#:]*?assets/[^"?#]+\.(?:css|js))(?P<query>\?[^"#]*)?"')
FINGERPRINTED = re.compile(r"\.[0-9a-f]{8,}\.min\.(?:css|js)$")


def _digest(path: Path, cache: dict[Path, str]) -> str:
    if path not in cache:
        cache[path] = hashlib.sha256(path.read_bytes()).hexdigest()[:12]
    return cache[path]


def version_assets(site_dir: Path) -> int:
    site = site_dir.resolve()
    cache: dict[Path, str] = {}
    changed = 0
    for page in site.rglob("*.html"):
        text = page.read_text(encoding="utf-8")

        def rewrite(match: re.Match[str]) -> str:
            url = match.group("url")
            if FINGERPRINTED.search(url):
                return match.group(0)
            target = (site / url.lstrip("/")) if url.startswith("/") else (page.parent / url)
            target = target.resolve()
            if site not in target.parents or not target.is_file():
                return match.group(0)
            return f'{match.group("attr")}{url}?v={_digest(target, cache)}"'

        updated = ASSET_REF.sub(rewrite, text)
        if updated != text:
            page.write_text(updated, encoding="utf-8")
            changed += 1
    return changed


def on_post_build(config, **kwargs) -> None:
    version_assets(Path(config["site_dir"]))
