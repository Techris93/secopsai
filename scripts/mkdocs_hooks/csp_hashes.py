"""MkDocs hook: replace script-src 'unsafe-inline' with SHA-256 hashes.

MkDocs Material emits a few small inline bootstrap scripts whose bodies vary
with page depth and theme version.  Instead of allowing every inline script,
hash the executable inline scripts in the built site and pin exactly those in
the Cloudflare Pages `_headers` CSP.  JSON data blocks are not executable and
are not hashed.  If the set grows unexpectedly the policy is left unchanged so
a build never ships a CSP that breaks the docs.
"""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

INLINE_SCRIPT = re.compile(r"<script(?P<attrs>(?:(?!\bsrc=)[^>])*)>(?P<body>.*?)</script>", re.S | re.I)
NON_EXECUTABLE_TYPE = re.compile(r"\btype=[\"']?application/(?:ld\+)?json", re.I)
MAX_HASHES = 40


def inline_script_hashes(site_dir: Path) -> set[str]:
    hashes: set[str] = set()
    for page in site_dir.rglob("*.html"):
        text = page.read_text(encoding="utf-8", errors="ignore")
        for match in INLINE_SCRIPT.finditer(text):
            if NON_EXECUTABLE_TYPE.search(match.group("attrs")) or not match.group("body").strip():
                continue
            digest = hashlib.sha256(match.group("body").encode("utf-8")).digest()
            hashes.add(f"'sha256-{base64.b64encode(digest).decode('ascii')}'")
    return hashes


def pin_script_hashes(headers: str, hashes: set[str]) -> str:
    if not hashes or len(hashes) > MAX_HASHES:
        return headers
    pinned = " ".join(sorted(hashes))

    def rewrite(match: re.Match[str]) -> str:
        directive = match.group(0)
        return directive.replace("'unsafe-inline'", pinned) if "'unsafe-inline'" in directive else directive

    return re.sub(r"script-src [^;\n]*", rewrite, headers)


def on_post_build(config, **_kwargs) -> None:
    site_dir = Path(config["site_dir"])
    headers_path = site_dir / "_headers"
    if not headers_path.exists():
        return
    headers = headers_path.read_text(encoding="utf-8")
    headers_path.write_text(pin_script_hashes(headers, inline_script_hashes(site_dir)), encoding="utf-8")
