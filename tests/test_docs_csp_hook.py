from pathlib import Path

from scripts.mkdocs_hooks.csp_hashes import inline_script_hashes, pin_script_hashes

HEADERS = "/*\n  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://static.cloudflareinsights.com; style-src 'self' 'unsafe-inline'\n"


def test_inline_scripts_are_pinned_and_json_blocks_ignored(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text(
        '<script>console.log(1)</script><script id="__config" type="application/json">{"a":1}</script>'
        '<script src="/x.js"></script>',
        encoding="utf-8",
    )
    hashes = inline_script_hashes(tmp_path)
    assert hashes == {"'sha256-CihokcEcBW4atb/CW/XWsvWwbTjqwQlE9nj9ii5ww5M='"}
    pinned = pin_script_hashes(HEADERS, hashes)
    script_src = pinned.split("script-src", 1)[1].split(";", 1)[0]
    assert "'unsafe-inline'" not in script_src
    assert "sha256-CihokcEcBW4atb" in script_src
    # style-src keeps its own policy.
    assert "style-src 'self' 'unsafe-inline'" in pinned


def test_policy_is_unchanged_without_hashes() -> None:
    assert pin_script_hashes(HEADERS, set()) == HEADERS
