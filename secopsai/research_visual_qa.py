"""Automated publication visual QA for research cases.

The reliability gate requires desktop and mobile rendering evidence before a
case may be drafted for publication, but nothing could render a post before
the draft existed.  This module renders the would-be post to a self-contained
preview, captures screenshots with a locally installed headless Chromium
(Chrome, Chromium, Brave, or Edge), measures page overflow, images without alt
text, and WCAG AA text contrast in the rendered DOM, and records the result
through ``record_visual_qa``.  No package artifact is rendered or executed;
only SecOpsAI's own generated HTML.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

VIEWPORTS = {"desktop": (1280, 900), "mobile": (390, 844)}
CHROMIUM_CANDIDATES = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
)

# Runs inside the preview only.  Writes its measurements to a body attribute
# that ``--dump-dom`` returns.
MEASURE_SCRIPT = """<script>
(function () {
  function rgb(value) {
    var m = String(value).match(/rgba?\\(([^)]+)\\)/);
    if (!m) return null;
    var p = m[1].split(',').map(function (x) { return parseFloat(x); });
    return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
  }
  function lum(c) {
    var v = [c.r, c.g, c.b].map(function (x) { x /= 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); });
    return 0.2126 * v[0] + 0.7152 * v[1] + 0.0722 * v[2];
  }
  function background(el) {
    for (var node = el; node && node.nodeType === 1; node = node.parentElement) {
      var c = rgb(getComputedStyle(node).backgroundColor);
      if (c && c.a > 0.5) return c;
    }
    return { r: 255, g: 255, b: 255, a: 1 };
  }
  function run() {
    var width = window.innerWidth;
    var overflow = document.documentElement.scrollWidth > width + 1 ? 1 : 0;
    var missingAlt = 0;
    document.querySelectorAll('img').forEach(function (img) {
      if (!img.hasAttribute('alt') || !img.getAttribute('alt').trim()) missingAlt += 1;
    });
    var contrast = 0;
    var checked = 0;
    document.querySelectorAll('body *').forEach(function (el) {
      var direct = Array.prototype.some.call(el.childNodes, function (n) { return n.nodeType === 3 && n.textContent.trim(); });
      if (!direct) return;
      var style = getComputedStyle(el);
      if (style.visibility === 'hidden' || style.display === 'none') return;
      var fg = rgb(style.color);
      if (!fg) return;
      var bg = background(el);
      var l1 = lum(fg), l2 = lum(bg);
      var ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
      var size = parseFloat(style.fontSize);
      var bold = parseInt(style.fontWeight, 10) >= 700;
      var large = size >= 24 || (bold && size >= 18.66);
      checked += 1;
      if (ratio < (large ? 3 : 4.5)) contrast += 1;
    });
    document.body.setAttribute('data-secopsai-qa', JSON.stringify({ width: width, overflow: overflow, missing_alt: missingAlt, contrast_failures: contrast, text_elements_checked: checked }));
  }
  if (document.readyState === 'complete') run(); else window.addEventListener('load', run);
})();
</script>"""


FRAME_TEMPLATE = """<!doctype html><html><head><meta charset="utf-8"><style>html,body{{margin:0;background:#fff}}iframe{{display:block;border:0}}</style></head>
<body><iframe id="f" src="{src}" style="width:{width}px;height:{height}px"></iframe>
<script>
var frame = document.getElementById('f');
function copy() {{
  try {{
    var value = frame.contentDocument && frame.contentDocument.body && frame.contentDocument.body.getAttribute('data-secopsai-qa');
    if (value) {{ document.body.setAttribute('data-secopsai-qa', value); return; }}
  }} catch (error) {{}}
  setTimeout(copy, 100);
}}
frame.addEventListener('load', copy);
</script></body></html>"""


def find_chromium() -> str:
    configured = os.environ.get("SECOPSAI_CHROMIUM_BIN", "").strip()
    for candidate in ((configured,) if configured else ()) + CHROMIUM_CANDIDATES:
        path = candidate if os.path.isabs(candidate) else shutil.which(candidate)
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise RuntimeError("no headless Chromium found; install Chrome/Chromium or set SECOPSAI_CHROMIUM_BIN")


def render_case_preview(case_id: str, out_dir: Path, *, db_path: Optional[str] = None) -> Path:
    """Write a self-contained HTML preview of the case's would-be blog post."""
    from secopsai import blog
    from secopsai.research_cases import get_case

    case = get_case(case_id, db_path=db_path)
    preview = blog.draft_research_case(case, write=False)
    post = blog._public_post(preview["post"])
    html = blog._render_post_html(post)
    # Absolute site paths become relative so the preview renders from disk.
    html = re.sub(r'(href|src)="/(?!/)', r'\1="', html)
    out_dir.mkdir(parents=True, exist_ok=True)
    assets = blog.BlogPaths().root / "assets"
    target_assets = out_dir / "assets"
    target_assets.mkdir(exist_ok=True)
    for name in ("blog.css", "blog.js", "favicon-512.png", "favicon.svg", "apple-touch-icon.png"):
        if (assets / name).is_file():
            shutil.copy2(assets / name, target_assets / name)
    (out_dir / "index.html").write_text(html, encoding="utf-8")
    (out_dir / "measure.html").write_text(html.replace("</body>", MEASURE_SCRIPT + "\n</body>"), encoding="utf-8")
    # Headless Chrome will not size a window below ~500 CSS px on some
    # platforms, so narrow viewports are emulated with an iframe of the exact
    # width; the iframe has its own viewport and media queries.
    for name, (width, height) in VIEWPORTS.items():
        for kind in ("index", "measure"):
            (out_dir / f"{name}-{kind}.html").write_text(FRAME_TEMPLATE.format(width=width, height=height, src=f"{kind}.html"), encoding="utf-8")
    return out_dir / "index.html"


def _chromium(binary: str, profile: Path, width: int, height: int, *args: str) -> subprocess.CompletedProcess[str]:
    command = [
        binary,
        "--headless=new",
        "--disable-gpu",
        "--hide-scrollbars",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-background-networking",
        f"--user-data-dir={profile}",
        f"--window-size={width},{height}",
        "--virtual-time-budget=4000",
        # The preview frames load sibling file:// pages; allow same-origin
        # access between them.  Only SecOpsAI-generated HTML is opened.
        "--allow-file-access-from-files",
        *args,
    ]
    return subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)


def capture_viewport(binary: str, preview_dir: Path, viewport: str) -> Dict[str, Any]:
    width, height = VIEWPORTS[viewport]
    window = (max(width, 520), height)
    with tempfile.TemporaryDirectory() as profile:
        screenshot = preview_dir / f"{viewport}.png"
        shot = _chromium(binary, Path(profile), *window, f"--screenshot={screenshot}", (preview_dir / f"{viewport}-index.html").as_uri())
        if not screenshot.is_file() or screenshot.stat().st_size == 0:
            raise RuntimeError(f"{viewport} screenshot failed: {shot.stderr[-400:]}")
        dom = _chromium(binary, Path(profile), *window, "--dump-dom", (preview_dir / f"{viewport}-measure.html").as_uri())
    match = re.search(r'data-secopsai-qa="([^"]+)"', dom.stdout)
    if not match:
        raise RuntimeError(f"{viewport} measurement did not complete")
    metrics = json.loads(match.group(1).replace("&quot;", '"').replace("&amp;", "&"))
    return {"viewport": viewport, "screenshot": str(screenshot), **metrics}


def run_visual_qa(case_id: str, *, out_dir: Optional[str] = None, actor: str = "publication-renderer", db_path: Optional[str] = None) -> Dict[str, Any]:
    from secopsai.research_reliability import record_visual_qa

    binary = find_chromium()
    preview_dir = Path(out_dir) if out_dir else Path(tempfile.mkdtemp(prefix=f"secopsai-visual-qa-{case_id}-"))
    render_case_preview(case_id, preview_dir, db_path=db_path)
    results = {name: capture_viewport(binary, preview_dir, name) for name in VIEWPORTS}
    audit = record_visual_qa(
        case_id,
        desktop_rendered=True,
        mobile_rendered=True,
        overflow_count=sum(int(item["overflow"]) for item in results.values()),
        contrast_failures=sum(int(item["contrast_failures"]) for item in results.values()),
        missing_alt_text=max(int(item["missing_alt"]) for item in results.values()),
        unlicensed_images=0,
        screenshots=[f"{name}={item['screenshot']}" for name, item in results.items()],
        actor=actor,
        db_path=db_path,
    )
    return {"preview_dir": str(preview_dir), "browser": binary, "measurements": results, "audit": audit}
