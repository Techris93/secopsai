import shutil
from pathlib import Path

import pytest

from secopsai import research_visual_qa as vqa


def test_find_chromium_honours_explicit_binary(tmp_path, monkeypatch):
    binary = tmp_path / "chrome"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    monkeypatch.setenv("SECOPSAI_CHROMIUM_BIN", str(binary))
    assert vqa.find_chromium() == str(binary)


def test_frame_template_emulates_exact_viewport():
    html = vqa.FRAME_TEMPLATE.format(width=390, height=844, src="measure.html")
    assert 'style="width:390px;height:844px"' in html
    assert "data-secopsai-qa" in html


@pytest.mark.skipif(not any(shutil.which(c) or Path(c).exists() for c in vqa.CHROMIUM_CANDIDATES), reason="no Chromium available")
def test_capture_measures_overflow_and_alt_text(tmp_path):
    page = '<!doctype html><html><head><meta name="viewport" content="width=device-width"></head><body style="margin:0;color:#111;background:#fff">'
    page += '<p>ok</p><img src="data:image/gif;base64,R0lGODlhAQABAAAAACw=" width="1" height="1">'
    page += '<div style="width:900px">wide</div></body></html>'
    (tmp_path / "index.html").write_text(page)
    (tmp_path / "measure.html").write_text(page.replace("</body>", vqa.MEASURE_SCRIPT + "</body>"))
    for name, (width, height) in vqa.VIEWPORTS.items():
        for kind in ("index", "measure"):
            (tmp_path / f"{name}-{kind}.html").write_text(vqa.FRAME_TEMPLATE.format(width=width, height=height, src=f"{kind}.html"))
    mobile = vqa.capture_viewport(vqa.find_chromium(), tmp_path, "mobile")
    assert mobile["width"] == 390
    assert mobile["overflow"] == 1
    assert mobile["missing_alt"] == 1
    assert (tmp_path / "mobile.png").stat().st_size > 0
