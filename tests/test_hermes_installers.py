from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_release_version_is_consistent() -> None:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "1.0.0"' in project
    assert '__version__ = "1.0.0"' in (ROOT / "secopsai" / "__init__.py").read_text(encoding="utf-8")
    assert "SecOpsAI v1.0.0" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert 'SECOPSAI_INSTALL_REF:-v1.0.0' in (ROOT / "docs" / "install.sh").read_text(encoding="utf-8")


def test_shell_installers_are_syntax_valid() -> None:
    commands = (
        ["bash", "-n", str(ROOT / "setup.sh")],
        ["sh", "-n", str(ROOT / "docs" / "install.sh")],
        ["sh", "-n", str(ROOT / "docs" / "install-hermes.sh")],
    )
    for command in commands:
        completed = subprocess.run(command, text=True, capture_output=True, check=False)
        assert completed.returncode == 0, completed.stderr


def test_public_hermes_installer_and_worker_route_are_wired() -> None:
    installer = (ROOT / "docs" / "install-hermes.sh").read_text(encoding="utf-8")
    worker = (ROOT / "scripts" / "cloudflare-installer-worker.js").read_text(encoding="utf-8")
    assert 'MIN_VERSION="0.18.2"' in installer
    assert 'PLUGIN="Techris93/secopsai/integrations/hermes"' in installer
    assert "hermes plugins install" in installer
    assert "hermes service install" in installer
    assert '"/install-hermes.sh": "https://docs.secopsai.dev/install-hermes.sh"' in worker


def test_tracked_website_copies_are_identical_and_contain_hermes_tab() -> None:
    website = (ROOT / "website" / "index.html").read_bytes()
    www = (ROOT / "www" / "index.html").read_bytes()
    assert website == www
    text = website.decode("utf-8")
    assert 'data-tab="hermes"' in text
    assert "https://secopsai.dev/install-hermes.sh" in text


def test_hermes_cli_help_is_packaged() -> None:
    completed = subprocess.run(
        [sys.executable, "-m", "secopsai.cli", "hermes", "--help"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0
    assert "doctor" in completed.stdout
    assert "refresh" in completed.stdout
    assert "service" in completed.stdout
