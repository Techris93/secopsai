from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_release_version_is_consistent() -> None:
    project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "test-and-build.yml").read_text(encoding="utf-8")
    assert 'version = "1.0.0"' in project
    assert '__version__ = "1.0.0"' in (ROOT / "secopsai" / "__init__.py").read_text(encoding="utf-8")
    assert "SecOpsAI v1.0.0" in (ROOT / "README.md").read_text(encoding="utf-8")
    assert 'SECOPSAI_INSTALL_REF:-v1.0.0' in (ROOT / "docs" / "install.sh").read_text(encoding="utf-8")
    assert "type=sha,prefix=sha-" in workflow
    assert "type=sha,prefix={{branch}}-" not in workflow


def test_hosted_deployment_has_one_actions_worker_and_cloudflare_core() -> None:
    # Render was retired on 9 October 2026; the research worker runs on
    # GitHub Actions with the ledger checkpointed to R2.
    assert not (ROOT / "render.yaml").exists()
    research = (ROOT / ".github" / "workflows" / "research-worker.yml").read_text(encoding="utf-8")
    worker = (ROOT / "cloudflare" / "secopsai-core-edge" / "wrangler.jsonc").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "test-and-build.yml").read_text(encoding="utf-8")
    assert "group: secopsai-research-ledger" in research
    assert "cancel-in-progress: false" in research
    assert "https://core.secopsai.dev/api/v1/research/alerts/webhook" in research
    assert "LEDGER_STORE_URL: https://ledger.secopsai.dev" in research
    assert '"name": "secopsai-core-edge"' in worker
    assert '"pattern": "core.secopsai.dev"' in worker
    assert "deploy-render:" not in workflow
    assert "RENDER_DEPLOY_HOOK_URL" not in workflow
    assert (ROOT / ".python-version").read_text(encoding="utf-8").strip() == "3.11.15"


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
    assert (ROOT / "website" / "install-hermes.sh").read_text(encoding="utf-8") == installer
    assert (ROOT / "www" / "install-hermes.sh").read_text(encoding="utf-8") == installer
    standard = (ROOT / "docs" / "install.sh").read_text(encoding="utf-8")
    assert (ROOT / "website" / "install.sh").read_text(encoding="utf-8") == standard
    assert (ROOT / "www" / "install.sh").read_text(encoding="utf-8") == standard
    deployment = (ROOT / ".github" / "workflows" / "deploy-public-site.yml").read_text(encoding="utf-8")
    assert "wrangler@4.114.0 pages deploy www" in deployment
    assert "verify_installer \"install-hermes.sh\"" in deployment
    assert "CLOUDFLARE_API_TOKEN" in deployment


def test_website_is_a_complete_mirror_of_www() -> None:
    # Both directories are deployed to the same Pages project (Git integration
    # builds www/, older automation used website/).  A partial copy would ship
    # without _headers, i.e. without CSP and HSTS.
    def tree(root: Path) -> dict:
        return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}

    assert tree(ROOT / "website") == tree(ROOT / "www")
    assert (ROOT / "www" / "_headers").exists()


def test_public_site_security_txt_is_current() -> None:
    import datetime as dt
    import re

    text = (ROOT / "www" / ".well-known" / "security.txt").read_text(encoding="utf-8")
    assert "Contact: mailto:security@secopsai.dev" in text
    expires = dt.datetime.fromisoformat(re.search(r"^Expires: (\S+)$", text, re.M).group(1).replace("Z", "+00:00"))
    # RFC 9116 recommends less than a year; renew before it lapses.
    assert expires - dt.datetime.now(dt.timezone.utc) > dt.timedelta(days=30), "renew www/.well-known/security.txt"


def test_tracked_website_copies_are_identical_and_contain_hermes_tab() -> None:
    website = (ROOT / "website" / "index.html").read_bytes()
    www = (ROOT / "www" / "index.html").read_bytes()
    assert website == www
    text = website.decode("utf-8")
    assert 'data-tab="hermes"' in text
    assert "https://secopsai.dev/install-hermes.sh" in text
    assert "DOC-SECOPS-AI-001" not in text
    assert "ISSUE 2026-07" not in text
    assert "LANGUAGE: EN (STE)" not in text
    assert "PLATFORMS" in text
    assert "Local-first · No log shipping by default" in text
    assert "Open source · MIT licensed" in text


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
