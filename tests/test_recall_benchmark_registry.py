import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import recall_benchmark as rb  # noqa: E402
from secopsai.frontier_metrics import benchmark_scores  # noqa: E402


def _tgz(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, body in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    return buffer.getvalue()


def test_osv_dates_are_earliest_per_package_and_version(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "MAL-1.json").write_text(json.dumps({"published": "2026-03-04T00:00:00Z",
        "affected": [{"package": {"name": "Evil_Pkg"}, "versions": ["1.0"]}]}))
    (tmp_path / "a" / "MAL-2.json").write_text(json.dumps({"published": "2025-12-01T00:00:00Z",
        "affected": [{"package": {"name": "evil-pkg"}, "versions": ["0.9"]}]}))
    dates = rb.osv_published(tmp_path)
    assert dates[("evil-pkg", "1.0")] == "2026-03-04" and dates[("evil-pkg", "")] == "2025-12-01"


def test_registry_sample_skips_versions_already_in_the_first_corpus(tmp_path):
    repo = tmp_path / "registry"
    for package, version in (("evil", "1.0"), ("evil", "2.0"), ("other", "0.1")):
        folder = repo / package / version
        folder.mkdir(parents=True)
        (folder / f"{package}-{version}.tar.gz").write_bytes(_tgz({"x/setup.py": b"print(1)"}))
    (repo / "README.md").write_text("x")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "x"], cwd=repo, check=True)
    chosen = rb.registry_paths(repo, 10, 1, exclude={("evil", "1.0")})
    assert sorted(chosen) == ["evil/2.0/evil-2.0.tar.gz", "other/0.1/other-0.1.tar.gz"]


def test_registry_archives_are_read_in_memory():
    members = rb.registry_members(_tgz({"evil-1.0/setup.py": b"import os\nos.system('id')", "evil-1.0/README": b"hi"}), "evil-1.0.tar.gz")
    assert dict(members)["evil-1.0/setup.py"].startswith(b"import os")


def test_each_corpus_is_also_scored_on_its_own():
    rows = [{"set": "malicious", "ecosystem": "pypi", "category": "malicious_intent", "level": "alert", "status": "scanned", "discovered": "2026-02-01"},
            {"set": "malicious", "corpus": "pypi_malregistry", "ecosystem": "pypi", "category": "malicious_intent", "level": "none",
             "status": "scanned", "discovered": "2026-02-01"}]
    recall = benchmark_scores(rows)["recall"]
    assert recall["pypi/malicious_intent"]["held_out"]["alert"] == 0.5
    assert recall["pypi/malicious_intent@datadog"]["held_out"]["alert"] == 1.0
    assert recall["pypi/malicious_intent@pypi_malregistry"]["held_out"]["alert"] == 0.0
