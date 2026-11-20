"""main requires pull requests; only the blog deploy key may push to it directly."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _steps():
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        for job in (data.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                yield path.name, step


def test_workflows_push_main_only_through_the_deploy_key_script():
    pushers = []
    for name, step in _steps():
        run = step.get("run") or ""
        assert "git push origin HEAD:main" not in run, f"{name}: {step.get('name')} pushes main with the Actions token"
        if "scripts/ci/push_main.sh" in run:
            pushers.append((name, step.get("name")))
            assert (step.get("env") or {}).get("BLOG_PUBLISH_DEPLOY_KEY") == "${{ secrets.BLOG_PUBLISH_DEPLOY_KEY }}", (name, step.get("name"))
    assert sorted(pushers) == [("blog-ops.yml", "Commit deployed draft state"),
                               ("blog-ops.yml", "Commit intentional Blog Ops changes"),
                               ("research-worker.yml", "Commit and deploy")]


def test_push_script_pins_the_github_host_key():
    script = (ROOT / "scripts" / "ci" / "push_main.sh").read_text(encoding="utf-8")
    assert "StrictHostKeyChecking=yes" in script and "IdentitiesOnly=yes" in script
    assert "github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl" in script
