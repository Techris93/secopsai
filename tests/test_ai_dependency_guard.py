import inspect
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from unittest import mock

import soc_store
from secopsai import ai_dependency_guard as guard
from secopsai import cli as secopsai_cli


def registry(exists=True, ecosystem="npm", package="fixture", created_at="2024-01-01T00:00:00Z", error=None):
    return guard.RegistryInfo(
        exists=exists,
        ecosystem=ecosystem,
        package=package,
        created_at=created_at,
        latest_version="1.0.0" if exists else None,
        version_count=3 if exists else 0,
        error=error,
    )


class AIDependencyGuardTests(unittest.TestCase):
    def test_extracts_dependencies_from_manifests_lockfiles_and_source_imports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text(json.dumps({"dependencies": {"express": "^4.0.0"}}), encoding="utf-8")
            (root / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
            (root / "composer.json").write_text(json.dumps({"require": {"vendor/package": "^1.0"}}), encoding="utf-8")
            (root / "go.mod").write_text("module unit\nrequire github.com/example/module v1.2.3\n", encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("import hallucinated_sdk\n", encoding="utf-8")
            (root / "src" / "app.ts").write_text("import thing from '@scope/pkg/subpath';\n", encoding="utf-8")

            candidates = guard.collect_repo_candidates(root)
            keys = set(candidates)

        self.assertIn(("npm", "express"), keys)
        self.assertIn(("npm", "@scope/pkg"), keys)
        self.assertIn(("pypi", "requests"), keys)
        self.assertIn(("pypi", "hallucinated-sdk"), keys)
        self.assertIn(("packagist", "vendor/package"), keys)
        self.assertIn(("go", "github.com/example/module"), keys)

    def test_missing_ai_suggested_manifest_package_is_high_risk(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text(json.dumps({"dependencies": {"ghost-ai-helper": "1.0.0"}}), encoding="utf-8")
            (root / "data" / "sessions").mkdir(parents=True)
            (root / "data" / "sessions" / "session.json").write_text(
                json.dumps({"message": "The AI assistant suggested npm install ghost-ai-helper"}),
                encoding="utf-8",
            )

            payload = guard.run_ai_dependency_guard(
                path=root,
                include_agent_logs=True,
                agent_source="sessions",
                metadata_fetcher=lambda eco, pkg: registry(False, eco, pkg, error="not_found"),
            )

        candidate = payload["candidates"][0]
        self.assertEqual(candidate["classification"], "missing_or_hallucinated")
        self.assertEqual(candidate["severity"], "high")
        self.assertTrue(candidate["ai_origin"])
        self.assertEqual(payload["summary"]["high_risk"], 1)
        self.assertEqual(len(payload["findings"]), 1)

    def test_newly_registered_ai_suggested_package_is_high_risk(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "data" / "sessions").mkdir(parents=True)
            (root / "data" / "sessions" / "session.json").write_text(
                json.dumps({"tool_call": "pip install fresh-ai-widget"}),
                encoding="utf-8",
            )
            now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

            payload = guard.run_ai_dependency_guard(
                path=root,
                include_agent_logs=True,
                agent_source="sessions",
                metadata_fetcher=lambda eco, pkg: registry(True, eco, pkg, created_at=now),
            )

        self.assertEqual(payload["candidates"][0]["classification"], "newly_registered")
        self.assertEqual(payload["candidates"][0]["severity"], "high")

    def test_similarity_risk_detects_trusted_package_lookalike(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "requirements.txt").write_text("reqeusts==1.0.0\n", encoding="utf-8")

            payload = guard.run_ai_dependency_guard(
                path=root,
                metadata_fetcher=lambda eco, pkg: registry(False, eco, pkg, error="not_found"),
            )

        candidate = payload["candidates"][0]
        self.assertEqual(candidate["classification"], "name_similarity_risk")
        self.assertEqual(candidate["similar_to"]["target"], "requests")

    def test_allowlisted_private_package_suppresses_false_positive(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            policy_path = root / "policy.toml"
            policy_path.write_text(
                "[thresholds]\nmalicious_score = 10\n\n[allow]\npackages = [\"npm:internal-ai-widget\"]\n",
                encoding="utf-8",
            )
            (root / "package.json").write_text(json.dumps({"dependencies": {"internal-ai-widget": "1.0.0"}}), encoding="utf-8")
            old_env = os.environ.get("SECOPS_SUPPLY_CHAIN_POLICY")
            os.environ["SECOPS_SUPPLY_CHAIN_POLICY"] = str(policy_path)
            try:
                payload = guard.run_ai_dependency_guard(
                    path=root,
                    metadata_fetcher=lambda eco, pkg: registry(False, eco, pkg, error="not_found"),
                )
            finally:
                if old_env is None:
                    os.environ.pop("SECOPS_SUPPLY_CHAIN_POLICY", None)
                else:
                    os.environ["SECOPS_SUPPLY_CHAIN_POLICY"] = old_env

        self.assertEqual(payload["candidates"][0]["classification"], "local_only_or_private")
        self.assertEqual(payload["findings"], [])

    def test_persist_findings_writes_high_confidence_guard_finding(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repo"
            root.mkdir()
            (root / "package.json").write_text(json.dumps({"dependencies": {"ghost-ai-helper": "1.0.0"}}), encoding="utf-8")
            findings_dir = Path(temp_dir) / "findings"
            old_env = os.environ.get("SECOPS_FINDINGS_DIR")
            os.environ["SECOPS_FINDINGS_DIR"] = str(findings_dir)
            try:
                payload = guard.run_ai_dependency_guard(
                    path=root,
                    persist_findings=True,
                    metadata_fetcher=lambda eco, pkg: registry(False, eco, pkg, error="not_found"),
                )
                rows = soc_store.list_findings(payload["db_path"], source=guard.SOURCE, include_payload=True)
            finally:
                if old_env is None:
                    os.environ.pop("SECOPS_FINDINGS_DIR", None)
                else:
                    os.environ["SECOPS_FINDINGS_DIR"] = old_env

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], guard.SOURCE)
        self.assertEqual(rows[0]["classification"], "missing_or_hallucinated")

    def test_guard_module_does_not_import_execution_primitives(self):
        source = inspect.getsource(guard)
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("__import__(", source)
        self.assertNotIn("pip install", source.replace("pip install|", ""))

    def test_cli_ai_dependency_guard_json_and_fail_on(self):
        fake_payload = {
            "ok": True,
            "path": "/tmp/repo",
            "summary": {
                "total_candidates": 1,
                "verified": 0,
                "missing_or_hallucinated": 1,
                "newly_registered": 0,
                "high_risk": 1,
            },
            "candidates": [],
            "findings": [],
            "recommendations": [],
            "would_fail": True,
        }
        stdout = StringIO()
        with mock.patch.object(secopsai_cli, "run_ai_dependency_guard", return_value=fake_payload) as guard_mock, \
             mock.patch("sys.stdout", stdout):
            rc = secopsai_cli.main([
                "--json",
                "supply-chain",
                "ai-dependency-guard",
                "--path",
                ".",
                "--include-agent-logs",
                "--agent-source",
                "sessions",
                "--ecosystem",
                "npm",
                "--fail-on",
                "high",
            ])

        self.assertEqual(rc, 1)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["summary"]["high_risk"], 1)
        self.assertTrue(guard_mock.call_args.kwargs["include_agent_logs"])
        self.assertEqual(guard_mock.call_args.kwargs["agent_source"], "sessions")
        self.assertEqual(guard_mock.call_args.kwargs["ecosystems"], ["npm"])


if __name__ == "__main__":
    unittest.main()
