from __future__ import annotations

import io
import hashlib
import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import soc_store
from secopsai import cli
from secopsai.blog import BlogPaths, draft_research_case
from secopsai.research_cases import (
    add_evidence,
    add_local_artifact,
    add_ioc,
    add_rule,
    add_subject,
    create_case,
    draft_case_blog,
    export_case,
    get_case,
    link_finding,
    list_cases,
    retract_item,
    start_package_case,
    update_case,
)
from secopsai.research_watchlists import promote_watchlist_packages, select_watchlist_packages


SUMMARY = (
    "A typosquatted payment package copied legitimate branding and introduced "
    "credential collection plus attacker-controlled network egress during checkout."
)


class ResearchCaseTests(unittest.TestCase):
    def test_init_db_migrates_legacy_research_status_columns(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "legacy.db")
            with sqlite3.connect(db_path) as connection:
                connection.executescript(
                    """
                    CREATE TABLE research_subjects (
                        subject_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, subject_type TEXT NOT NULL,
                        ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
                        publisher TEXT NOT NULL, metadata_json TEXT NOT NULL, created_at TEXT NOT NULL
                    );
                    CREATE TABLE research_evidence (
                        evidence_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, evidence_type TEXT NOT NULL,
                        title TEXT NOT NULL, locator TEXT NOT NULL, sha256 TEXT NOT NULL,
                        provenance TEXT NOT NULL, notes TEXT NOT NULL, collected_at TEXT NOT NULL,
                        created_at TEXT NOT NULL, metadata_json TEXT NOT NULL
                    );
                    CREATE TABLE research_iocs (
                        ioc_id TEXT PRIMARY KEY, case_id TEXT NOT NULL, ioc_type TEXT NOT NULL,
                        value TEXT NOT NULL, confidence INTEGER NOT NULL, first_seen TEXT,
                        last_seen TEXT, source_evidence_id TEXT, tags_json TEXT NOT NULL,
                        created_at TEXT NOT NULL
                    );
                    """
                )

            soc_store.init_db(db_path)

            with soc_store.connect(db_path) as connection:
                for table in ("research_subjects", "research_evidence", "research_iocs"):
                    columns = {str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table})")}
                    self.assertIn("status", columns)
                    status_column = next(
                        row for row in connection.execute(f"PRAGMA table_info({table})")
                        if str(row["name"]) == "status"
                    )
                    self.assertEqual(str(status_column["dflt_value"]), "'active'")
            self.assertEqual(list_cases(db_path=db_path), [])

    def test_init_db_migrates_potential_impact_override_column(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "impact.db")
            with sqlite3.connect(db_path) as connection:
                connection.execute(
                    """CREATE TABLE research_cases (
                        case_id TEXT PRIMARY KEY, title TEXT NOT NULL, summary TEXT NOT NULL,
                        case_type TEXT NOT NULL, severity TEXT NOT NULL, confidence INTEGER NOT NULL,
                        status TEXT NOT NULL, owner TEXT NOT NULL, disclosure_status TEXT NOT NULL,
                        embargo_until TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                        closed_at TEXT, published_at TEXT, payload_json TEXT NOT NULL,
                        potential_impact TEXT NOT NULL DEFAULT 'medium'
                    )"""
                )
                connection.execute("PRAGMA user_version = 3")
                connection.commit()
            soc_store.init_db(db_path)
            with soc_store.connect(db_path) as connection:
                columns = {str(row["name"]): row for row in connection.execute("PRAGMA table_info(research_cases)")}
            self.assertIn("potential_impact_explicit", columns)
            self.assertEqual(str(columns["potential_impact_explicit"]["dflt_value"]), "0")

    def _build_ready_case(self, db_path: str) -> dict:
        case = create_case(
            title="Typosquatted payment package investigation",
            summary=SUMMARY,
            case_type="typosquatting",
            severity="critical",
            confidence=90,
            owner="research-team",
            db_path=db_path,
        )
        case = add_subject(
            case["case_id"],
            subject_type="package",
            ecosystem="nuget",
            name="Braintree.Payments.SDK",
            version="4.2.1",
            publisher="unknown-publisher",
            db_path=db_path,
        )
        case = add_evidence(
            case["case_id"],
            evidence_type="source",
            title="Public registry package record",
            locator="https://example.test/packages/braintree-payments-sdk",
            provenance="public package registry",
            db_path=db_path,
        )
        case = add_evidence(
            case["case_id"],
            evidence_type="static_analysis",
            title="Extracted package static analysis",
            sha256="a" * 64,
            notes="Obfuscated JavaScript captures payment fields and posts them to an external domain.",
            provenance="isolated local extraction",
            db_path=db_path,
        )
        evidence_id = case["evidence"][0]["evidence_id"]
        case = add_ioc(
            case["case_id"],
            ioc_type="domain",
            value="checkout-telemetry.example",
            confidence="high",
            source_evidence_id=evidence_id,
            tags=["credential-theft", "payment-skimmer"],
            db_path=db_path,
        )
        return update_case(
            case["case_id"],
            status="ready_to_publish",
            disclosure_status="not_required",
            db_path=db_path,
        )

    def test_case_lifecycle_is_structured_idempotent_and_exportable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            case = self._build_ready_case(db_path)

            duplicate = add_subject(
                case["case_id"],
                subject_type="package",
                ecosystem="nuget",
                name="Braintree.Payments.SDK",
                version="4.2.1",
                publisher="updated-publisher",
                db_path=db_path,
            )
            duplicate = add_ioc(
                case["case_id"],
                ioc_type="domain",
                value="checkout-telemetry.example",
                confidence=95,
                tags=["payment-skimmer"],
                db_path=db_path,
            )

            self.assertRegex(case["case_id"], r"^RSC-[A-F0-9]{12}$")
            self.assertEqual(len(duplicate["subjects"]), 1)
            self.assertEqual(duplicate["subjects"][0]["publisher"], "updated-publisher")
            self.assertEqual(len(duplicate["iocs"]), 1)
            self.assertEqual(duplicate["iocs"][0]["confidence"], 95)
            self.assertTrue(duplicate["publication_readiness"]["ready"])
            self.assertGreaterEqual(len(duplicate["timeline"]), 7)

            exported = export_case(
                case["case_id"],
                db_path=db_path,
                output_dir=str(Path(temp_dir) / "reports"),
            )
            self.assertTrue(Path(exported["json_report"]).exists())
            self.assertTrue(Path(exported["manifest"]).exists())
            markdown = Path(exported["markdown_report"]).read_text(encoding="utf-8")
            self.assertIn("Indicators of Compromise", markdown)
            self.assertIn("checkout-telemetry.example", markdown)
            self.assertTrue(exported["publication_readiness"]["ready"])

            repeat_dir = Path(temp_dir) / "repeat"
            repeated = export_case(case["case_id"], db_path=db_path, output_dir=str(repeat_dir))
            self.assertEqual(
                Path(exported["json_report"]).read_bytes(),
                Path(repeated["json_report"]).read_bytes(),
            )
            self.assertEqual(
                Path(exported["markdown_report"]).read_bytes(),
                Path(repeated["markdown_report"]).read_bytes(),
            )
            manifest = json.loads(Path(exported["manifest"]).read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], "secopsai.research.export-manifest.v1")
            for item in manifest["files"]:
                report_bytes = (Path(exported["json_report"]).parent / item["name"]).read_bytes()
                self.assertEqual(item["bytes"], len(report_bytes))
                self.assertEqual(item["sha256"], hashlib.sha256(report_bytes).hexdigest())

    def test_npm_watchlist_selection_excludes_other_ecosystems(self) -> None:
        watchlist = {
            "packages": ["npm:chalk-tempalte", "pypi:requests-lookalike", "axios-utils", "npm:chalk-tempalte"],
        }
        selected = select_watchlist_packages(
            watchlist,
            ecosystem="npm",
            packages=["npm:chalk-tempalte", "axios-utils"],
        )
        self.assertEqual([item["package"] for item in selected], ["chalk-tempalte", "axios-utils"])
        with self.assertRaisesRegex(ValueError, "invalid npm package"):
            select_watchlist_packages(watchlist, ecosystem="npm", packages=["pypi:requests-lookalike"])

    def test_watchlist_promotion_is_previewable_idempotent_and_provenance_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            db_path = str(root / "soc.db")
            watchlist_path = root / "watchlist.json"
            watchlist_path.write_text(
                json.dumps({"packages": ["npm:chalk-tempalte", "pypi:other-package"]}),
                encoding="utf-8",
            )

            preview = promote_watchlist_packages(
                ecosystem="npm",
                packages=["npm:chalk-tempalte"],
                db_path=db_path,
                watchlist_path=str(watchlist_path),
            )
            self.assertTrue(preview["dry_run"])
            self.assertEqual(preview["selected"][0]["package"], "chalk-tempalte")
            self.assertEqual(preview["created"], [])

            created = promote_watchlist_packages(
                ecosystem="npm",
                packages=["npm:chalk-tempalte"],
                create=True,
                owner="research-team",
                actor="watchlist-test",
                db_path=db_path,
                watchlist_path=str(watchlist_path),
            )
            self.assertEqual(len(created["created"]), 1)
            case = get_case(created["created"][0]["case_id"], db_path=db_path)
            self.assertEqual(case["subjects"][0]["ecosystem"], "npm")
            self.assertEqual(case["evidence"][0]["locator"], "local://secopsai/campaign-watchlist")
            self.assertIn("execution=false", case["evidence"][0]["notes"])

            repeated = promote_watchlist_packages(
                ecosystem="npm",
                packages=["chalk-tempalte"],
                create=True,
                db_path=db_path,
                watchlist_path=str(watchlist_path),
            )
            self.assertEqual(repeated["created"], [])
            self.assertEqual(repeated["existing"][0]["case_id"], created["created"][0]["case_id"])

    def test_cli_watchlist_promotion_requires_create_for_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            db_path = root / "soc.db"
            watchlist_path = root / "watchlist.json"
            watchlist_path.write_text(json.dumps({"packages": ["npm:demo-package"]}), encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli.main([
                    "--json",
                    "research",
                    "case",
                    "from-watchlist",
                    "--ecosystem",
                    "npm",
                    "--package",
                    "npm:demo-package",
                    "--watchlist-path",
                    str(watchlist_path),
                    "--db-path",
                    str(db_path),
                ])
            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertTrue(payload["dry_run"])
            self.assertEqual(payload["created"], [])

    def test_case_links_existing_soc_finding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            soc_store.persist_findings(
                [
                    {
                        "finding_id": "SCM-CASE-LINK",
                        "title": "Suspicious package",
                        "summary": "Package needs investigation.",
                        "severity": "high",
                        "severity_score": 80,
                        "status": "open",
                        "disposition": "unreviewed",
                        "first_seen": "2026-07-13T00:00:00Z",
                        "last_seen": "2026-07-13T00:00:00Z",
                    }
                ],
                source="test",
                db_path=db_path,
            )
            case = create_case(title="Finding-linked package research", db_path=db_path)
            linked = link_finding(case["case_id"], "SCM-CASE-LINK", relationship="derived_from", db_path=db_path)

            self.assertEqual(linked["findings"][0]["finding_id"], "SCM-CASE-LINK")
            self.assertEqual(linked["findings"][0]["relationship"], "derived_from")

    def test_detection_rules_are_validated_exported_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            case = self._build_ready_case(db_path)
            sigma = """title: Suspicious package execution\nlogsource:\n  product: application\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n"""
            yara = """rule SuspiciousPackage {\n  strings:\n    $domain = \"telemetry.example\"\n  condition:\n    $domain\n}\n"""
            semgrep = """rules:\n  - id: suspicious-package-egress\n    message: Detects suspicious package egress\n    severity: WARNING\n    pattern: requests.post($URL, ...)\n"""

            case = add_rule(
                case["case_id"],
                rule_type="sigma",
                name="suspicious-package-execution",
                content=sigma,
                purpose="Detect process execution associated with package installation.",
                db_path=db_path,
            )
            case = add_rule(case["case_id"], rule_type="yara", name="suspicious-package", content=yara, db_path=db_path)
            case = add_rule(case["case_id"], rule_type="semgrep", name="suspicious-package-egress", content=semgrep, db_path=db_path)

            self.assertEqual(len(case["rules"]), 3)
            self.assertTrue(all(item["validation_status"] == "passed" for item in case["rules"]))
            self.assertTrue(case["publication_readiness"]["ready"])

            exported = export_case(case["case_id"], db_path=db_path, output_dir=str(Path(temp_dir) / "reports"))
            export_payload = json.loads(Path(exported["json_report"]).read_text(encoding="utf-8"))
            self.assertEqual(len(export_payload["rules"]), 3)
            markdown = Path(exported["markdown_report"]).read_text(encoding="utf-8")
            self.assertIn("Detection Rules", markdown)
            self.assertIn("suspicious-package-egress", markdown)
            self.assertIn("telemetry.example", markdown)

            repeated = export_case(case["case_id"], db_path=db_path, output_dir=str(Path(temp_dir) / "repeat"))
            self.assertEqual(Path(exported["json_report"]).read_bytes(), Path(repeated["json_report"]).read_bytes())
            self.assertEqual(Path(exported["markdown_report"]).read_bytes(), Path(repeated["markdown_report"]).read_bytes())

            updated = add_rule(
                case["case_id"],
                rule_type="sigma",
                name="suspicious-package-execution",
                content=sigma.replace("EventID: 1", "EventID: 7"),
                db_path=db_path,
            )
            self.assertEqual(len(updated["rules"]), 3)
            self.assertIn("EventID: 7", next(item for item in updated["rules"] if item["rule_type"] == "sigma")["content"])

    def test_failed_rule_validation_blocks_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            case = self._build_ready_case(db_path)
            invalid = add_rule(
                case["case_id"],
                rule_type="sigma",
                name="incomplete-rule",
                content="title: Missing required fields\n",
                db_path=db_path,
            )

            rule = invalid["rules"][0]
            self.assertEqual(rule["validation_status"], "failed")
            self.assertFalse(invalid["publication_readiness"]["ready"])
            self.assertIn("every active detection rule must pass structural validation", invalid["publication_readiness"]["blockers"])

            retracted = retract_item(
                invalid["case_id"],
                item_type="rule",
                item_id=rule["rule_id"],
                reason="Replaced with a reviewed rule.",
                db_path=db_path,
            )
            self.assertEqual(retracted["rules"][0]["status"], "retracted")
            self.assertTrue(retracted["publication_readiness"]["ready"])

    def test_cli_add_rule_reads_a_local_file_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            db_path = str(root / "soc.db")
            case = create_case(title="CLI detection rule case", db_path=db_path)
            rule_file = root / "rule.yml"
            rule_file.write_text(
                "title: CLI rule\nlogsource:\n  product: app\ndetection:\n  selection:\n    EventID: 1\n  condition: selection\n",
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli.main([
                    "--json",
                    "research",
                    "case",
                    "add-rule",
                    case["case_id"],
                    "--rule-type",
                    "sigma",
                    "--name",
                    "cli-rule",
                    "--file",
                    str(rule_file),
                    "--db-path",
                    db_path,
                ])
            self.assertEqual(exit_code, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["rules"][0]["name"], "cli-rule")
            self.assertEqual(payload["rules"][0]["validation_status"], "passed")

    def test_retraction_preserves_history_and_excludes_inactive_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            case = self._build_ready_case(db_path)
            source = next(item for item in case["evidence"] if item["evidence_type"] == "source")

            retracted = retract_item(
                case["case_id"],
                item_type="evidence",
                item_id=source["evidence_id"],
                reason="Registry record was attached to the wrong package namespace.",
                actor="reviewer",
                db_path=db_path,
            )

            preserved = next(item for item in retracted["evidence"] if item["evidence_id"] == source["evidence_id"])
            self.assertEqual(preserved["status"], "retracted")
            self.assertFalse(retracted["publication_readiness"]["ready"])
            self.assertIn("at least two evidence records are required", retracted["publication_readiness"]["blockers"])
            self.assertEqual(retracted["timeline"][-1]["event_type"], "evidence_retracted")
            exported = export_case(case["case_id"], db_path=db_path, output_dir=str(Path(temp_dir) / "reports"))
            markdown = Path(exported["markdown_report"]).read_text(encoding="utf-8")
            self.assertNotIn("https://example.test/packages/braintree-payments-sdk", markdown)

    def test_blog_handoff_is_blocked_until_disclosure_and_evidence_are_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            case = create_case(title="Incomplete package investigation", db_path=db_path)

            with self.assertRaisesRegex(ValueError, "not publication-ready"):
                draft_case_blog(case["case_id"], db_path=db_path)

            ready = self._build_ready_case(db_path)
            with mock.patch("secopsai.blog.draft_research_case", return_value={"draft_path": "/tmp/review-draft.json", "review_status": "needs_review"}) as draft:
                payload = draft_case_blog(ready["case_id"], db_path=db_path)

            self.assertEqual(payload["draft_path"], "/tmp/review-draft.json")
            research_case = draft.call_args.args[0]
            self.assertEqual(research_case["case_id"], ready["case_id"])
            self.assertEqual(research_case["iocs"][0]["value"], "checkout-telemetry.example")
            self.assertTrue(get_case(ready["case_id"], db_path=db_path)["timeline"][-1]["event_type"] == "blog_draft_created")

    def test_invalid_evidence_hash_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            case = create_case(title="Hash validation research case", db_path=db_path)
            with self.assertRaisesRegex(ValueError, "64 hexadecimal"):
                add_evidence(
                    case["case_id"],
                    evidence_type="package_artifact",
                    title="Downloaded artifact",
                    sha256="not-a-hash",
                    db_path=db_path,
                )

    def test_local_artifact_is_hash_only_and_does_not_store_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            db_path = str(root / "soc.db")
            artifact = root / "sample-package.nupkg"
            artifact.write_bytes(b"package bytes used only for hashing")
            case = create_case(title="Local artifact hashing case", db_path=db_path)
            hashed = add_local_artifact(case["case_id"], artifact_path=str(artifact), db_path=db_path)

            evidence = hashed["evidence"][-1]
            self.assertEqual(evidence["evidence_type"], "package_artifact")
            self.assertEqual(evidence["sha256"], hashlib.sha256(artifact.read_bytes()).hexdigest())
            self.assertEqual(evidence["metadata"]["collection_mode"], "hash_only")
            self.assertNotIn(str(root), json.dumps(evidence))

            symlink = root / "linked-package.nupkg"
            symlink.symlink_to(artifact)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                add_local_artifact(case["case_id"], artifact_path=str(symlink), db_path=db_path)

    def test_start_package_case_records_leads_without_fetching_or_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            db_path = str(root / "soc.db")
            artifact = root / "package.tgz"
            artifact.write_bytes(b"safe fixture bytes")
            case = start_package_case(
                package="payments-helper",
                ecosystem="npm",
                version="1.2.3",
                publisher="unknown-publisher",
                source_url="https://registry.example.test/payments-helper",
                artifact_path=str(artifact),
                db_path=db_path,
            )

            self.assertEqual(case["status"], "draft")
            self.assertEqual(case["subjects"][0]["name"], "payments-helper")
            self.assertEqual(case["subjects"][0]["ecosystem"], "npm")
            self.assertEqual(len(case["evidence"]), 2)
            self.assertTrue(all(item["metadata"].get("analysis_executed") is False for item in case["evidence"] if item["evidence_type"] == "package_artifact"))
            self.assertTrue(any(item["evidence_type"] == "registry_metadata" for item in case["evidence"]))

    def test_original_research_blog_template_stays_review_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            case = self._build_ready_case(db_path)
            case = add_ioc(
                case["case_id"],
                ioc_type="sha256",
                value="b" * 64,
                confidence=100,
                db_path=db_path,
            )
            case = add_evidence(
                case["case_id"],
                evidence_type="analyst_note",
                title="Sensitive working note",
                notes="api_key=super-secret-research-value",
                db_path=db_path,
            )
            payload = draft_research_case(case, paths=BlogPaths(root=Path(temp_dir) / "blog"))

            draft = json.loads(Path(payload["draft_path"]).read_text(encoding="utf-8"))
            self.assertEqual(draft["review_status"], "needs_review")
            self.assertFalse(draft["external_news"])
            self.assertIn("Original Research", draft["categories"])
            self.assertEqual(draft["research_case_id"], case["case_id"])
            self.assertIn("## Disclosure", draft["body_markdown"])
            self.assertIn("b" * 64, draft["body_markdown"])
            self.assertNotIn("super-secret-research-value", draft["body_markdown"])
            self.assertIn("[REDACTED]", draft["body_markdown"])

    def test_cli_create_and_list_emit_machine_readable_cases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = str(Path(temp_dir) / "soc.db")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli.main(
                    [
                        "--json",
                        "research",
                        "case",
                        "create",
                        "--title",
                        "CLI package research investigation",
                        "--db-path",
                        db_path,
                    ]
                )
            self.assertEqual(exit_code, 0)
            created = json.loads(stdout.getvalue())

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = cli.main(["--json", "research", "case", "list", "--db-path", db_path])
            self.assertEqual(exit_code, 0)
            listed = json.loads(stdout.getvalue())
            self.assertEqual(listed["cases"][0]["case_id"], created["case_id"])
            self.assertEqual(len(list_cases(db_path=db_path)), 1)


if __name__ == "__main__":
    unittest.main()
