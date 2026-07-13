from __future__ import annotations

import io
import json
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
    add_ioc,
    add_subject,
    create_case,
    draft_case_blog,
    export_case,
    get_case,
    link_finding,
    list_cases,
    retract_item,
    update_case,
)


SUMMARY = (
    "A typosquatted payment package copied legitimate branding and introduced "
    "credential collection plus attacker-controlled network egress during checkout."
)


class ResearchCaseTests(unittest.TestCase):
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
            markdown = Path(exported["markdown_report"]).read_text(encoding="utf-8")
            self.assertIn("Indicators of Compromise", markdown)
            self.assertIn("checkout-telemetry.example", markdown)
            self.assertTrue(exported["publication_readiness"]["ready"])

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
