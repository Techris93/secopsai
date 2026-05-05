from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import soc_store
from secopsai import cli
from secopsai.adaptive_response import evaluate_adaptive_response
from secopsai.triage import generate_summary


def _sample_findings():
    return [
        {
            "finding_id": "OCF-ADAPT001",
            "title": "OpenClaw Credential Exfiltration",
            "summary": "Credential access and exfiltration observed.",
            "severity": "critical",
            "severity_score": 96,
            "status": "open",
            "disposition": "unreviewed",
            "source": "secopsai-test",
            "first_seen": "2026-05-03T23:30:00Z",
            "last_seen": "2026-05-03T23:35:00Z",
            "rule_ids": ["RULE-EXFIL"],
            "events": [
                {"host": "laptop-1", "user": "analyst", "session_key": "s1"},
            ],
        },
        {
            "finding_id": "OCF-ADAPT002",
            "title": "OpenClaw Policy Denials",
            "summary": "Repeated policy denials on the same host.",
            "severity": "high",
            "severity_score": 78,
            "status": "open",
            "disposition": "unreviewed",
            "source": "secopsai-test",
            "first_seen": "2026-05-04T00:10:00Z",
            "last_seen": "2026-05-04T00:11:00Z",
            "rule_ids": ["RULE-DENY"],
            "events": [
                {"host": "laptop-1", "user": "analyst", "session_key": "s2"},
            ],
        },
    ]


class AdaptiveResponseTests(unittest.TestCase):
    def test_evaluate_adaptive_response_activates_response_posture_and_capabilities(self):
        payload = evaluate_adaptive_response(_sample_findings())

        self.assertEqual(payload["design_principle"], "Adaptive Response Layer")
        self.assertEqual(payload["loop"], ["observe", "detect_pattern", "adapt_response", "remember_outcome"])
        self.assertEqual(payload["response_posture"]["mode"], "active")
        self.assertTrue(payload["confidence_memory"]["confidence_trails"])
        self.assertTrue(payload["signal_routing"]["weak_signal_clusters"])
        self.assertTrue(payload["triage_coordination"]["agent_rules"])
        self.assertTrue(payload["adversarial_simulation"]["red_blue_simulations"])
        self.assertTrue(payload["layered_defense"]["layered_defense"])
        self.assertTrue(payload["time_aware_detection"]["time_aware_anomalies"])
        self.assertTrue(payload["priority_routing"]["asset_priorities"])
        self.assertTrue(payload["validation_probes"]["safe_probes"])
        self.assertTrue(payload["deception_controls"]["deception_recommendations"])
        self.assertEqual(payload["findings"][0]["recommended_state"], "heightened_response")

    def test_triage_summary_embeds_adaptive_response_layer(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            soc_store.persist_findings(_sample_findings(), source="secopsai-test", db_path=db_path)

            summary = generate_summary(
                db_path=db_path,
                summary_dir=str(temp_path / "summaries"),
            )

            adaptive = summary["adaptive_response"]
            self.assertEqual(adaptive["design_principle"], "Adaptive Response Layer")
            self.assertEqual(adaptive["response_posture"]["mode"], "active")
            markdown = Path(summary["summary_markdown"]).read_text(encoding="utf-8")
            self.assertIn("## Adaptive Response", markdown)
            self.assertIn("Response Posture: active", markdown)

    def test_cli_adaptive_response_outputs_json_and_persists_memory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            memory_path = temp_path / "memory.json"
            soc_store.persist_findings(_sample_findings(), source="secopsai-test", db_path=db_path)

            stdout = io.StringIO()
            with redirect_stdout(stdout):
                rc = cli.main(
                    [
                        "--json",
                        "adaptive-response",
                        "--db-path",
                        db_path,
                        "--memory-path",
                        str(memory_path),
                        "--persist-memory",
                    ]
                )

            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["response_posture"]["mode"], "active")
            self.assertTrue(memory_path.exists())


if __name__ == "__main__":
    unittest.main()
