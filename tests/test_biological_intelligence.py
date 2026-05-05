from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import soc_store
from secopsai import cli
from secopsai.biological_intelligence import evaluate_security_biology
from secopsai.triage import generate_summary


def _sample_findings():
    return [
        {
            "finding_id": "OCF-BIO001",
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
            "finding_id": "OCF-BIO002",
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


class BiologicalIntelligenceTests(unittest.TestCase):
    def test_evaluate_security_biology_activates_immune_mode_and_all_nature_models(self):
        payload = evaluate_security_biology(_sample_findings())

        self.assertEqual(payload["design_principle"], "Biological Intelligence Layer")
        self.assertEqual(payload["loop"], ["observe", "detect_pattern", "adapt_response", "remember_outcome"])
        self.assertEqual(payload["immune_system"]["mode"], "active")
        self.assertTrue(payload["ant_colonies"]["pheromone_trails"])
        self.assertTrue(payload["mycelium_networks"]["weak_signal_clusters"])
        self.assertTrue(payload["flocking_birds"]["agent_rules"])
        self.assertTrue(payload["predator_prey_cycles"]["red_blue_simulations"])
        self.assertTrue(payload["skin"]["layered_defense"])
        self.assertTrue(payload["circadian_rhythm"]["time_aware_anomalies"])
        self.assertTrue(payload["tree_roots"]["asset_priorities"])
        self.assertTrue(payload["echolocation"]["safe_probes"])
        self.assertTrue(payload["octopus_camouflage"]["deception_recommendations"])
        self.assertEqual(payload["findings"][0]["recommended_state"], "immune_response")

    def test_triage_summary_embeds_biological_intelligence_layer(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            db_path = str(temp_path / "soc.db")
            soc_store.persist_findings(_sample_findings(), source="secopsai-test", db_path=db_path)

            summary = generate_summary(
                db_path=db_path,
                summary_dir=str(temp_path / "summaries"),
            )

            bio = summary["biological_intelligence"]
            self.assertEqual(bio["design_principle"], "Biological Intelligence Layer")
            self.assertEqual(bio["immune_system"]["mode"], "active")
            markdown = Path(summary["summary_markdown"]).read_text(encoding="utf-8")
            self.assertIn("## Biological Intelligence", markdown)
            self.assertIn("Immune Mode: active", markdown)

    def test_cli_bio_intel_outputs_json_and_persists_memory(self):
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
                        "bio-intel",
                        "--db-path",
                        db_path,
                        "--memory-path",
                        str(memory_path),
                        "--persist-memory",
                    ]
                )

            self.assertEqual(rc, 0)
            payload = json.loads(stdout.getvalue())
            self.assertEqual(payload["immune_system"]["mode"], "active")
            self.assertTrue(memory_path.exists())


if __name__ == "__main__":
    unittest.main()
