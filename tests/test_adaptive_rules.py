import ast
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import adaptive_rule_generator as generator_mod
import adaptive_rule_validator as validator_mod


class AdaptiveRuleGeneratorTests(unittest.TestCase):
    def test_generated_rce_rule_parses_as_python(self):
        generator = generator_mod.AdaptiveRuleGenerator()
        rule = generator._generate_rce_rule(
            {
                "title": "CVE-2026-33488",
                "source": "unit-test",
                "hash_id": "abc123",
                "mitre_techniques": [],
            }
        )

        ast.parse(rule.python_code)
        self.assertIn(r"""python\d*\s+-c\s+['\"]import\s+socket""", rule.python_code)


class AdaptiveRuleValidatorTests(unittest.TestCase):
    def test_injection_registers_auto_rules_before_run_detection(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            detect_path = root / "detect.py"
            detect_path.write_text(
                "DETECTION_RULES = []\n\n\ndef run_detection(events):\n    return {'total_detections': 0}\n",
                encoding="utf-8",
            )

            rules_dir = root / "auto_rules"
            rules_dir.mkdir()
            (rules_dir / "auto_rule_auto_001.py").write_text(
                'def detect_auto_001(events):\n    return []\n',
                encoding="utf-8",
            )

            with mock.patch.object(validator_mod, "AUTO_RULES_DIR", str(rules_dir)), \
                 mock.patch.object(validator_mod, "DETECT_PY_PATH", str(detect_path)):
                validator = validator_mod.RuleValidator()
                self.assertTrue(validator.inject_rules_into_detect_py())

            updated = detect_path.read_text(encoding="utf-8")
            self.assertIn("DETECTION_RULES.extend([", updated)
            self.assertIn('{"id": "AUTO-001"', updated)
            self.assertIn("detect_auto_001", updated)
            ast.parse(updated)


if __name__ == "__main__":
    unittest.main()
