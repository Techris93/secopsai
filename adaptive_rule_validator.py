#!/usr/bin/env python3
"""
SecOpsAI Adaptive Rule Validator
Tests generated rules against evaluation dataset.
Only keeps rules that improve F1 score.
"""

import os
import sys
import json
import subprocess
import shutil
import re
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adaptive_rule_generator import GeneratedRule, RULES_OUTPUT_DIR

SECOPSAI_DIR = str(Path(__file__).resolve().parent)
AUTO_RULES_DIR = os.path.join(SECOPSAI_DIR, 'auto_rules')
DETECT_PY_PATH = os.path.join(SECOPSAI_DIR, 'detect.py')
AUTO_RULES_START = "# === AUTO-GENERATED RULES ==="
AUTO_RULES_END = "# === END AUTO-GENERATED RULES ==="
AUTO_RULE_REGISTRY_START = "# === AUTO-GENERATED RULE REGISTRY ==="
AUTO_RULE_REGISTRY_END = "# === END AUTO-GENERATED RULE REGISTRY ==="


class RuleValidator:
    """Validates generated rules and only keeps F1 improvers"""
    
    def __init__(self):
        self.baseline_f1 = 0.0
        self.new_f1 = 0.0
        self.validated_rules: List[GeneratedRule] = []
        self.rejected_rules: List[GeneratedRule] = []
        self._original_detect_content: str | None = None
        self.validation_failed = False
    
    def get_baseline_f1(self) -> float:
        """Get current F1 score without new rules"""
        print("[BASELINE] Running evaluation without new rules...")
        
        # Run evaluate.py
        result = subprocess.run(
            ['python3', 'evaluate.py'],
            cwd=SECOPSAI_DIR,
            capture_output=True,
            text=True
        )
        
        # Extract F1 score
        for line in result.stdout.split('\n'):
            if 'F1_SCORE=' in line:
                try:
                    # Handle format: ">>> F1_SCORE=0.862651 <<<"
                    f1_part = line.split('=')[1].strip()
                    # Remove any trailing characters like "<<<"
                    f1_str = f1_part.split()[0]
                    self.baseline_f1 = float(f1_str)
                    print(f"[BASELINE] F1 Score: {self.baseline_f1:.6f}")
                    return self.baseline_f1
                except Exception as e:
                    print(f"[DEBUG] Failed to parse F1 from: {line} - {e}")
                    pass
        
        print(f"[WARN] Could not parse F1, using default 0.0")
        return 0.0
    
    def inject_rules_into_detect_py(self) -> bool:
        """Inject auto-generated rules into detect.py"""
        if not os.path.exists(AUTO_RULES_DIR):
            print("[ERROR] No auto_rules directory found")
            return False

        metadata_path = os.path.join(AUTO_RULES_DIR, "metadata.json")
        rule_files: List[str] = []
        if os.path.exists(metadata_path):
            try:
                with open(metadata_path, "r", encoding="utf-8") as f:
                    metadata = json.load(f)
                for rule in metadata.get("rules", []):
                    rule_id = str(rule.get("rule_id") or "").strip().lower().replace("-", "_")
                    if not rule_id:
                        continue
                    filename = f"auto_rule_{rule_id}.py"
                    if os.path.exists(os.path.join(AUTO_RULES_DIR, filename)):
                        rule_files.append(filename)
                if rule_files:
                    print(f"[INFO] Loading {len(rule_files)} auto rules from metadata.json")
            except Exception as exc:
                print(f"[WARN] Failed to parse metadata.json: {exc}")

        if not rule_files:
            rule_files = [
                f for f in os.listdir(AUTO_RULES_DIR)
                if f.startswith('auto_rule_') and f.endswith('.py')
            ]
        
        if not rule_files:
            print("[WARN] No auto-generated rules found")
            return False
        
        # Read current detect.py
        with open(DETECT_PY_PATH, 'r', encoding='utf-8') as f:
            detect_content = f.read()
        self._original_detect_content = detect_content

        # Remove any previously injected rule bodies and registry entries.
        if AUTO_RULES_START in detect_content or AUTO_RULE_REGISTRY_START in detect_content:
            print("[INFO] Rules already injected, removing old sections...")
            lines = detect_content.splitlines()
            new_lines = []
            skip_until: Optional[str] = None
            for line in lines:
                if AUTO_RULES_START in line:
                    skip_until = AUTO_RULES_END
                    continue
                if AUTO_RULE_REGISTRY_START in line:
                    skip_until = AUTO_RULE_REGISTRY_END
                    continue
                if skip_until:
                    if skip_until in line:
                        skip_until = None
                    continue
                new_lines.append(line)
            detect_content = "\n".join(new_lines)

        # Build auto-generated function section.
        auto_section = [
            "",
            AUTO_RULES_START,
            f'# Generated: {datetime.utcnow().isoformat()}',
            "",
        ]

        registry_entries = []
        for rule_file in sorted(rule_files):
            rule_path = os.path.join(AUTO_RULES_DIR, rule_file)
            with open(rule_path, 'r', encoding='utf-8') as f:
                rule_content = f.read()

            match = re.fullmatch(r'auto_rule_(auto_\d+)\.py', rule_file)
            if not match:
                print(f"[WARN] Skipping unexpected auto-rule filename: {rule_file}")
                continue
            fn_suffix = match.group(1)
            rule_id = fn_suffix.upper().replace("_", "-")
            registry_entries.append(
                f'    {{"id": "{rule_id}", "name": "{rule_id}", "mitre": "AUTO", "fn": detect_{fn_suffix}}},'
            )

            auto_section.append(f'# --- From {rule_file} ---')
            auto_section.append(rule_content)
            auto_section.append('')

        if not registry_entries:
            print("[ERROR] No injectable auto-rule functions were discovered")
            return False

        auto_section.append(AUTO_RULES_END)
        auto_section.append("")
        auto_section.append(AUTO_RULE_REGISTRY_START)
        auto_section.append("DETECTION_RULES.extend([")
        auto_section.extend(registry_entries)
        auto_section.append("])")
        auto_section.append(AUTO_RULE_REGISTRY_END)

        injection_point = detect_content.find('\ndef run_detection(')
        if injection_point == -1:
            print("[ERROR] Could not locate run_detection() in detect.py")
            return False

        new_content = (
            detect_content[:injection_point].rstrip()
            + "\n"
            + "\n".join(auto_section)
            + "\n\n"
            + detect_content[injection_point:].lstrip()
        )

        # Write back
        with open(DETECT_PY_PATH, 'w', encoding='utf-8') as f:
            f.write(new_content)

        print(f"[INJECT] Injected {len(rule_files)} auto-generated rules into detect.py")
        return True
    
    def get_new_f1(self) -> Optional[float]:
        """Get F1 score with new rules injected"""
        print("[TEST] Running evaluation with new rules...")
        
        result = subprocess.run(
            ['python3', 'evaluate.py'],
            cwd=SECOPSAI_DIR,
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            self.validation_failed = True
            print(f"[ERROR] evaluate.py failed after injecting rules (exit {result.returncode})")
            if result.stdout:
                print("[ERROR] evaluate.py stdout tail:")
                for line in result.stdout.splitlines()[-20:]:
                    print(f"  {line}")
            if result.stderr:
                print("[ERROR] evaluate.py stderr tail:")
                for line in result.stderr.splitlines()[-20:]:
                    print(f"  {line}")
            return None
        
        for line in result.stdout.split('\n'):
            if 'F1_SCORE=' in line:
                try:
                    # Handle format: ">>> F1_SCORE=0.862651 <<<"
                    f1_part = line.split('=')[1].strip()
                    # Remove any trailing characters like "<<<"
                    f1_str = f1_part.split()[0]
                    self.new_f1 = float(f1_str)
                    print(f"[TEST] F1 Score with new rules: {self.new_f1:.6f}")
                    return self.new_f1
                except Exception as e:
                    print(f"[DEBUG] Failed to parse F1 from: {line} - {e}")
                    pass

        self.validation_failed = True
        print("[ERROR] Could not parse new F1 from evaluate.py output")
        return None
    
    def rollback_detect_py(self):
        """Remove auto-generated rules from detect.py"""
        if self._original_detect_content is None:
            with open(DETECT_PY_PATH, 'r', encoding='utf-8') as f:
                self._original_detect_content = f.read()

        with open(DETECT_PY_PATH, 'w', encoding='utf-8') as f:
            f.write(self._original_detect_content)
        
        print("[ROLLBACK] Removed auto-generated rules from detect.py")
    
    def validate_individual_rules(self) -> List[Tuple[GeneratedRule, float]]:
        """Test each rule individually to find which ones help"""
        print("[VALIDATE] Testing rules individually...")
        
        # This would require more sophisticated testing
        # For now, we validate as a batch
        return []
    
    def commit_validated_rules(self):
        """Commit only the validated (improving) rules"""
        if not self.validated_rules:
            print("[INFO] No rules to commit")
            return
        
        # Copy only validated rules to a permanent location
        validated_dir = os.path.join(SECOPSAI_DIR, 'validated_rules')
        os.makedirs(validated_dir, exist_ok=True)
        
        for rule in self.validated_rules:
            src = os.path.join(AUTO_RULES_DIR, f"auto_rule_{rule.rule_id.lower().replace('-', '_')}.py")
            dst = os.path.join(validated_dir, f"{rule.rule_id.lower().replace('-', '_')}.py")
            if os.path.exists(src):
                shutil.copy2(src, dst)
        
        print(f"[COMMIT] Saved {len(self.validated_rules)} validated rules to {validated_dir}")
    
    def run(self) -> bool:
        """Full validation pipeline"""
        print("=" * 60)
        print("SecOpsAI Adaptive Rule Validator")
        print(f"Started: {datetime.utcnow().isoformat()}")
        print("=" * 60)
        
        # Step 1: Get baseline
        self.get_baseline_f1()
        
        # Step 2: Inject new rules
        if not self.inject_rules_into_detect_py():
            return False
        
        # Step 3: Test with new rules
        new_f1 = self.get_new_f1()
        if new_f1 is None:
            self.rollback_detect_py()
            return False
        self.new_f1 = new_f1
        
        # Step 4: Decide
        improvement = self.new_f1 - self.baseline_f1
        
        if improvement > 0.001:  # At least 0.1% improvement
            print(f"\n[✅ SUCCESS] F1 improved by {improvement:.6f}")
            print(f"  Baseline: {self.baseline_f1:.6f}")
            print(f"  New:      {self.new_f1:.6f}")
            
            # Keep the rules in detect.py
            # (they're already injected)
            
            # Commit to git
            self._git_commit_rules()
            return True
        else:
            print(f"\n[❌ REJECTED] No improvement or regression")
            print(f"  Baseline: {self.baseline_f1:.6f}")
            print(f"  New:      {self.new_f1:.6f}")
            print(f"  Change:   {improvement:.6f}")
            
            # Rollback
            self.rollback_detect_py()
            return False
    
    def _git_commit_rules(self):
        """Commit the validated rules to git"""
        try:
            # Add detect.py with new rules
            subprocess.run(['git', 'add', 'detect.py'], cwd=SECOPSAI_DIR, check=True)
            
            # Also add the auto_rules directory
            subprocess.run(['git', 'add', 'auto_rules/'], cwd=SECOPSAI_DIR, check=True)
            
            # Commit
            commit_msg = f"""feat: Auto-generated threat intel rules

F1 improved: {self.baseline_f1:.6f} → {self.new_f1:.6f} (+{self.new_f1 - self.baseline_f1:.6f})

Generated from latest threat intelligence:
- CVE database
- Security RSS feeds  
- GitHub exploit PoCs

Rules are automatically validated before inclusion."""
            
            subprocess.run(['git', 'commit', '-m', commit_msg], cwd=SECOPSAI_DIR, check=True)
            
            print("[GIT] Committed validated rules")
            
        except subprocess.CalledProcessError as e:
            print(f"[WARN] Git commit failed: {e}")


def main():
    """Main entry point"""
    validator = RuleValidator()
    success = validator.run()
    
    if success:
        print("\n" + "=" * 60)
        print("✅ Adaptive rules deployed successfully!")
        print("=" * 60)
        sys.exit(0)
    if validator.validation_failed:
        print("\n" + "=" * 60)
        print("❌ Adaptive rules validation failed")
        print("=" * 60)
        sys.exit(2)
    else:
        print("\n" + "=" * 60)
        print("❌ No improvement from new rules - rolled back")
        print("=" * 60)
        sys.exit(1)


if __name__ == '__main__':
    main()
