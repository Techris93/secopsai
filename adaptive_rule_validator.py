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
from datetime import datetime
from typing import List, Dict, Any, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from adaptive_rule_generator import GeneratedRule, RULES_OUTPUT_DIR

SECOPSAI_DIR = os.path.expanduser("~/.openclaw/workspace/secopsai")
AUTO_RULES_DIR = os.path.join(SECOPSAI_DIR, 'auto_rules')
DETECT_PY_PATH = os.path.join(SECOPSAI_DIR, 'detect.py')


class RuleValidator:
    """Validates generated rules and only keeps F1 improvers"""
    
    def __init__(self):
        self.baseline_f1 = 0.0
        self.new_f1 = 0.0
        self.validated_rules: List[GeneratedRule] = []
        self.rejected_rules: List[GeneratedRule] = []
    
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
        
        # Read all generated rule files
        rule_files = [f for f in os.listdir(AUTO_RULES_DIR) 
                      if f.startswith('auto_rule_') and f.endswith('.py')]
        
        if not rule_files:
            print("[WARN] No auto-generated rules found")
            return False
        
        # Read current detect.py
        with open(DETECT_PY_PATH, 'r') as f:
            detect_content = f.read()
        
        # Check if already injected
        if '# === AUTO-GENERATED RULES ===' in detect_content:
            print("[INFO] Rules already injected, removing old ones...")
            # Remove old auto-generated section
            lines = detect_content.split('\n')
            new_lines = []
            in_auto_section = False
            for line in lines:
                if '# === AUTO-GENERATED RULES ===' in line:
                    in_auto_section = True
                    continue
                if '# === END AUTO-GENERATED RULES ===' in line:
                    in_auto_section = False
                    continue
                if not in_auto_section:
                    new_lines.append(line)
            detect_content = '\n'.join(new_lines)
        
        # Build auto-generated section
        auto_section = ['\n# === AUTO-GENERATED RULES ===', 
                        f'# Generated: {datetime.utcnow().isoformat()}',
                        '']
        
        for rule_file in sorted(rule_files):
            rule_path = os.path.join(AUTO_RULES_DIR, rule_file)
            with open(rule_path, 'r') as f:
                rule_content = f.read()
            
            auto_section.append(f'# --- From {rule_file} ---')
            auto_section.append(rule_content)
            auto_section.append('')
        
        auto_section.append('# === END AUTO-GENERATED RULES ===')
        
        # Inject before the last few lines (after all existing rules)
        injection_point = detect_content.rfind('\ndef get_all_rules():')
        if injection_point == -1:
            injection_point = len(detect_content)
        
        new_content = (detect_content[:injection_point] + 
                      '\n'.join(auto_section) + 
                      '\n' + detect_content[injection_point:])
        
        # Write back
        with open(DETECT_PY_PATH, 'w') as f:
            f.write(new_content)
        
        print(f"[INJECT] Injected {len(rule_files)} auto-generated rules into detect.py")
        return True
    
    def get_new_f1(self) -> float:
        """Get F1 score with new rules injected"""
        print("[TEST] Running evaluation with new rules...")
        
        result = subprocess.run(
            ['python3', 'evaluate.py'],
            cwd=SECOPSAI_DIR,
            capture_output=True,
            text=True
        )
        
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
        
        return 0.0
    
    def rollback_detect_py(self):
        """Remove auto-generated rules from detect.py"""
        with open(DETECT_PY_PATH, 'r') as f:
            detect_content = f.read()
        
        # Remove auto-generated section
        lines = detect_content.split('\n')
        new_lines = []
        in_auto_section = False
        
        for line in lines:
            if '# === AUTO-GENERATED RULES ===' in line:
                in_auto_section = True
                continue
            if '# === END AUTO-GENERATED RULES ===' in line:
                in_auto_section = False
                continue
            if not in_auto_section:
                new_lines.append(line)
        
        with open(DETECT_PY_PATH, 'w') as f:
            f.write('\n'.join(new_lines))
        
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
        self.get_new_f1()
        
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
    else:
        print("\n" + "=" * 60)
        print("❌ No improvement from new rules - rolled back")
        print("=" * 60)
        sys.exit(1)


if __name__ == '__main__':
    main()
