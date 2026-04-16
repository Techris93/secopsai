#!/usr/bin/env python3
"""
SecOpsAI Adaptive Intelligence Pipeline
Master orchestration script that runs the full pipeline:
1. Ingest threat intelligence
2. Generate detection rules
3. Validate against evaluation dataset
4. Deploy if F1 improves
5. Notify via Telegram

Run this daily via launchd/cron for continuous adaptation.
"""

import os
import sys
import subprocess
import json
import re
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
WORKSPACE_DIR = Path.home() / ".openclaw" / "workspace"

# Import from the repo that owns this script, not a stale workspace checkout.
sys.path.insert(0, str(BASE_DIR))

from threat_intel_ingestor import ThreatIntelIngestor
from adaptive_rule_generator import AdaptiveRuleGenerator


class AdaptiveIntelligencePipeline:
    """Master pipeline orchestrator"""
    
    def __init__(self):
        self.workspace = str(WORKSPACE_DIR)
        self.secopsai_dir = str(BASE_DIR)
        self.log_file = os.path.join(self.workspace, 'logs', f'adaptive_intel_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.log')
        self.results = {
            'started_at': datetime.utcnow().isoformat(),
            'indicators_fetched': 0,
            'rules_generated': 0,
            'f1_baseline': 0.0,
            'f1_new': 0.0,
            'deployed': False,
            'errors': []
        }
        
        # Ensure log directory exists
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)

    @staticmethod
    def _extract_f1_scores(text: str) -> list[float]:
        """Extract all F1-like numeric values from command output."""
        scores: list[float] = []
        if not text:
            return scores

        patterns = [
            r"F1_SCORE\s*=\s*([0-9]*\.?[0-9]+)",
            r"\bNew:\s*([0-9]*\.?[0-9]+)",
            r"F1 Score with new rules:\s*([0-9]*\.?[0-9]+)",
            r"F1 Score:\s*([0-9]*\.?[0-9]+)",
        ]
        for pattern in patterns:
            for match in re.findall(pattern, text):
                try:
                    scores.append(float(match))
                except Exception:
                    continue
        return scores
    
    def log(self, message: str):
        """Log to console and file"""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        log_line = f"[{timestamp}] {message}"
        print(log_line)
        with open(self.log_file, 'a') as f:
            f.write(log_line + '\n')
    
    def send_notification(self, message: str):
        """Send Telegram notification"""
        token = os.environ.get('TELEGRAM_BOT_TOKEN', '')
        chat_id = os.environ.get('TELEGRAM_CHAT_ID', '')
        
        if not token or not chat_id:
            self.log("[WARN] Telegram credentials not set, skipping notification")
            return
        
        try:
            import urllib.request
            import urllib.parse
            
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            data = urllib.parse.urlencode({
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }).encode()
            
            urllib.request.urlopen(url, data=data, timeout=10)
            self.log("[NOTIFY] Telegram notification sent")
        except Exception as e:
            self.log(f"[WARN] Failed to send notification: {e}")
    
    def step_1_ingest(self) -> bool:
        """Step 1: Ingest threat intelligence"""
        self.log("=" * 60)
        self.log("STEP 1: Ingesting Threat Intelligence")
        self.log("=" * 60)
        
        try:
            ingestor = ThreatIntelIngestor()
            indicators = ingestor.run()
            self.results['indicators_fetched'] = len(indicators)
            self.log(f"[SUCCESS] Fetched {len(indicators)} indicators")
            return True
        except Exception as e:
            self.log(f"[ERROR] Ingestion failed: {e}")
            self.results['errors'].append(f"Ingestion: {str(e)}")
            return False
    
    def step_2_generate(self) -> bool:
        """Step 2: Generate detection rules"""
        self.log("\n" + "=" * 60)
        self.log("STEP 2: Generating Detection Rules")
        self.log("=" * 60)
        
        try:
            generator = AdaptiveRuleGenerator()
            rules = generator.generate_all_rules()
            generator.save_rules()
            self.results['rules_generated'] = len(rules)
            self.log(f"[SUCCESS] Generated {len(rules)} rules")
            return True
        except Exception as e:
            self.log(f"[ERROR] Generation failed: {e}")
            self.results['errors'].append(f"Generation: {str(e)}")
            return False
    
    def step_3_validate(self) -> bool:
        """Step 3: Validate rules and get baseline F1"""
        self.log("\n" + "=" * 60)
        self.log("STEP 3: Validating Rules")
        self.log("=" * 60)
        
        try:
            # Get baseline F1
            result = subprocess.run(
                ['python3', 'evaluate.py'],
                cwd=self.secopsai_dir,
                capture_output=True,
                text=True
            )

            combined = "\n".join([result.stdout or "", result.stderr or ""])
            scores = self._extract_f1_scores(combined)
            if scores:
                self.results['f1_baseline'] = scores[0]
                self.log(f"[BASELINE] F1 Score: {self.results['f1_baseline']:.6f}")
            else:
                self.log("[WARN] Could not parse baseline F1 from evaluate.py output")
                self.results['errors'].append("Validation: could not parse baseline F1")

            if result.returncode != 0:
                self.log(f"[WARN] evaluate.py exited non-zero: {result.returncode}")
                if result.stderr:
                    for line in result.stderr.splitlines()[-20:]:
                        self.log(f"[EVAL_STDERR] {line}")
            
            return True
        except Exception as e:
            self.log(f"[ERROR] Validation failed: {e}")
            self.results['errors'].append(f"Validation: {str(e)}")
            return False
    
    def step_4_inject_and_test(self) -> bool:
        """Step 4: Inject rules and test improvement"""
        self.log("\n" + "=" * 60)
        self.log("STEP 4: Testing Rule Performance")
        self.log("=" * 60)
        
        try:
            # Run the validator script
            result = subprocess.run(
                ['python3', 'adaptive_rule_validator.py'],
                cwd=self.secopsai_dir,
                capture_output=True,
                text=True
            )

            if result.stdout:
                for line in result.stdout.splitlines()[-80:]:
                    self.log(f"[VALIDATOR_STDOUT] {line}")
            if result.stderr:
                for line in result.stderr.splitlines()[-80:]:
                    self.log(f"[VALIDATOR_STDERR] {line}")
            
            # Check if it succeeded
            if result.returncode == 0:
                self.results['deployed'] = True
                self.log("[SUCCESS] Rules improved F1 and were deployed")
            elif result.returncode == 1:
                self.results['deployed'] = False
                self.log("[INFO] Rules did not improve F1 - skipped deployment")
            else:
                self.results['deployed'] = False
                self.results['errors'].append(f"Testing: validator failed with exit {result.returncode}")
                self.log(f"[ERROR] Adaptive rule validator failed with exit {result.returncode}")
                return False

            # Get new F1 from output (prefer "New:" line, fallback to last parsed score)
            combined = "\n".join([result.stdout or "", result.stderr or ""])
            explicit_new = re.findall(r"\bNew:\s*([0-9]*\.?[0-9]+)", combined)
            if explicit_new:
                try:
                    self.results['f1_new'] = float(explicit_new[-1])
                except Exception:
                    explicit_new = []

            if not explicit_new:
                scores = self._extract_f1_scores(combined)
                if scores:
                    self.results['f1_new'] = scores[-1]

            if self.results['f1_new'] == 0.0 and self.results['f1_baseline'] > 0.0 and not explicit_new:
                # Avoid misleading zero when parser can't recover a "new" score.
                self.results['f1_new'] = self.results['f1_baseline']
                self.results['errors'].append("Testing: could not parse new F1; defaulted to baseline")
                self.log("[WARN] Could not parse new F1, defaulting to baseline value")
            
            return True
        except Exception as e:
            self.log(f"[ERROR] Testing failed: {e}")
            self.results['errors'].append(f"Testing: {str(e)}")
            return False
    
    def step_5_notify(self):
        """Step 5: Send completion notification"""
        self.log("\n" + "=" * 60)
        self.log("STEP 5: Sending Notifications")
        self.log("=" * 60)
        
        # Build summary message
        validation_failed = any("validator failed" in str(err).lower() for err in self.results['errors'])
        status_emoji = "✅" if self.results['deployed'] else ("❌" if validation_failed else "⚠️")
        if self.results['deployed']:
            outcome_line = "✅ Rules DEPLOYED"
        elif validation_failed:
            outcome_line = "❌ Validation failed - rules not deployed"
        else:
            outcome_line = "⚠️ No improvement - rules skipped"
        
        message = f"""{status_emoji} *SecOpsAI Adaptive Intelligence Complete*

📊 *Results:*
• Indicators Fetched: `{self.results['indicators_fetched']}`
• Rules Generated: `{self.results['rules_generated']}`
• F1 Baseline: `{self.results['f1_baseline']:.6f}`
• F1 New: `{self.results['f1_new']:.6f}`

📈 *Improvement:* `{self.results['f1_new'] - self.results['f1_baseline']:+.6f}`

{outcome_line}

📁 *Log:* `{self.log_file}`

⏰ Next run: Tomorrow"""
        
        if self.results['errors']:
            message += f"\n\n⚠️ *Errors:*\n" + '\n'.join(f"• {e}" for e in self.results['errors'][:3])
        
        self.send_notification(message)
        self.log("[DONE] Pipeline complete")
    
    def run(self):
        """Run the full pipeline"""
        self.log("🚀 Starting SecOpsAI Adaptive Intelligence Pipeline")
        self.log(f"📝 Log: {self.log_file}")
        
        # Run steps
        success = True
        
        if not self.step_1_ingest():
            success = False
        
        if success and not self.step_2_generate():
            success = False
        
        if success and not self.step_3_validate():
            success = False
        
        if success and not self.step_4_inject_and_test():
            success = False
        
        # Always notify
        self.step_5_notify()
        
        # Save results JSON
        self.results['ended_at'] = datetime.utcnow().isoformat()
        results_path = os.path.join(self.workspace, 'logs', 'adaptive_results.json')
        with open(results_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        return success


def main():
    """Main entry point"""
    pipeline = AdaptiveIntelligencePipeline()
    success = pipeline.run()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
