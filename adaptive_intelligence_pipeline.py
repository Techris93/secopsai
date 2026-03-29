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
from datetime import datetime
from pathlib import Path

# Add secopsai to path
sys.path.insert(0, os.path.expanduser("~/.openclaw/workspace/secopsai"))

from threat_intel_ingestor import ThreatIntelIngestor
from adaptive_rule_generator import AdaptiveRuleGenerator


class AdaptiveIntelligencePipeline:
    """Master pipeline orchestrator"""
    
    def __init__(self):
        self.workspace = os.path.expanduser("~/.openclaw/workspace")
        self.secopsai_dir = os.path.join(self.workspace, 'secopsai')
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
            
            for line in result.stdout.split('\n'):
                if 'F1_SCORE=' in line:
                    self.results['f1_baseline'] = float(line.split('=')[1].strip())
                    self.log(f"[BASELINE] F1 Score: {self.results['f1_baseline']:.6f}")
                    break
            
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
            
            # Check if it succeeded
            if result.returncode == 0:
                self.results['deployed'] = True
                self.log("[SUCCESS] Rules improved F1 and were deployed")
            else:
                self.results['deployed'] = False
                self.log("[INFO] Rules did not improve F1 - skipped deployment")
            
            # Get new F1 from output
            for line in result.stdout.split('\n'):
                if 'F1_SCORE=' in line or 'New:' in line:
                    try:
                        if 'New:' in line:
                            f1_str = line.split('New:')[1].strip()
                            self.results['f1_new'] = float(f1_str)
                        elif 'new rules:' in line.lower():
                            f1_str = line.split(':')[-1].strip()
                            self.results['f1_new'] = float(f1_str)
                    except:
                        pass
            
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
        status_emoji = "✅" if self.results['deployed'] else "⚠️"
        
        message = f"""{status_emoji} *SecOpsAI Adaptive Intelligence Complete*

📊 *Results:*
• Indicators Fetched: `{self.results['indicators_fetched']}`
• Rules Generated: `{self.results['rules_generated']}`
• F1 Baseline: `{self.results['f1_baseline']:.6f}`
• F1 New: `{self.results['f1_new']:.6f}`

📈 *Improvement:* `{self.results['f1_new'] - self.results['f1_baseline']:+.6f}`

{"✅ Rules DEPLOYED" if self.results['deployed'] else "⚠️ No improvement - rules skipped"}

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
