#!/usr/bin/env python3
"""
SecOpsAI - Incident Response Playbooks
Automated response to supply chain attacks

Usage:
    python incident_response.py --playbook npm_supply_chain --alert-file alert.json
    python incident_response.py --playbook editor_exploit --pid 12345
    python incident_response.py --list-playbooks
"""

import argparse
import json
import sys
import os
import subprocess
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('incident-response')


@dataclass
class PlaybookAction:
    name: str
    description: str
    command: Optional[str]
    automatic: bool
    severity_threshold: int


class IncidentResponsePlaybooks:
    """Collection of incident response playbooks"""
    
    PLAYBOOKS = {
        'npm_supply_chain_compromise': {
            'name': 'NPM Supply Chain Compromise',
            'description': 'Response playbook for npm package supply chain attacks',
            'triggers': ['KNOWN_MALICIOUS_PACKAGE', 'SUSPICIOUS_PUBLISH'],
            'actions': [
                {
                    'name': 'block_egress',
                    'description': 'Block egress to known C2 domains',
                    'command': 'iptables -A OUTPUT -d {c2_domain} -j DROP',
                    'automatic': True,
                    'severity_threshold': 50
                },
                {
                    'name': 'isolate_container',
                    'description': 'Isolate affected containers',
                    'command': 'docker network disconnect bridge {container_id}',
                    'automatic': False,
                    'severity_threshold': 80
                },
                {
                    'name': 'revoke_npm_tokens',
                    'description': 'Revoke all npm tokens for organization',
                    'command': 'npm token revoke --all',
                    'automatic': False,
                    'severity_threshold': 70
                },
                {
                    'name': 'clean_node_modules',
                    'description': 'Remove node_modules and reinstall from lockfile',
                    'command': 'rm -rf node_modules package-lock.json && npm ci',
                    'automatic': False,
                    'severity_threshold': 60
                },
                {
                    'name': 'rotate_secrets',
                    'description': 'Rotate all exposed secrets',
                    'command': None,  # Manual process
                    'automatic': False,
                    'severity_threshold': 90
                },
                {
                    'name': 'notify_security_team',
                    'description': 'Send alert to security team',
                    'command': None,
                    'automatic': True,
                    'severity_threshold': 30
                }
            ]
        },
        
        'editor_exploit_detected': {
            'name': 'Editor Exploit Detection',
            'description': 'Response for Vim/Emacs-based exploits',
            'triggers': ['EDITOR_SHELL_SPAWN', 'MALICIOUS_PLUGIN'],
            'actions': [
                {
                    'name': 'suspend_user',
                    'description': 'Suspend user session',
                    'command': 'pkill -STOP -u {username}',
                    'automatic': False,
                    'severity_threshold': 80
                },
                {
                    'name': 'kill_process_tree',
                    'description': 'Kill process and all children',
                    'command': 'pkill -9 -P {pid} && kill -9 {pid}',
                    'automatic': True,
                    'severity_threshold': 90
                },
                {
                    'name': 'capture_memory',
                    'description': 'Capture memory dump for forensics',
                    'command': 'gcore -o /var/secopsai/dumps/{pid}_{timestamp} {pid}',
                    'automatic': False,
                    'severity_threshold': 70
                },
                {
                    'name': 'quarantine_files',
                    'description': 'Quarantine suspicious files',
                    'command': 'mv {suspicious_file} /var/secopsai/quarantine/',
                    'automatic': True,
                    'severity_threshold': 60
                },
                {
                    'name': 'audit_opened_files',
                    'description': 'List files opened by process',
                    'command': 'lsof -p {pid}',
                    'automatic': True,
                    'severity_threshold': 50
                }
            ]
        },
        
        'python_pth_backdoor': {
            'name': 'Python .pth Backdoor Detection',
            'description': 'Response for Python path file exploits',
            'triggers': ['MALICIOUS_PTH_FILE', 'PYTHON_STARTUP_HOOK'],
            'actions': [
                {
                    'name': 'remove_pth_file',
                    'description': 'Remove malicious .pth file',
                    'command': 'rm -f {pth_file}',
                    'automatic': True,
                    'severity_threshold': 80
                },
                {
                    'name': 'scan_site_packages',
                    'description': 'Scan all site-packages for anomalies',
                    'command': 'find {site_packages} -name "*.pth" -exec cat {} \\;',
                    'automatic': True,
                    'severity_threshold': 50
                },
                {
                    'name': 'audit_python_installs',
                    'description': 'Audit recent pip installations',
                    'command': 'pip list --format=json | jq ".[] | select(.name | contains(\"{suspicious_package}\"))"',
                    'automatic': False,
                    'severity_threshold': 60
                }
            ]
        },
        
        'litellm_proxy_compromise': {
            'name': 'LiteLLM Proxy Compromise',
            'description': 'Response for LiteLLM credential theft',
            'triggers': ['LITELLM_ANOMALY', 'CREDENTIAL_ACCESS'],
            'actions': [
                {
                    'name': 'stop_litellm',
                    'description': 'Stop LiteLLM proxy service',
                    'command': 'systemctl stop litellm || pkill -f litellm',
                    'automatic': True,
                    'severity_threshold': 80
                },
                {
                    'name': 'rotate_llm_keys',
                    'description': 'Rotate all LLM API keys',
                    'command': None,
                    'automatic': False,
                    'severity_threshold': 100
                },
                {
                    'name': 'audit_api_calls',
                    'description': 'Audit recent API calls for abuse',
                    'command': 'grep -r "api.litellm" /var/log/',
                    'automatic': True,
                    'severity_threshold': 70
                },
                {
                    'name': 'check_config_exposure',
                    'description': 'Check for exposed config files',
                    'command': 'find / -name "litellm_config.yaml" -o -name ".env" 2>/dev/null',
                    'automatic': True,
                    'severity_threshold': 60
                }
            ]
        }
    }
    
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.log_dir = Path('/var/secopsai/incidents')
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
    def list_playbooks(self):
        """List available playbooks"""
        print("\n📚 Available Incident Response Playbooks:\n")
        for key, playbook in self.PLAYBOOKS.items():
            print(f"  📋 {key}")
            print(f"     Name: {playbook['name']}")
            print(f"     Description: {playbook['description']}")
            print(f"     Triggers: {', '.join(playbook['triggers'])}")
            print(f"     Actions: {len(playbook['actions'])}")
            print()
    
    def execute_playbook(self, playbook_id: str, context: Dict, auto_confirm: bool = False) -> Dict:
        """Execute a playbook with given context"""
        if playbook_id not in self.PLAYBOOKS:
            logger.error(f"Unknown playbook: {playbook_id}")
            return {'error': 'Unknown playbook'}
        
        playbook = self.PLAYBOOKS[playbook_id]
        results = {
            'playbook': playbook_id,
            'timestamp': datetime.now().isoformat(),
            'context': context,
            'actions_executed': [],
            'actions_skipped': [],
            'actions_failed': []
        }
        
        print(f"\n🚨 EXECUTING PLAYBOOK: {playbook['name']}")
        print(f"   Description: {playbook['description']}")
        print(f"   Context: {json.dumps(context, indent=2)}")
        print()
        
        for action in playbook['actions']:
            action_result = self._execute_action(action, context, auto_confirm)
            
            if action_result['status'] == 'executed':
                results['actions_executed'].append(action_result)
            elif action_result['status'] == 'skipped':
                results['actions_skipped'].append(action_result)
            else:
                results['actions_failed'].append(action_result)
        
        # Save incident log
        incident_file = self.log_dir / f"{playbook_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(incident_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n💾 Incident log saved to: {incident_file}")
        self._print_summary(results)
        
        return results
    
    def _execute_action(self, action: Dict, context: Dict, auto_confirm: bool) -> Dict:
        """Execute a single action"""
        result = {
            'name': action['name'],
            'description': action['description'],
            'status': 'skipped',
            'output': None,
            'error': None
        }
        
        # Check severity threshold
        severity = context.get('severity', 0)
        if severity < action['severity_threshold']:
            result['status'] = 'skipped'
            result['reason'] = f'Severity {severity} below threshold {action["severity_threshold"]}'
            return result
        
        # Format command with context
        command = action['command']
        if command:
            try:
                command = command.format(**context)
            except KeyError as e:
                result['status'] = 'failed'
                result['error'] = f'Missing context variable: {e}'
                return result
        
        # Get confirmation for non-automatic actions
        if not action['automatic'] and not auto_confirm:
            print(f"\n⚠️  ACTION REQUIRES CONFIRMATION:")
            print(f"   Name: {action['name']}")
            print(f"   Description: {action['description']}")
            if command:
                print(f"   Command: {command}")
            
            confirm = input("   Execute? [y/N]: ").strip().lower()
            if confirm != 'y':
                result['status'] = 'skipped'
                result['reason'] = 'User declined'
                return result
        
        # Execute command
        if self.dry_run:
            print(f"   [DRY RUN] Would execute: {command}")
            result['status'] = 'executed'
            result['dry_run'] = True
        elif command:
            print(f"   Executing: {command}")
            try:
                proc = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                result['status'] = 'executed'
                result['output'] = proc.stdout
                if proc.stderr:
                    result['error'] = proc.stderr
                if proc.returncode != 0:
                    result['status'] = 'failed'
                    result['error'] = f'Exit code: {proc.returncode}'
            except subprocess.TimeoutExpired:
                result['status'] = 'failed'
                result['error'] = 'Command timed out'
            except Exception as e:
                result['status'] = 'failed'
                result['error'] = str(e)
        else:
            print(f"   [MANUAL] {action['description']}")
            result['status'] = 'manual'
        
        return result
    
    def _print_summary(self, results: Dict):
        """Print execution summary"""
        print("\n" + "="*60)
        print("📊 PLAYBOOK EXECUTION SUMMARY")
        print("="*60)
        print(f"   ✅ Executed: {len(results['actions_executed'])}")
        print(f"   ⏭️  Skipped: {len(results['actions_skipped'])}")
        print(f"   ❌ Failed: {len(results['actions_failed'])}")
        
        if results['actions_failed']:
            print("\n   Failed Actions:")
            for action in results['actions_failed']:
                print(f"     - {action['name']}: {action.get('error', 'Unknown error')}")


def main():
    parser = argparse.ArgumentParser(description='SecOpsAI Incident Response')
    parser.add_argument('--playbook', '-p', help='Playbook to execute')
    parser.add_argument('--alert-file', '-a', help='Alert JSON file')
    parser.add_argument('--context', '-c', help='Context as JSON string')
    parser.add_argument('--list-playbooks', '-l', action='store_true', help='List available playbooks')
    parser.add_argument('--dry-run', '-d', action='store_true', help='Simulate without executing')
    parser.add_argument('--auto-confirm', '-y', action='store_true', help='Auto-confirm all actions')
    parser.add_argument('--pid', type=int, help='Process ID (for context)')
    parser.add_argument('--username', '-u', help='Username (for context)')
    
    args = parser.parse_args()
    
    playbooks = IncidentResponsePlaybooks(dry_run=args.dry_run)
    
    if args.list_playbooks:
        playbooks.list_playbooks()
        return
    
    if not args.playbook:
        parser.print_help()
        return
    
    # Build context
    context = {}
    if args.alert_file:
        with open(args.alert_file) as f:
            context = json.load(f)
    elif args.context:
        context = json.loads(args.context)
    
    # Add command line context
    if args.pid:
        context['pid'] = args.pid
    if args.username:
        context['username'] = args.username
    if 'timestamp' not in context:
        context['timestamp'] = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Execute playbook
    results = playbooks.execute_playbook(
        args.playbook,
        context,
        auto_confirm=args.auto_confirm
    )
    
    # Exit with error if any actions failed
    if results.get('actions_failed'):
        sys.exit(1)


if __name__ == '__main__':
    main()
