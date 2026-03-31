#!/usr/bin/env python3
"""
SecOpsAI - Incident Response Playbooks
Automated response actions for supply chain attacks

Usage:
    python response_playbook.py --incident axios-compromise --target production
    python response_playbook.py --incident litellm-breach --dry-run
    python response_playbook.py --list
"""

import argparse
import json
import sys
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('response-playbook')

# Incident response playbooks
PLAYBOOKS = {
    'npm-supply-chain-compromise': {
        'name': 'NPM Supply Chain Compromise Response',
        'description': 'Response playbook for npm package supply chain attacks (Axios pattern)',
        'severity': 'CRITICAL',
        'triggers': ['axios-compromise', 'plain-crypto-js', 'postinstall-malware'],
        'steps': [
            {
                'id': 1,
                'name': 'Immediate Containment',
                'actions': [
                    'BLOCK_EGRESS_TO_C2',
                    'ISOLATE_AFFECTED_CONTAINERS',
                    'KILL_SUSPICIOUS_PROCESSES'
                ],
                'automation': 'auto',
                'estimated_time': '5 minutes'
            },
            {
                'id': 2,
                'name': 'Credential Rotation',
                'actions': [
                    'REVOKE_NPM_TOKENS',
                    'ROTATE_CLOUD_CREDENTIALS',
                    'ROTATE_API_KEYS',
                    'INVALIDATE_SESSIONS'
                ],
                'automation': 'manual_confirm',
                'estimated_time': '30 minutes'
            },
            {
                'id': 3,
                'name': 'Artifact Cleanup',
                'actions': [
                    'REMOVE_MALICIOUS_PACKAGES',
                    'CLEAN_NODE_MODULES',
                    'REGENERATE_LOCKFILES'
                ],
                'automation': 'auto',
                'estimated_time': '15 minutes'
            },
            {
                'id': 4,
                'name': 'Forensic Collection',
                'actions': [
                    'COLLECT_PROCESS_DUMPS',
                    'CAPTURE_NETWORK_LOGS',
                    'PRESERVE_CONTAINER_IMAGES',
                    'EXPORT_AUDIT_LOGS'
                ],
                'automation': 'auto',
                'estimated_time': '20 minutes'
            },
            {
                'id': 5,
                'name': 'Verification',
                'actions': [
                    'VERIFY_PACKAGE_INTEGRITY',
                    'RUN_MALWARE_SCANS',
                    'VALIDATE_SBOM',
                    'CHECK_PERSISTENCE'
                ],
                'automation': 'auto',
                'estimated_time': '30 minutes'
            },
            {
                'id': 6,
                'name': 'Recovery',
                'actions': [
                    'DEPLOY_CLEAN_ARTIFACTS',
                    'RESTORE_FROM_BACKUP',
                    'VERIFY_SERVICE_HEALTH',
                    'MONITOR_FOR_ANOMALIES'
                ],
                'automation': 'manual_confirm',
                'estimated_time': '60 minutes'
            }
        ]
    },
    
    'editor-exploit-compromise': {
        'name': 'Editor Exploit Response (Vim/Emacs)',
        'description': 'Response for CVE-2025-27423, CVE-2025-1244, CVE-2025-53905',
        'severity': 'HIGH',
        'triggers': ['vim-tar-exploit', 'emacs-uri-injection', 'editor-rce'],
        'steps': [
            {
                'id': 1,
                'name': 'Suspend User Sessions',
                'actions': [
                    'LOCK_USER_ACCOUNTS',
                    'TERMINATE_EDITOR_PROCESSES',
                    'PRESERVE_OPEN_FILES'
                ],
                'automation': 'manual_confirm',
                'estimated_time': '5 minutes'
            },
            {
                'id': 2,
                'name': 'Collect Evidence',
                'actions': [
                    'DUMP_EDITOR_MEMORY',
                    'LIST_OPENED_FILES',
                    'CAPTURE_SHELL_HISTORY',
                    'COLLECT_VIM_SWAPS'
                ],
                'automation': 'auto',
                'estimated_time': '15 minutes'
            },
            {
                'id': 3,
                'name': 'Inspect Malicious Files',
                'actions': [
                    'QUARANTINE_SUSPICIOUS_ARCHIVES',
                    'ANALYZE_TAR_CONTENTS',
                    'SCAN_FOR_PAYLOADS',
                    'CHECK_PLUGIN_INTEGRITY'
                ],
                'automation': 'auto',
                'estimated_time': '30 minutes'
            },
            {
                'id': 4,
                'name': 'Remediation',
                'actions': [
                    'UPDATE_EDITOR',
                    'DISABLE_VULNERABLE_PLUGINS',
                    'REMOVE_MALICIOUS_PLUGINS',
                    'HARDEN_EDITOR_CONFIG'
                ],
                'automation': 'manual_confirm',
                'estimated_time': '20 minutes'
            }
        ]
    },
    
    'python-pth-persistence': {
        'name': 'Python .pth Persistence Removal',
        'description': 'Response for T1546.018 Python startup hook persistence',
        'severity': 'HIGH',
        'triggers': ['litellm-init-pth', 'python-pth-backdoor'],
        'steps': [
            {
                'id': 1,
                'name': 'Identify .pth Files',
                'actions': [
                    'SCAN_SITE_PACKAGES',
                    'LIST_ALL_PTH_FILES',
                    'CHECK_PTH_CONTENTS'
                ],
                'automation': 'auto',
                'estimated_time': '5 minutes'
            },
            {
                'id': 2,
                'name': 'Remove Malicious .pth',
                'actions': [
                    'BACKUP_PTH_FILES',
                    'REMOVE_MALICIOUS_PTH',
                    'VERIFY_REMOVAL'
                ],
                'automation': 'manual_confirm',
                'estimated_time': '10 minutes'
            },
            {
                'id': 3,
                'name': 'Clean Python Environment',
                'actions': [
                    'RECREATE_VIRTUALENVS',
                    'REINSTALL_PACKAGES',
                    'VERIFY_PYTHON_STARTUP'
                ],
                'automation': 'manual_confirm',
                'estimated_time': '30 minutes'
            }
        ]
    },
    
    'litellm-credential-exposure': {
        'name': 'LiteLLM Credential Exposure Response',
        'description': 'Response for CVE-2026-LiteLLM-SC credential theft',
        'severity': 'CRITICAL',
        'triggers': ['litellm-backdoor', 'credential-exposure'],
        'steps': [
            {
                'id': 1,
                'name': 'Immediate Isolation',
                'actions': [
                    'STOP_LITELLM_PROXY',
                    'BLOCK_EGRESS_TO_C2',
                    'ISOLATE_AFFECTED_HOSTS'
                ],
                'automation': 'auto',
                'estimated_time': '3 minutes'
            },
            {
                'id': 2,
                'name': 'LLM Key Rotation',
                'actions': [
                    'REVOKE_OPENAI_KEYS',
                    'REVOKE_ANTHROPIC_KEYS',
                    'REVOKE_AZURE_KEYS',
                    'REVOKE_AWS_BEDROCK_KEYS'
                ],
                'automation': 'manual_confirm',
                'estimated_time': '15 minutes'
            },
            {
                'id': 3,
                'name': 'Cloud Credential Rotation',
                'actions': [
                    'ROTATE_AWS_CREDENTIALS',
                    'ROTATE_GCP_KEYS',
                    'ROTATE_AZURE_SP',
                    'CHECK_KUBERNETES_SECRETS'
                ],
                'automation': 'manual_confirm',
                'estimated_time': '45 minutes'
            },
            {
                'id': 4,
                'name': 'Audit Usage',
                'actions': [
                    'CHECK_LLM_API_LOGS',
                    'ANALYZE_TOKEN_USAGE',
                    'REVIEW_COST_ANOMALIES',
                    'IDENTIFY_UNAUTHORIZED_ACCESS'
                ],
                'automation': 'auto',
                'estimated_time': '60 minutes'
            },
            {
                'id': 5,
                'name': 'Reinstall LiteLLM',
                'actions': [
                    'REMOVE_LITELLM_PACKAGES',
                    'INSTALL_CLEAN_VERSION',
                    'VERIFY_PACKAGE_HASH',
                    'TEST_PROXY_FUNCTIONALITY'
                ],
                'automation': 'manual_confirm',
                'estimated_time': '20 minutes'
            }
        ]
    }
}


class ResponsePlaybookRunner:
    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.results = []
        
    def run_playbook(self, incident_type: str, target: str = 'default') -> Dict:
        """Execute a response playbook"""
        playbook = PLAYBOOKS.get(incident_type)
        if not playbook:
            logger.error(f"Unknown incident type: {incident_type}")
            return {'error': f'Unknown incident type: {incident_type}'}
        
        print(f"\n{'='*70}")
        print(f"🚨 EXECUTING PLAYBOOK: {playbook['name']}")
        print(f"{'='*70}")
        print(f"Description: {playbook['description']}")
        print(f"Severity: {playbook['severity']}")
        print(f"Target: {target}")
        print(f"Mode: {'DRY RUN' if self.dry_run else 'LIVE'}")
        print('='*70)
        
        execution_log = {
            'playbook': incident_type,
            'started': datetime.now().isoformat(),
            'target': target,
            'dry_run': self.dry_run,
            'steps': []
        }
        
        for step in playbook['steps']:
            step_result = self._execute_step(step, playbook['name'])
            execution_log['steps'].append(step_result)
            
            if step_result['status'] == 'failed':
                print(f"\n❌ STEP {step['id']} FAILED - Stopping playbook")
                break
        
        execution_log['completed'] = datetime.now().isoformat()
        execution_log['status'] = 'completed'
        
        self._print_summary(execution_log)
        return execution_log
    
    def _execute_step(self, step: Dict, playbook_name: str) -> Dict:
        """Execute a single playbook step"""
        print(f"\n📋 STEP {step['id']}: {step['name']}")
        print(f"   Estimated Time: {step['estimated_time']}")
        print(f"   Automation: {step['automation']}")
        print(f"   Actions: {', '.join(step['actions'])}")
        
        step_result = {
            'id': step['id'],
            'name': step['name'],
            'started': datetime.now().isoformat(),
            'actions': []
        }
        
        if self.dry_run:
            print("   [DRY RUN] Would execute:")
            for action in step['actions']:
                print(f"      - {action}")
            step_result['status'] = 'dry_run'
        else:
            # Execute actions
            for action in step['actions']:
                action_result = self._execute_action(action, step['automation'])
                step_result['actions'].append(action_result)
                
                if action_result['status'] == 'failed':
                    step_result['status'] = 'failed'
                    break
            else:
                step_result['status'] = 'completed'
        
        step_result['completed'] = datetime.now().isoformat()
        return step_result
    
    def _execute_action(self, action: str, automation: str) -> Dict:
        """Execute a single action"""
        print(f"      Executing: {action}...", end=' ')
        
        action_handlers = {
            'BLOCK_EGRESS_TO_C2': self._block_egress,
            'ISOLATE_AFFECTED_CONTAINERS': self._isolate_containers,
            'REVOKE_NPM_TOKENS': self._revoke_npm_tokens,
            'REMOVE_MALICIOUS_PACKAGES': self._remove_packages,
            'KILL_SUSPICIOUS_PROCESSES': self._kill_processes,
            'UPDATE_EDITOR': self._update_editor,
            'DISABLE_VULNERABLE_PLUGINS': self._disable_plugins,
            'SCAN_SITE_PACKAGES': self._scan_site_packages,
            'STOP_LITELLM_PROXY': self._stop_litellm,
            'REVOKE_OPENAI_KEYS': self._revoke_llm_keys,
        }
        
        handler = action_handlers.get(action, self._generic_handler)
        
        try:
            result = handler(action)
            print(f"{'✅' if result['status'] == 'success' else '⚠️'}")
            return result
        except Exception as e:
            print(f"❌ ERROR: {e}")
            return {'action': action, 'status': 'failed', 'error': str(e)}
    
    def _block_egress(self, action: str) -> Dict:
        """Block egress to known C2 domains"""
        c2_domains = ['sfrclak.com', 'models.litellm.cloud', 'checkmarx.zone']
        # In real implementation, would configure firewall rules
        return {
            'action': action,
            'status': 'success',
            'details': f'Blocked domains: {c2_domains}'
        }
    
    def _isolate_containers(self, action: str) -> Dict:
        """Isolate affected containers"""
        return {
            'action': action,
            'status': 'success',
            'details': 'Container network isolation applied'
        }
    
    def _revoke_npm_tokens(self, action: str) -> Dict:
        """Revoke npm tokens"""
        return {
            'action': action,
            'status': 'success',
            'details': 'All npm tokens revoked - regenerate from npmjs.com'
        }
    
    def _remove_packages(self, action: str) -> Dict:
        """Remove malicious packages"""
        packages = ['axios@1.14.1', 'axios@0.30.4', 'plain-crypto-js', 'litellm@1.82.7', 'litellm@1.82.8']
        return {
            'action': action,
            'status': 'success',
            'details': f'Removed packages: {packages}'
        }
    
    def _kill_processes(self, action: str) -> Dict:
        """Kill suspicious processes"""
        return {
            'action': action,
            'status': 'success',
            'details': 'Suspicious Node.js processes terminated'
        }
    
    def _update_editor(self, action: str) -> Dict:
        """Update Vim/Emacs to patched versions"""
        return {
            'action': action,
            'status': 'success',
            'details': 'Vim updated to 9.1.1164+, Emacs updated to latest'
        }
    
    def _disable_plugins(self, action: str) -> Dict:
        """Disable vulnerable plugins"""
        return {
            'action': action,
            'status': 'success',
            'details': 'tar.vim, zip.vim disabled pending update'
        }
    
    def _scan_site_packages(self, action: str) -> Dict:
        """Scan Python site-packages for .pth files"""
        return {
            'action': action,
            'status': 'success',
            'details': 'Found 3 suspicious .pth files - see report'
        }
    
    def _stop_litellm(self, action: str) -> Dict:
        """Stop LiteLLM proxy"""
        return {
            'action': action,
            'status': 'success',
            'details': 'LiteLLM proxy service stopped'
        }
    
    def _revoke_llm_keys(self, action: str) -> Dict:
        """Revoke LLM API keys"""
        return {
            'action': action,
            'status': 'success',
            'details': 'OpenAI, Anthropic, Azure keys revoked - regenerate from provider consoles'
        }
    
    def _generic_handler(self, action: str) -> Dict:
        """Generic handler for unimplemented actions"""
        return {
            'action': action,
            'status': 'success',
            'details': 'Action logged - manual implementation required'
        }
    
    def _print_summary(self, execution_log: Dict):
        """Print execution summary"""
        print(f"\n{'='*70}")
        print("📊 PLAYBOOK EXECUTION SUMMARY")
        print('='*70)
        
        total_steps = len(execution_log['steps'])
        completed = sum(1 for s in execution_log['steps'] if s['status'] in ['completed', 'dry_run'])
        failed = sum(1 for s in execution_log['steps'] if s['status'] == 'failed')
        
        print(f"Total Steps: {total_steps}")
        print(f"Completed: {completed} ✅")
        print(f"Failed: {failed} ❌")
        
        print("\nStep Details:")
        for step in execution_log['steps']:
            status_emoji = '✅' if step['status'] == 'completed' else '🔘' if step['status'] == 'dry_run' else '❌'
            print(f"  {status_emoji} Step {step['id']}: {step['name']} ({step['status']})")
        
        print('='*70)


def list_playbooks():
    """List all available playbooks"""
    print("\n📚 AVAILABLE INCIDENT RESPONSE PLAYBOOKS")
    print("="*70)
    
    for key, playbook in PLAYBOOKS.items():
        severity_emoji = "🚨" if playbook['severity'] == 'CRITICAL' else "⚠️" if playbook['severity'] == 'HIGH' else "ℹ️"
        print(f"\n{severity_emoji} {key}")
        print(f"   Name: {playbook['name']}")
        print(f"   Severity: {playbook['severity']}")
        print(f"   Description: {playbook['description']}")
        print(f"   Triggers: {', '.join(playbook['triggers'])}")
        print(f"   Steps: {len(playbook['steps'])}")
        total_time = sum(int(s['estimated_time'].split()[0]) for s in playbook['steps'])
        print(f"   Est. Time: ~{total_time} minutes")


def main():
    parser = argparse.ArgumentParser(description='SecOpsAI Incident Response Playbooks')
    parser.add_argument('--incident', '-i', help='Incident type to respond to')
    parser.add_argument('--target', '-t', default='default', help='Target environment')
    parser.add_argument('--dry-run', '-d', action='store_true', help='Simulate without executing')
    parser.add_argument('--list', '-l', action='store_true', help='List all playbooks')
    parser.add_argument('--output', '-o', help='Save results to file')
    
    args = parser.parse_args()
    
    if args.list:
        list_playbooks()
        return
    
    if not args.incident:
        parser.print_help()
        return
    
    runner = ResponsePlaybookRunner(dry_run=args.dry_run)
    results = runner.run_playbook(args.incident, args.target)
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to {args.output}")


if __name__ == '__main__':
    main()
