#!/usr/bin/env python3
"""
SecOpsAI - Threat Intelligence Integration
Fetches and aggregates threat intelligence for supply chain attacks

Usage:
    python threat_intel.py --update
    python threat_intel.py --check axios
    python threat_intel.py --export-blocklist
"""

import argparse
import json
import hashlib
import requests
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Set
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('threat-intel')


class ThreatIntelligenceAggregator:
    """Aggregates threat intelligence from multiple sources"""
    
    SOURCES = {
        'npm_advisories': 'https://www.npmjs.com/advisories',
        'github_advisories': 'https://api.github.com/advisories',
        'osv_database': 'https://api.osv.dev/v1/query',
        'snyk_vuln_db': 'https://snyk.io/vuln',
    }
    
    def __init__(self, cache_dir: str = ".threat_intel_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.known_iocs = self._load_known_iocs()
        
    def _load_known_iocs(self) -> Dict:
        """Load known indicators of compromise"""
        return {
            'packages': {
                'npm': {
                    'plain-crypto-js': {
                        'versions': ['4.2.1'],
                        'c2_domains': ['sfrclak.com'],
                        'first_seen': '2026-03-31',
                        'attack_type': 'supply_chain',
                        'description': 'Axios supply chain attack RAT dropper'
                    },
                    'axios': {
                        'versions': ['1.14.1', '0.30.4'],
                        'first_seen': '2026-03-31',
                        'attack_type': 'compromised_credentials',
                        'description': 'Compromised npm credentials'
                    },
                    'sync-axios': {
                        'versions': ['*'],
                        'first_seen': '2024-02-20',
                        'attack_type': 'typosquat'
                    },
                    'litellm': {
                        'versions': ['1.82.7', '1.82.8'],
                        'c2_domains': ['models.litellm.cloud', 'checkmarx.zone'],
                        'first_seen': '2026-03-24',
                        'attack_type': 'supply_chain'
                    }
                },
                'pypi': {
                    'litellm': {
                        'versions': ['1.82.7', '1.82.8'],
                        'c2_domains': ['models.litellm.cloud'],
                        'first_seen': '2026-03-24'
                    }
                }
            },
            'c2_domains': [
                'sfrclak.com',
                'models.litellm.cloud',
                'checkmarx.zone',
            ],
            'file_paths': {
                'macos': ['/Library/Caches/com.apple.act.mond'],
                'windows': ['%PROGRAMDATA%\\wt.exe'],
                'linux': ['/tmp/ld.py']
            },
            'attack_groups': {
                'TeamPCP': {
                    'aliases': ['PCPcat', 'Persy_PCP', 'ShellForce', 'DeadCatx3'],
                    'targets': ['npm', 'pypi', 'docker', 'github_actions'],
                    'tactics': ['credential_theft', 'supply_chain', 'c2_beaconing']
                }
            }
        }
    
    def check_package(self, name: str, version: str, registry: str = 'npm') -> Optional[Dict]:
        """Check if a package is known malicious"""
        registry_packages = self.known_iocs.get('packages', {}).get(registry, {})
        
        if name in registry_packages:
            pkg_info = registry_packages[name]
            affected_versions = pkg_info.get('versions', [])
            
            if '*' in affected_versions or version in affected_versions:
                return {
                    'malicious': True,
                    'package': name,
                    'version': version,
                    'registry': registry,
                    'details': pkg_info
                }
        
        return None
    
    def get_blocklist(self) -> Dict:
        """Generate blocklist for network/firewall"""
        return {
            'domains': self.known_iocs.get('c2_domains', []),
            'generated_at': datetime.now().isoformat(),
            'format': 'txt'
        }
    
    def export_blocklist(self, format: str = 'txt') -> str:
        """Export blocklist in various formats"""
        blocklist = self.get_blocklist()
        domains = blocklist['domains']
        
        if format == 'txt':
            return '\n'.join(domains)
        
        elif format == 'json':
            return json.dumps(blocklist, indent=2)
        
        elif format == 'hosts':
            lines = ['# SecOpsAI Blocklist']
            for domain in domains:
                lines.append(f'0.0.0.0 {domain}')
                lines.append(f':: {domain}')
            return '\n'.join(lines)
        
        elif format == 'dnsmasq':
            lines = ['# SecOpsAI Blocklist']
            for domain in domains:
                lines.append(f'address=/{domain}/0.0.0.0')
            return '\n'.join(lines)
        
        elif format == 'unbound':
            lines = ['server:']
            for domain in domains:
                lines.append(f'    local-zone: "{domain}" always_nxdomain')
            return '\n'.join(lines)
        
        elif format == 'iptables':
            lines = ['#!/bin/bash', '# SecOpsAI C2 Blocklist']
            for domain in domains:
                lines.append(f'# Block {domain}')
                lines.append(f'iptables -A OUTPUT -d {domain} -j DROP')
                lines.append(f'ip6tables -A OUTPUT -d {domain} -j DROP')
            return '\n'.join(lines)
        
        else:
            raise ValueError(f"Unknown format: {format}")
    
    def generate_sigma_rules(self) -> List[Dict]:
        """Generate Sigma rules from threat intel"""
        rules = []
        
        # Rule for known C2 domains
        c2_domains = self.known_iocs.get('c2_domains', [])
        if c2_domains:
            rules.append({
                'title': 'SecOpsAI Known C2 Domain Communication',
                'id': 'secopsai-ti-c2-001',
                'logsource': {
                    'category': 'dns'
                },
                'detection': {
                    'selection': {
                        'query|contains': c2_domains
                    },
                    'condition': 'selection'
                },
                'level': 'critical',
                'tags': ['attack.command-and-control', 'attack.t1071']
            })
        
        # Rules for known malicious packages
        for registry, packages in self.known_iocs.get('packages', {}).items():
            for pkg_name, pkg_info in packages.items():
                versions = pkg_info.get('versions', [])
                for version in versions:
                    if version != '*':
                        rules.append({
                            'title': f'Known Malicious Package: {pkg_name}@{version}',
                            'id': f'secopsai-ti-{registry}-{pkg_name}-{version}',
                            'logsource': {
                                'category': 'process_creation'
                            },
                            'detection': {
                                'selection': {
                                    'CommandLine|contains': [
                                        f'{pkg_name}@{version}',
                                        f'{pkg_name}@{version}'
                                    ]
                                },
                                'condition': 'selection'
                            },
                            'level': 'critical'
                        })
        
        return rules
    
    def search_by_cve(self, cve: str) -> List[Dict]:
        """Search for intelligence by CVE"""
        results = []
        
        # Search in known IOCs
        for registry, packages in self.known_iocs.get('packages', {}).items():
            for pkg_name, pkg_info in packages.items():
                if cve in pkg_info.get('description', ''):
                    results.append({
                        'type': 'package',
                        'registry': registry,
                        'name': pkg_name,
                        'details': pkg_info
                    })
        
        return results
    
    def get_mitigations(self, attack_type: str) -> List[str]:
        """Get mitigation recommendations for attack type"""
        mitigations = {
            'supply_chain': [
                'Enable npm provenance attestation',
                'Use granular access tokens with IP restrictions',
                'Implement SBOM validation in CI/CD',
                'Monitor for postinstall script execution',
                'Block install-time network access'
            ],
            'compromised_credentials': [
                'Revoke all long-lived tokens',
                'Enable 2FA for all publishing accounts',
                'Implement publish signing with Sigstore',
                'Monitor for account email changes',
                'Use OIDC trusted publishing'
            ],
            'typosquat': [
                'Validate package names against allowlist',
                'Check for similar names to popular packages',
                'Review new dependencies manually',
                'Use private registry with vetting'
            ],
            'c2_beaconing': [
                'Block known C2 domains at DNS/firewall',
                'Monitor for periodic outbound connections',
                'Implement application-aware egress filtering',
                'Use behavioral analysis for process anomalies'
            ]
        }
        
        return mitigations.get(attack_type, [])


def main():
    parser = argparse.ArgumentParser(description='SecOpsAI Threat Intelligence')
    parser.add_argument('--check', '-c', help='Check package (format: name@version)')
    parser.add_argument('--registry', '-r', default='npm', choices=['npm', 'pypi'])
    parser.add_argument('--export-blocklist', '-e', help='Export blocklist to file')
    parser.add_argument('--format', '-f', default='txt', 
                       choices=['txt', 'json', 'hosts', 'dnsmasq', 'unbound', 'iptables'])
    parser.add_argument('--generate-sigma', '-s', help='Generate Sigma rules to file')
    parser.add_argument('--cve', help='Search by CVE ID')
    parser.add_argument('--mitigations', '-m', help='Get mitigations for attack type')
    parser.add_argument('--list-iocs', '-l', action='store_true', help='List all IoCs')
    
    args = parser.parse_args()
    
    ti = ThreatIntelligenceAggregator()
    
    if args.check:
        if '@' in args.check:
            name, version = args.check.split('@', 1)
        else:
            name = args.check
            version = '*'
        
        result = ti.check_package(name, version, args.registry)
        if result:
            print(f"\n🚨 MALICIOUS PACKAGE DETECTED")
            print(f"   Package: {name}@{version}")
            print(f"   Registry: {args.registry}")
            print(f"   Details: {json.dumps(result['details'], indent=2)}")
        else:
            print(f"\n✅ Package {name}@{version} not in threat intelligence database")
    
    elif args.export_blocklist:
        blocklist = ti.export_blocklist(args.format)
        with open(args.export_blocklist, 'w') as f:
            f.write(blocklist)
        print(f"✅ Blocklist exported to {args.export_blocklist} ({args.format} format)")
    
    elif args.generate_sigma:
        rules = ti.generate_sigma_rules()
        with open(args.generate_sigma, 'w') as f:
            yaml.dump_all(rules, f, default_flow_style=False)
        print(f"✅ Sigma rules exported to {args.generate_sigma}")
    
    elif args.cve:
        results = ti.search_by_cve(args.cve)
        if results:
            print(f"\n🔍 Results for {args.cve}:")
            for r in results:
                print(f"   - {r['type']}: {r['name']} ({r['registry']})")
        else:
            print(f"\nNo results for {args.cve}")
    
    elif args.mitigations:
        mits = ti.get_mitigations(args.mitigations)
        print(f"\n🛡️ Mitigations for {args.mitigations}:")
        for m in mits:
            print(f"   - {m}")
    
    elif args.list_iocs:
        print("\n📊 Known Indicators of Compromise:")
        print("\nC2 Domains:")
        for domain in ti.known_iocs.get('c2_domains', []):
            print(f"   - {domain}")
        
        print("\nMalicious Packages:")
        for registry, packages in ti.known_iocs.get('packages', {}).items():
            print(f"\n  {registry.upper()}:")
            for name, info in packages.items():
                versions = ', '.join(info.get('versions', []))
                print(f"    - {name}: {versions}")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    # Import yaml only if needed
    try:
        import yaml
    except ImportError:
        yaml = None
    
    main()
