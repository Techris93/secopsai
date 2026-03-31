#!/usr/bin/env python3
"""
SecOpsAI - SBOM Validator
Validates Software Bill of Materials against security policies

Usage:
    python sbom_validator.py --sbom sbom.json --policy strict
    python sbom_validator.py --generate ./project --output sbom.json
    python sbom_validator.py --watch ./package.json
"""

import argparse
import json
import sys
import subprocess
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('sbom-validator')

@dataclass
class ValidationResult:
    package: str
    version: str
    passed: bool
    score: int
    findings: List[Dict]
    
    def to_dict(self):
        return asdict(self)


class SecurityPolicy:
    """Defines security policies for package validation"""
    
    POLICIES = {
        'strict': {
            'min_downloads': 10000,
            'max_age_days': 365,
            'allow_postinstall': False,
            'require_provenance': True,
            'max_maintainers': 5,
            'block_unscoped': False,
        },
        'moderate': {
            'min_downloads': 1000,
            'max_age_days': 180,
            'allow_postinstall': True,
            'require_provenance': False,
            'max_maintainers': 10,
            'block_unscoped': False,
        },
        'permissive': {
            'min_downloads': 100,
            'max_age_days': 90,
            'allow_postinstall': True,
            'require_provenance': False,
            'max_maintainers': 20,
            'block_unscoped': False,
        }
    }
    
    def __init__(self, policy_name: str = 'moderate'):
        self.config = self.POLICIES.get(policy_name, self.POLICIES['moderate'])
        self.known_bad_packages = self._load_known_bad()
    
    def _load_known_bad(self) -> Dict:
        """Load known malicious packages"""
        return {
            'plain-crypto-js': {'versions': ['4.2.1'], 'reason': 'Axios supply chain attack'},
            'sync-axios': {'versions': ['*'], 'reason': 'Malicious typosquat'},
            'axios': {'versions': ['1.14.1', '0.30.4'], 'reason': 'Compromised npm credentials'},
            'litellm': {'versions': ['1.82.7', '1.82.8'], 'reason': 'PyPI supply chain attack'},
        }
    
    def validate(self, package: Dict) -> ValidationResult:
        """Validate a single package against policy"""
        findings = []
        score = 100
        
        name = package.get('name', '')
        version = package.get('version', '')
        
        # Check known malicious
        if name in self.known_bad_packages:
            bad_info = self.known_bad_packages[name]
            if '*' in bad_info['versions'] or version in bad_info['versions']:
                findings.append({
                    'severity': 'CRITICAL',
                    'rule': 'KNOWN_MALICIOUS',
                    'message': f"Known malicious package: {bad_info['reason']}"
                })
                score = 0
        
        # Check postinstall scripts
        scripts = package.get('scripts', {})
        has_postinstall = any(
            k in scripts for k in ['postinstall', 'preinstall', 'install']
        )
        
        if has_postinstall and not self.config['allow_postinstall']:
            findings.append({
                'severity': 'HIGH',
                'rule': 'POSTINSTALL_SCRIPT_BLOCKED',
                'message': 'Package has install-time scripts (blocked by policy)'
            })
            score -= 30
        
        # Check download count (if available)
        downloads = package.get('weeklyDownloads', 0)
        if downloads < self.config['min_downloads']:
            findings.append({
                'severity': 'MEDIUM',
                'rule': 'LOW_DOWNLOAD_COUNT',
                'message': f'Package has only {downloads} weekly downloads (min: {self.config["min_downloads"]})'
            })
            score -= 15
        
        # Check package age
        published = package.get('published')
        if published:
            try:
                pub_date = datetime.fromisoformat(published.replace('Z', '+00:00'))
                age_days = (datetime.now() - pub_date).days
                if age_days < 7:
                    findings.append({
                        'severity': 'HIGH',
                        'rule': 'VERY_NEW_PACKAGE',
                        'message': f'Package published only {age_days} days ago'
                    })
                    score -= 25
            except:
                pass
        
        # Check provenance
        if self.config['require_provenance'] and not package.get('provenance'):
            findings.append({
                'severity': 'MEDIUM',
                'rule': 'MISSING_PROVENANCE',
                'message': 'Package lacks npm provenance attestation'
            })
            score -= 10
        
        # Check maintainer count
        maintainers = package.get('maintainers', [])
        if len(maintainers) > self.config['max_maintainers']:
            findings.append({
                'severity': 'LOW',
                'rule': 'TOO_MANY_MAINTAINERS',
                'message': f'Package has {len(maintainers)} maintainers'
            })
            score -= 5
        
        # Typosquat check
        popular_packages = ['axios', 'lodash', 'express', 'react', 'vue']
        pkg_base = name.split('/')[-1]
        for popular in popular_packages:
            if self._is_typosquat(pkg_base, popular):
                findings.append({
                    'severity': 'HIGH',
                    'rule': 'TYPOSQUAT_CANDIDATE',
                    'message': f'Package name similar to popular package: {popular}'
                })
                score -= 20
                break
        
        passed = score >= 70 and not any(f['severity'] == 'CRITICAL' for f in findings)
        
        return ValidationResult(
            package=name,
            version=version,
            passed=passed,
            score=max(0, score),
            findings=findings
        )
    
    def _is_typosquat(self, s1: str, s2: str) -> bool:
        """Check if string is a typosquat candidate"""
        if s1 == s2:
            return False
        # Simple edit distance check
        return self._levenshtein(s1, s2) <= 2
    
    def _levenshtein(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]


class SBOMGenerator:
    """Generate SBOM from various sources"""
    
    def generate_from_npm(self, project_path: str) -> Dict:
        """Generate SBOM from npm project"""
        package_json = Path(project_path) / 'package.json'
        if not package_json.exists():
            raise FileNotFoundError(f"No package.json found in {project_path}")
        
        with open(package_json) as f:
            pkg = json.load(f)
        
        sbom = {
            'bomFormat': 'SecOpsAI-SBOM',
            'specVersion': '1.0',
            'timestamp': datetime.now().isoformat(),
            'components': []
        }
        
        # Get installed packages
        result = subprocess.run(
            ['npm', 'list', '--json', '--all'],
            cwd=project_path,
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            npm_list = json.loads(result.stdout)
            components = self._parse_npm_deps(npm_list.get('dependencies', {}))
            sbom['components'] = components
        
        return sbom
    
    def _parse_npm_deps(self, deps: Dict, path: str = '') -> List[Dict]:
        """Recursively parse npm dependencies"""
        components = []
        
        for name, info in deps.items():
            if name == '':
                continue
            
            component = {
                'type': 'library',
                'name': name,
                'version': info.get('version', 'unknown'),
                'purl': f'pkg:npm/{name}@{info.get("version", "unknown")}',
                'scope': info.get('extraneous', False) and 'optional' or 'required'
            }
            
            # Add resolved URL if available
            if 'resolved' in info:
                component['downloadUrl'] = info['resolved']
            
            # Add integrity hash
            if 'integrity' in info:
                component['hashes'] = [{'alg': 'SHA-512', 'content': info['integrity']}]
            
            components.append(component)
            
            # Recurse into nested deps
            if 'dependencies' in info:
                components.extend(self._parse_npm_deps(info['dependencies'], f"{path}/{name}"))
        
        return components
    
    def generate_from_requirements(self, project_path: str) -> Dict:
        """Generate SBOM from Python requirements.txt"""
        req_file = Path(project_path) / 'requirements.txt'
        if not req_file.exists():
            raise FileNotFoundError(f"No requirements.txt found in {project_path}")
        
        sbom = {
            'bomFormat': 'SecOpsAI-SBOM',
            'specVersion': '1.0',
            'timestamp': datetime.now().isoformat(),
            'components': []
        }
        
        with open(req_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Parse package==version format
                    if '==' in line:
                        name, version = line.split('==', 1)
                        component = {
                            'type': 'library',
                            'name': name.strip(),
                            'version': version.strip(),
                            'purl': f'pkg:pypi/{name.strip()}@{version.strip()}'
                        }
                        sbom['components'].append(component)
        
        return sbom


class SBOMValidator:
    """Main SBOM validation engine"""
    
    def __init__(self, policy_name: str = 'moderate'):
        self.policy = SecurityPolicy(policy_name)
        self.generator = SBOMGenerator()
    
    def validate_sbom(self, sbom: Dict) -> Dict:
        """Validate entire SBOM"""
        results = {
            'timestamp': datetime.now().isoformat(),
            'policy': self.policy.config,
            'summary': {
                'total': 0,
                'passed': 0,
                'failed': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            },
            'validations': []
        }
        
        components = sbom.get('components', [])
        results['summary']['total'] = len(components)
        
        for component in components:
            validation = self.policy.validate(component)
            results['validations'].append(validation.to_dict())
            
            if validation.passed:
                results['summary']['passed'] += 1
            else:
                results['summary']['failed'] += 1
            
            for finding in validation.findings:
                sev = finding['severity'].lower()
                if sev in results['summary']:
                    results['summary'][sev] += 1
        
        return results
    
    def generate_and_validate(self, project_path: str, package_manager: str = 'npm') -> Dict:
        """Generate SBOM and validate it"""
        if package_manager == 'npm':
            sbom = self.generator.generate_from_npm(project_path)
        elif package_manager == 'pip':
            sbom = self.generator.generate_from_requirements(project_path)
        else:
            raise ValueError(f"Unsupported package manager: {package_manager}")
        
        validation = self.validate_sbom(sbom)
        validation['sbom'] = sbom
        
        return validation


def print_report(results: Dict):
    """Print formatted validation report"""
    summary = results['summary']
    
    print("\n" + "="*70)
    print("📋 SECOpsAI SBOM VALIDATION REPORT")
    print("="*70)
    print(f"Timestamp: {results['timestamp']}")
    print(f"Policy: {results.get('policy', {})}")
    print("\n📊 SUMMARY:")
    print(f"  Total Packages: {summary['total']}")
    print(f"  ✅ Passed: {summary['passed']}")
    print(f"  ❌ Failed: {summary['failed']}")
    print(f"  🚨 Critical: {summary['critical']}")
    print(f"  ⚠️  High: {summary['high']}")
    print(f"  ℹ️  Medium: {summary['medium']}")
    print(f"  💡 Low: {summary['low']}")
    
    print("\n🔍 DETAILED FINDINGS:")
    for validation in results['validations']:
        if not validation['passed'] or validation['findings']:
            status = "✅" if validation['passed'] else "❌"
            print(f"\n  {status} {validation['package']}@{validation['version']} (Score: {validation['score']})")
            for finding in validation['findings']:
                emoji = "🚨" if finding['severity'] == 'CRITICAL' else "⚠️" if finding['severity'] == 'HIGH' else "ℹ️"
                print(f"     {emoji} [{finding['severity']}] {finding['message']}")


def main():
    parser = argparse.ArgumentParser(description='SecOpsAI SBOM Validator')
    parser.add_argument('--sbom', '-s', help='SBOM file to validate')
    parser.add_argument('--generate', '-g', help='Generate SBOM from project path')
    parser.add_argument('--package-manager', '-pm', default='npm', choices=['npm', 'pip'])
    parser.add_argument('--policy', '-p', default='moderate', choices=['strict', 'moderate', 'permissive'])
    parser.add_argument('--output', '-o', help='Output file for results')
    parser.add_argument('--fail-on-critical', action='store_true', help='Exit with error on critical findings')
    
    args = parser.parse_args()
    
    validator = SBOMValidator(args.policy)
    
    if args.sbom:
        # Validate existing SBOM
        with open(args.sbom) as f:
            sbom = json.load(f)
        results = validator.validate_sbom(sbom)
        print_report(results)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
        
        if args.fail_on_critical and results['summary']['critical'] > 0:
            sys.exit(1)
    
    elif args.generate:
        # Generate and validate
        results = validator.generate_and_validate(args.generate, args.package_manager)
        print_report(results)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
        
        if args.fail_on_critical and results['summary']['critical'] > 0:
            sys.exit(1)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
