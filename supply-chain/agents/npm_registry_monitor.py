#!/usr/bin/env python3
"""
SecOpsAI - npm Registry Monitor
Monitors npm registry for suspicious package publications

Usage:
    python npm_registry_monitor.py --package axios --watch
    python npm_registry_monitor.py --org @mycompany --audit
    python npm_registry_monitor.py --check litellm==1.82.7
"""

import argparse
import json
import sys
import time
import hashlib
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('npm-monitor')

NPM_REGISTRY = "https://registry.npmjs.org"
NPM_AUDIT = "https://registry.npmjs.org/-/npm/v1/security/audits"

# Known compromised packages from research
KNOWN_MALICIOUS = {
    'plain-crypto-js': ['4.2.1'],
    'sync-axios': ['*'],
    'axios': ['1.14.1', '0.30.4'],  # Compromised versions
    'litellm': ['1.82.7', '1.82.8'],
}

SUSPICIOUS_PATTERNS = [
    'postinstall',
    'preinstall',
    'install',
]

@dataclass
class PackageInfo:
    name: str
    version: str
    published: datetime
    maintainers: List[str]
    dist: Dict
    scripts: Dict[str, str]
    dependencies: Dict[str, str]
    dev_dependencies: Dict[str, str]
    repository: Optional[str]
    homepage: Optional[str]
    license: Optional[str]
    
    @property
    def has_install_script(self) -> bool:
        """Check if package has install-time scripts"""
        for pattern in SUSPICIOUS_PATTERNS:
            if pattern in self.scripts:
                return True
        return False
    
    @property
    def is_known_malicious(self) -> bool:
        """Check if package/version is known malicious"""
        if self.name in KNOWN_MALICIOUS:
            if '*' in KNOWN_MALICIOUS[self.name]:
                return True
            if self.version in KNOWN_MALICIOUS[self.name]:
                return True
        return False
    
    def to_dict(self) -> Dict:
        return asdict(self)


class NPMRegistryMonitor:
    def __init__(self, cache_dir: str = ".npm_monitor_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecOpsAI-npm-monitor/1.0'
        })
        
    def get_package_info(self, package_name: str) -> Optional[Dict]:
        """Fetch package metadata from npm registry"""
        cache_file = self.cache_dir / f"{package_name.replace('/', '_')}.json"
        
        # Check cache first (5 min TTL)
        if cache_file.exists():
            mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
            if datetime.now() - mtime < timedelta(minutes=5):
                with open(cache_file) as f:
                    return json.load(f)
        
        try:
            url = f"{NPM_REGISTRY}/{package_name}"
            resp = self.session.get(url, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            
            # Cache response
            with open(cache_file, 'w') as f:
                json.dump(data, f)
            
            return data
        except requests.RequestException as e:
            logger.error(f"Failed to fetch {package_name}: {e}")
            return None
    
    def get_version_info(self, package_name: str, version: str) -> Optional[PackageInfo]:
        """Get specific version information"""
        pkg_data = self.get_package_info(package_name)
        if not pkg_data or version not in pkg_data.get('versions', {}):
            return None
        
        v_data = pkg_data['versions'][version]
        time_data = pkg_data.get('time', {})
        
        published_str = time_data.get(version, '')
        try:
            published = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
        except:
            published = datetime.now()
        
        return PackageInfo(
            name=package_name,
            version=version,
            published=published,
            maintainers=[m.get('name', '') for m in v_data.get('maintainers', [])],
            dist=v_data.get('dist', {}),
            scripts=v_data.get('scripts', {}),
            dependencies=v_data.get('dependencies', {}),
            dev_dependencies=v_data.get('devDependencies', {}),
            repository=v_data.get('repository', {}).get('url'),
            homepage=v_data.get('homepage'),
            license=v_data.get('license')
        )
    
    def check_typosquat(self, package_name: str) -> List[str]:
        """Check if package name is a typosquat of popular packages"""
        popular_packages = {
            'axios': ['axois', 'axio', 'axiosp', 'sync-axios'],
            'lodash': ['loadsh', 'lodahs', 'lodas'],
            'express': ['expres', 'expresss', 'node-express'],
            'react': ['reac', 'reacjs', 'react-js'],
            'vue': ['vuejs', 'vue.js'],
            'angular': ['angualr', 'angularjs'],
        }
        
        typosquats = []
        pkg_base = package_name.split('/')[-1]  # Remove scope
        
        for popular, typos in popular_packages.items():
            if pkg_base in typos:
                typosquats.append(popular)
            # Check edit distance for close matches
            if self._levenshtein_distance(pkg_base, popular) <= 2:
                if pkg_base != popular:
                    typosquats.append(f"{popular} (similar)")
        
        return typosquats
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
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
    
    def analyze_package(self, package_name: str, version: Optional[str] = None) -> Dict:
        """Comprehensive package analysis"""
        pkg_data = self.get_package_info(package_name)
        if not pkg_data:
            return {'error': 'Package not found'}
        
        versions = pkg_data.get('versions', {})
        time_data = pkg_data.get('time', {})
        
        # Get versions to analyze
        if version:
            versions_to_check = {version: versions.get(version, {})} if version in versions else {}
        else:
            # Check last 5 versions
            sorted_versions = sorted(
                time_data.keys(),
                key=lambda x: time_data.get(x, ''),
                reverse=True
            )
            versions_to_check = {v: versions.get(v, {}) for v in sorted_versions[:5] if v in versions}
        
        results = {
            'package': package_name,
            'analysis_timestamp': datetime.now().isoformat(),
            'total_versions': len(versions),
            'risk_score': 0,
            'alerts': [],
            'versions': []
        }
        
        for ver, ver_data in versions_to_check.items():
            ver_info = self.get_version_info(package_name, ver)
            if not ver_info:
                continue
            
            ver_analysis = {
                'version': ver,
                'published': ver_info.published.isoformat(),
                'maintainers': ver_info.maintainers,
                'has_install_script': ver_info.has_install_script,
                'is_known_malicious': ver_info.is_known_malicious,
                'dependencies': list(ver_info.dependencies.keys()),
                'alerts': []
            }
            
            # Check for known malicious
            if ver_info.is_known_malicious:
                ver_analysis['alerts'].append({
                    'severity': 'CRITICAL',
                    'type': 'KNOWN_MALICIOUS',
                    'message': f'{package_name}@{ver} is a known compromised version'
                })
                results['risk_score'] += 100
            
            # Check for install scripts
            if ver_info.has_install_script:
                ver_analysis['alerts'].append({
                    'severity': 'HIGH',
                    'type': 'INSTALL_SCRIPT',
                    'message': 'Package contains install-time scripts'
                })
                results['risk_score'] += 30
            
            # Check for typosquats
            typosquats = self.check_typosquat(package_name)
            if typosquats:
                ver_analysis['alerts'].append({
                    'severity': 'MEDIUM',
                    'type': 'TYPOSQUAT_CANDIDATE',
                    'message': f'Package name similar to: {", ".join(typosquats)}'
                })
                results['risk_score'] += 20
            
            # Check for new maintainers (if we have history)
            if len(ver_info.maintainers) == 1:
                ver_analysis['alerts'].append({
                    'severity': 'LOW',
                    'type': 'SINGLE_MAINTAINER',
                    'message': 'Package has only one maintainer'
                })
                results['risk_score'] += 10
            
            results['versions'].append(ver_analysis)
            results['alerts'].extend(ver_analysis['alerts'])
        
        return results
    
    def watch_package(self, package_name: str, interval: int = 300):
        """Continuously watch a package for changes"""
        logger.info(f"Starting watch on {package_name} (interval: {interval}s)")
        
        last_versions = set()
        
        while True:
            try:
                pkg_data = self.get_package_info(package_name)
                if pkg_data:
                    current_versions = set(pkg_data.get('versions', {}).keys())
                    
                    # Detect new versions
                    new_versions = current_versions - last_versions
                    if new_versions:
                        for ver in new_versions:
                            logger.warning(f"🚨 NEW VERSION DETECTED: {package_name}@{ver}")
                            analysis = self.analyze_package(package_name, ver)
                            self._print_analysis(analysis)
                    
                    last_versions = current_versions
                
                time.sleep(interval)
                
            except KeyboardInterrupt:
                logger.info("Stopping watch...")
                break
            except Exception as e:
                logger.error(f"Watch error: {e}")
                time.sleep(interval)
    
    def _print_analysis(self, analysis: Dict):
        """Pretty print analysis results"""
        print("\n" + "="*60)
        print(f"📦 Package Analysis: {analysis.get('package')}")
        print("="*60)
        
        risk = analysis.get('risk_score', 0)
        risk_level = "🟢 LOW" if risk < 30 else "🟡 MEDIUM" if risk < 60 else "🔴 HIGH" if risk < 100 else "🚨 CRITICAL"
        print(f"Risk Score: {risk} ({risk_level})")
        
        for alert in analysis.get('alerts', []):
            emoji = "🚨" if alert['severity'] == 'CRITICAL' else "⚠️" if alert['severity'] == 'HIGH' else "ℹ️"
            print(f"{emoji} [{alert['severity']}] {alert['type']}: {alert['message']}")
        
        for ver in analysis.get('versions', []):
            print(f"\n  📋 Version: {ver['version']}")
            print(f"     Published: {ver['published']}")
            print(f"     Install Script: {'⚠️ YES' if ver['has_install_script'] else '✓ No'}")
            print(f"     Dependencies: {len(ver['dependencies'])}")


def main():
    parser = argparse.ArgumentParser(description='SecOpsAI npm Registry Monitor')
    parser.add_argument('--package', '-p', help='Package name to analyze')
    parser.add_argument('--version', '-v', help='Specific version to check')
    parser.add_argument('--watch', '-w', action='store_true', help='Watch for changes')
    parser.add_argument('--audit', '-a', action='store_true', help='Audit mode - check all versions')
    parser.add_argument('--check-lockfile', '-l', help='Check package-lock.json file')
    parser.add_argument('--output', '-o', help='Output file for JSON results')
    
    args = parser.parse_args()
    
    monitor = NPMRegistryMonitor()
    
    if args.watch and args.package:
        monitor.watch_package(args.package)
    
    elif args.package:
        analysis = monitor.analyze_package(args.package, args.version)
        monitor._print_analysis(analysis)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(analysis, f, indent=2)
            print(f"\n💾 Results saved to {args.output}")
    
    elif args.check_lockfile:
        # Analyze lockfile
        with open(args.check_lockfile) as f:
            lockfile = json.load(f)
        
        packages = lockfile.get('packages', {})
        print(f"📋 Analyzing {len(packages)} packages from lockfile...")
        
        all_results = []
        for pkg_path, pkg_info in packages.items():
            if pkg_path.startswith('node_modules/'):
                pkg_name = pkg_path.replace('node_modules/', '').split('node_modules/')[-1]
                version = pkg_info.get('version')
                if version:
                    analysis = monitor.analyze_package(pkg_name, version)
                    if analysis.get('risk_score', 0) > 0:
                        all_results.append(analysis)
                        monitor._print_analysis(analysis)
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(all_results, f, indent=2)
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
