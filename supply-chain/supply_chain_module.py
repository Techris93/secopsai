#!/usr/bin/env python3
"""
SecOpsAI Supply Chain Security Module
Integrates with SecOpsAI's detection pipeline and findings store

This module adds supply chain attack detection to SecOpsAI:
- npm package analysis
- Editor exploit detection (Vim, Emacs)
- Runtime process monitoring for supply chain attacks
- SBOM validation

Usage (via SecOpsAI CLI):
    secopsai refresh              # Includes supply chain detection
    secopsai list --severity high # Shows supply chain findings
    secopsai check-supply-chain   # Dedicated supply chain scan
"""

import argparse
import json
import sys
import os
import sqlite3
import subprocess
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict

# SecOpsAI paths
SECOPSAI_DIR = Path.home() / "secopsai"
SOC_DB_PATH = SECOPSAI_DIR / "data" / "openclaw" / "findings" / "openclaw_soc.db"
FINDINGS_DIR = SECOPSAI_DIR / "data" / "openclaw" / "findings"

# Supply chain module paths
MODULE_DIR = Path(__file__).parent
AGENTS_DIR = MODULE_DIR / "agents"
RULES_DIR = MODULE_DIR / "rules"
PLAYBOOKS_DIR = MODULE_DIR / "playbooks"


@dataclass
class SupplyChainFinding:
    """Supply chain finding compatible with SecOpsAI SOC store"""
    finding_id: str
    timestamp: str
    severity: str  # critical, high, medium, low
    category: str  # supply_chain_npm, supply_chain_editor, etc.
    title: str
    description: str
    evidence: Dict
    mitigation: str
    status: str = "open"
    disposition: str = "unreviewed"
    
    def to_secopsai_format(self) -> Dict:
        """Convert to SecOpsAI finding format"""
        return {
            "finding_id": self.finding_id,
            "timestamp": self.timestamp,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": json.dumps(self.evidence),
            "mitigation": self.mitigation,
            "status": self.status,
            "disposition": self.disposition,
            "source": "supply-chain-module"
        }


class SupplyChainDetector:
    """Supply chain attack detector for SecOpsAI integration"""
    
    CATEGORIES = {
        "npm_malicious_package": "Supply Chain: Malicious npm Package",
        "npm_suspicious_install": "Supply Chain: Suspicious npm Installation",
        "editor_exploit_vim": "Supply Chain: Vim Editor Exploit",
        "editor_exploit_emacs": "Supply Chain: Emacs Editor Exploit",
        "python_pth_backdoor": "Supply Chain: Python .pth Backdoor",
        "runtime_dropper": "Supply Chain: RAT/Dropper Detected",
        "sbom_policy_violation": "Supply Chain: SBOM Policy Violation",
    }
    
    # Known malicious from research
    KNOWN_MALICIOUS = {
        "plain-crypto-js": {
            "versions": ["4.2.1"],
            "c2": ["sfrclak.com"],
            "severity": "critical",
            "mitigation": "Remove package immediately, rotate credentials, block C2 domains"
        },
        "axios": {
            "versions": ["1.14.1", "0.30.4"],
            "severity": "critical",
            "mitigation": "Downgrade to 1.14.0 or 0.30.3, revoke npm tokens"
        },
        "litellm": {
            "versions": ["1.82.7", "1.82.8"],
            "severity": "critical",
            "mitigation": "Remove malicious versions, check for .pth files in site-packages"
        }
    }
    
    def __init__(self):
        self.findings: List[SupplyChainFinding] = []
        
    def detect_npm_packages(self, project_path: str = ".") -> List[SupplyChainFinding]:
        """Detect malicious npm packages in project"""
        findings = []
        
        # Check for lockfile
        lockfiles = ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]
        lockfile = None
        for lf in lockfiles:
            if (Path(project_path) / lf).exists():
                lockfile = Path(project_path) / lf
                break
        
        if not lockfile:
            return findings
        
        # Parse lockfile and check against known malicious
        try:
            with open(lockfile) as f:
                if lockfile.name == "package-lock.json":
                    data = json.load(f)
                    packages = data.get("packages", {})
                    
                    for pkg_path, pkg_info in packages.items():
                        if not pkg_path.startswith("node_modules/"):
                            continue
                        
                        pkg_name = pkg_path.replace("node_modules/", "").split("/")[-1]
                        version = pkg_info.get("version", "")
                        
                        # Check against known malicious
                        if pkg_name in self.KNOWN_MALICIOUS:
                            malicious_info = self.KNOWN_MALICIOUS[pkg_name]
                            if version in malicious_info["versions"] or "*" in malicious_info["versions"]:
                                finding = SupplyChainFinding(
                                    finding_id=self._generate_id(),
                                    timestamp=datetime.now().isoformat(),
                                    severity=malicious_info["severity"],
                                    category="npm_malicious_package",
                                    title=f"Known malicious package: {pkg_name}@{version}",
                                    description=f"Package {pkg_name}@{version} is a known compromised version used in supply chain attacks.",
                                    evidence={
                                        "package": pkg_name,
                                        "version": version,
                                        "lockfile": str(lockfile),
                                        "c2_domains": malicious_info.get("c2", [])
                                    },
                                    mitigation=malicious_info["mitigation"]
                                )
                                findings.append(finding)
        
        except Exception as e:
            print(f"Error analyzing lockfile: {e}")
        
        return findings
    
    def detect_editor_configs(self) -> List[SupplyChainFinding]:
        """Detect insecure editor configurations"""
        findings = []
        
        home = Path.home()
        
        # Check Vim config
        vimrc_paths = [home / ".vimrc", home / ".vim" / "vimrc"]
        for vimrc in vimrc_paths:
            if vimrc.exists():
                content = vimrc.read_text()
                
                # Check for modelines (CVE-2019-12735, CVE-2025-53905)
                if "set modeline" in content or "modeline" not in content.lower():
                    finding = SupplyChainFinding(
                        finding_id=self._generate_id(),
                        timestamp=datetime.now().isoformat(),
                        severity="high",
                        category="editor_exploit_vim",
                        title="Vim modelines enabled (CVE-2019-12735)",
                        description="Vim modelines are enabled, allowing arbitrary code execution via crafted files.",
                        evidence={
                            "config_file": str(vimrc),
                            "cve": ["CVE-2019-12735", "CVE-2025-53905"]
                        },
                        mitigation="Add 'set nomodeline' to ~/.vimrc"
                    )
                    findings.append(finding)
                
                # Check for tar plugin
                if "g:loaded_tar" not in content:
                    finding = SupplyChainFinding(
                        finding_id=self._generate_id(),
                        timestamp=datetime.now().isoformat(),
                        severity="medium",
                        category="editor_exploit_vim",
                        title="Vim tar plugin may be enabled (CVE-2025-27423)",
                        description="Vim tar plugin can execute arbitrary commands via malicious archive filenames.",
                        evidence={
                            "config_file": str(vimrc),
                            "cve": "CVE-2025-27423"
                        },
                        mitigation="Add 'let g:loaded_tar = 1' to ~/.vimrc to disable"
                    )
                    findings.append(finding)
        
        # Check Emacs config
        emacs_paths = [home / ".emacs", home / ".emacs.d" / "init.el"]
        for emacs_config in emacs_paths:
            if emacs_config.exists():
                content = emacs_config.read_text()
                
                # Check if man URI handler is disabled
                if "browse-url-handlers" in content and "man" not in content:
                    pass  # Already handled
                else:
                    finding = SupplyChainFinding(
                        finding_id=self._generate_id(),
                        timestamp=datetime.now().isoformat(),
                        severity="medium",
                        category="editor_exploit_emacs",
                        title="Emacs man URI handler enabled (CVE-2025-1244)",
                        description="Emacs man: URI scheme allows remote command execution.",
                        evidence={
                            "config_file": str(emacs_config),
                            "cve": "CVE-2025-1244"
                        },
                        mitigation="Add (delete 'man browse-url-handlers) to config"
                    )
                    findings.append(finding)
        
        return findings
    
    def detect_suspicious_files(self) -> List[SupplyChainFinding]:
        """Detect known malicious files on system"""
        findings = []
        
        # Known RAT payload paths
        suspicious_paths = [
            Path("/Library/Caches/com.apple.act.mond"),  # macOS
            Path.home() / "Library" / "Caches" / "com.apple.act.mond",
            Path("/tmp/ld.py"),  # Linux
            Path.home() / ".local" / "share" / "ld.py",
        ]
        
        for path in suspicious_paths:
            if path.exists():
                finding = SupplyChainFinding(
                    finding_id=self._generate_id(),
                    timestamp=datetime.now().isoformat(),
                    severity="critical",
                    category="runtime_dropper",
                    title=f"Known supply chain RAT payload detected: {path.name}",
                    description=f"File matches known payload from Axios/LiteLLM supply chain attacks.",
                    evidence={
                        "path": str(path),
                        "file_type": "RAT payload",
                        "related_attacks": ["Axios npm", "LiteLLM PyPI"]
                    },
                    mitigation="Isolate system, capture forensic image, remove file, rotate all credentials"
                )
                findings.append(finding)
        
        # Check for Python .pth files
        try:
            import site
            site_packages = site.getsitepackages()
            for sp in site_packages:
                sp_path = Path(sp)
                if sp_path.exists():
                    for pth_file in sp_path.glob("*.pth"):
                        content = pth_file.read_text()
                        if "import" in content and ("exec" in content or "eval" in content):
                            finding = SupplyChainFinding(
                                finding_id=self._generate_id(),
                                timestamp=datetime.now().isoformat(),
                                severity="critical",
                                category="python_pth_backdoor",
                                title=f"Malicious Python .pth file: {pth_file.name}",
                                description=".pth file contains executable code that runs on every Python startup.",
                                evidence={
                                    "path": str(pth_file),
                                    "content_preview": content[:200]
                                },
                                mitigation="Remove .pth file immediately, audit Python installations"
                            )
                            findings.append(finding)
        except Exception as e:
            print(f"Error checking site-packages: {e}")
        
        return findings
    
    def _generate_id(self) -> str:
        """Generate SecOpsAI-compatible finding ID"""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        hash_suffix = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:6]
        return f"SCF-{timestamp}-{hash_suffix}"  # Supply Chain Finding
    
    def run_full_detection(self, project_path: str = ".") -> List[SupplyChainFinding]:
        """Run all supply chain detection checks"""
        print("🔍 Running supply chain security detection...")
        
        self.findings = []
        
        print("  Checking npm packages...")
        self.findings.extend(self.detect_npm_packages(project_path))
        
        print("  Checking editor configurations...")
        self.findings.extend(self.detect_editor_configs())
        
        print("  Checking for suspicious files...")
        self.findings.extend(self.detect_suspicious_files())
        
        return self.findings
    
    def persist_to_soc(self, findings: List[SupplyChainFinding]):
        """Persist findings to SecOpsAI SOC store"""
        if not SOC_DB_PATH.exists():
            print(f"⚠️ SecOpsAI SOC store not found at {SOC_DB_PATH}")
            print("  Findings will be saved to JSON only")
            return
        
        try:
            conn = sqlite3.connect(SOC_DB_PATH)
            cursor = conn.cursor()
            
            # Check if findings table exists
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    timestamp TEXT,
                    severity TEXT,
                    category TEXT,
                    title TEXT,
                    description TEXT,
                    evidence TEXT,
                    mitigation TEXT,
                    status TEXT,
                    disposition TEXT,
                    source TEXT
                )
            """)
            
            for finding in findings:
                data = finding.to_secopsai_format()
                cursor.execute("""
                    INSERT OR REPLACE INTO findings 
                    (finding_id, timestamp, severity, category, title, description, 
                     evidence, mitigation, status, disposition, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    data["finding_id"], data["timestamp"], data["severity"],
                    data["category"], data["title"], data["description"],
                    data["evidence"], data["mitigation"], data["status"],
                    data["disposition"], data["source"]
                ))
            
            conn.commit()
            conn.close()
            print(f"💾 {len(findings)} findings persisted to SecOpsAI SOC store")
            
        except Exception as e:
            print(f"⚠️ Error persisting to SOC store: {e}")
    
    def export_findings_json(self, findings: List[SupplyChainFinding], output_path: str):
        """Export findings to JSON file"""
        data = {
            "timestamp": datetime.now().isoformat(),
            "module": "supply-chain",
            "findings_count": len(findings),
            "findings": [asdict(f) for f in findings]
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"💾 Findings exported to {output_path}")


def check_supply_chain(args):
    """Main entry point for supply chain checks"""
    detector = SupplyChainDetector()
    
    # Run detection
    findings = detector.run_full_detection(args.project_path)
    
    # Display findings
    if findings:
        print(f"\n🚨 {len(findings)} SUPPLY CHAIN FINDINGS DETECTED:\n")
        for f in findings:
            emoji = "🚨" if f.severity == "critical" else "⚠️" if f.severity == "high" else "ℹ️"
            print(f"{emoji} [{f.severity.upper()}] {f.finding_id}")
            print(f"    Title: {f.title}")
            print(f"    Category: {f.category}")
            print(f"    Mitigation: {f.mitigation}")
            print()
    else:
        print("\n✅ No supply chain threats detected")
    
    # Persist to SecOpsAI SOC store
    detector.persist_to_soc(findings)
    
    # Export to JSON
    if args.output:
        detector.export_findings_json(findings, args.output)
    
    # Exit with error if critical findings
    critical_count = sum(1 for f in findings if f.severity == "critical")
    if critical_count > 0 and args.fail_on_critical:
        return 1
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="SecOpsAI Supply Chain Security Module",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This module integrates supply chain attack detection into SecOpsAI.

When used with SecOpsAI:
    secopsai refresh              # Runs supply chain detection automatically
    secopsai list --severity high # Shows supply chain findings
    secopsai show SCF-XXXX        # View specific finding

Standalone usage:
    python3 supply_chain_module.py check --project-path . --output findings.json
"""
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Check command
    check_parser = subparsers.add_parser("check", help="Run supply chain detection")
    check_parser.add_argument("--project-path", "-p", default=".", help="Project path to analyze")
    check_parser.add_argument("--output", "-o", help="Output JSON file")
    check_parser.add_argument("--fail-on-critical", action="store_true", help="Exit with error on critical findings")
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Check module status")
    
    args = parser.parse_args()
    
    if args.command == "check":
        return check_supply_chain(args)
    
    elif args.command == "status":
        print("📊 SecOpsAI Supply Chain Module Status")
        print(f"   Module directory: {MODULE_DIR}")
        print(f"   Agents: {AGENTS_DIR.exists()}")
        print(f"   Rules: {RULES_DIR.exists()}")
        print(f"   Playbooks: {PLAYBOOKS_DIR.exists()}")
        print(f"   SecOpsAI SOC DB: {SOC_DB_PATH.exists()}")
        return 0
    
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
