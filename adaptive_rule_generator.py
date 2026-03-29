#!/usr/bin/env python3
"""
SecOpsAI Adaptive Rule Generator
Converts threat intelligence into detection rules.
Uses LLM to generate Python detection code from attack patterns.
"""

import os
import json
import re
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

THREAT_INTEL_DIR = os.path.expanduser("~/.openclaw/workspace/secopsai/threat_intel")
RULES_OUTPUT_DIR = os.path.expanduser("~/.openclaw/workspace/secopsai/auto_rules")

os.makedirs(RULES_OUTPUT_DIR, exist_ok=True)


@dataclass
class GeneratedRule:
    """A generated detection rule"""
    rule_id: str
    name: str
    description: str
    source_intel: str  # Which threat intel generated this
    mitre_techniques: List[str]
    severity: str
    python_code: str
    test_cases: List[Dict[str, Any]]
    validation_score: float = 0.0  # F1 score from evaluate.py


class AdaptiveRuleGenerator:
    """Generates detection rules from threat intelligence"""
    
    def __init__(self):
        self.rules: List[GeneratedRule] = []
        self.next_rule_id = self._get_next_rule_id()
    
    def _get_next_rule_id(self) -> int:
        """Find the next available rule ID"""
        existing_rules = []
        if os.path.exists(RULES_OUTPUT_DIR):
            for f in os.listdir(RULES_OUTPUT_DIR):
                if f.startswith('auto_rule_') and f.endswith('.py'):
                    match = re.search(r'AUTO-(\d+)', f)
                    if match:
                        existing_rules.append(int(match.group(1)))
        
        return max(existing_rules, default=0) + 1
    
    def load_threat_intel(self, filepath: Optional[str] = None) -> List[Dict[str, Any]]:
        """Load threat intelligence from JSON file"""
        if filepath is None:
            filepath = os.path.join(THREAT_INTEL_DIR, 'latest_indicators.json')
        
        if not os.path.exists(filepath):
            print(f"[ERROR] No threat intel file found at {filepath}")
            return []
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        return data.get('indicators', [])
    
    def generate_rule_from_cve(self, indicator: Dict[str, Any]) -> Optional[GeneratedRule]:
        """Generate detection rule from CVE description"""
        desc = indicator.get('description', '').lower()
        cve_id = indicator.get('title', 'UNKNOWN')
        
        # Skip if not actionable
        if len(desc) < 50:
            return None
        
        # Determine rule type based on CVE content
        if any(kw in desc for kw in ['sql injection', 'sqli', 'sql command']):
            return self._generate_sqli_rule(indicator)
        
        elif any(kw in desc for kw in ['remote code execution', 'rce', 'arbitrary code']):
            return self._generate_rce_rule(indicator)
        
        elif any(kw in desc for kw in ['authentication bypass', 'auth bypass', 'login bypass']):
            return self._generate_auth_bypass_rule(indicator)
        
        elif any(kw in desc for kw in ['path traversal', 'directory traversal', '../']):
            return self._generate_path_traversal_rule(indicator)
        
        elif any(kw in desc for kw in ['command injection', 'os command']):
            return self._generate_command_injection_rule(indicator)
        
        elif any(kw in desc for kw in ['xss', 'cross-site scripting', 'javascript injection']):
            return self._generate_xss_rule(indicator)
        
        elif any(kw in desc for kw in ['buffer overflow', 'memory corruption']):
            return self._generate_memory_corruption_rule(indicator)
        
        elif any(kw in desc for kw in ['privilege escalation', 'elevation of privilege']):
            return self._generate_privesc_rule(indicator)
        
        else:
            # Generic anomaly detection
            return self._generate_generic_anomaly_rule(indicator)
    
    def generate_rule_from_iocs(self, indicator: Dict[str, Any]) -> Optional[GeneratedRule]:
        """Generate IOC-based detection rules"""
        iocs = indicator.get('iocs', [])
        
        if not iocs:
            return None
        
        # Group IOCs by type
        malicious_ips = [ioc['value'] for ioc in iocs if ioc['type'] == 'ip']
        malicious_domains = [ioc['value'] for ioc in iocs if ioc['type'] == 'domain']
        malicious_hashes = [ioc['value'] for ioc in iocs if ioc['type'].startswith('hash_')]
        
        if not malicious_ips and not malicious_domains and not malicious_hashes:
            return None
        
        rule_id = f"AUTO-{self.next_rule_id:03d}"
        self.next_rule_id += 1
        
        # Build Python code
        python_code = f'''def detect_{rule_id.lower().replace("-", "_")}(events):
    """
    Threat Intel: {indicator.get('source', 'Unknown')}
    Description: {indicator.get('description', '')[:100]}...
    Generated: {datetime.utcnow().isoformat()}
    """
    malicious_ips = {malicious_ips}
    malicious_domains = {malicious_domains}
    malicious_hashes = {malicious_hashes}
    
    detected = []
    for event in events:
        # Check IP-based indicators
        dest_ip = event.get("dest_ip") or event.get("dst_ip") or ""
        src_ip = event.get("src_ip") or event.get("source_ip") or ""
        
        if dest_ip in malicious_ips or src_ip in malicious_ips:
            detected.append(event["event_id"])
            continue
        
        # Check domain indicators
        domain = event.get("dns_query") or event.get("hostname") or ""
        if domain in malicious_domains:
            detected.append(event["event_id"])
            continue
        
        # Check hash indicators (in process/file events)
        file_hash = event.get("file_hash") or event.get("hash") or ""
        if file_hash in malicious_hashes:
            detected.append(event["event_id"])
            continue
        
        # Check URL patterns for domains
        url = event.get("url") or event.get("request") or ""
        for bad_domain in malicious_domains:
            if bad_domain in url:
                detected.append(event["event_id"])
                break
    
    return detected
'''
        
        return GeneratedRule(
            rule_id=rule_id,
            name=f"Threat Intel: {indicator.get('title', 'Unknown')[:50]}",
            description=f"Detects IOCs from {indicator.get('source', 'Unknown')}",
            source_intel=indicator.get('hash_id', ''),
            mitre_techniques=indicator.get('mitre_techniques', []),
            severity=indicator.get('severity', 'medium'),
            python_code=python_code,
            test_cases=[]
        )
    
    def _generate_sqli_rule(self, indicator: Dict[str, Any]) -> GeneratedRule:
        """Generate SQL injection detection rule"""
        rule_id = f"AUTO-{self.next_rule_id:03d}"
        self.next_rule_id += 1
        
        python_code = f'''def detect_{rule_id.lower().replace("-", "_")}(events):
    """
    Threat Intel: {indicator.get('source', 'Unknown')}
    Description: SQL Injection detection
    Generated: {datetime.utcnow().isoformat()}
    """
    sqli_patterns = [
        r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
        r"((\%3D)|(=))[^\\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
        r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
        r"((\%27)|(\'))union",
        r"exec(\s|\\+)+(s|x)p\\w+",
        r"UNION\\s+SELECT",
        r"INSERT\\s+INTO",
        r"DELETE\\s+FROM",
        r"DROP\\s+TABLE",
    ]
    
    import re
    detected = []
    
    for event in events:
        # Check URL and request body
        url = event.get("url") or ""
        request = event.get("request") or event.get("http_request") or ""
        body = event.get("body") or event.get("data") or ""
        
        content = f"{{url}} {{request}} {{body}}"
        
        for pattern in sqli_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(event["event_id"])
                break
    
    return detected
'''
        
        return GeneratedRule(
            rule_id=rule_id,
            name=f"SQL Injection: {indicator.get('title', 'CVE')}",
            description=f"Detects SQL injection patterns from {indicator.get('source', 'Unknown')}",
            source_intel=indicator.get('hash_id', ''),
            mitre_techniques=['T1190'] + indicator.get('mitre_techniques', []),
            severity='high',
            python_code=python_code,
            test_cases=[
                {'event_id': 'test_sqli_1', 'url': "http://example.com?id=1' OR '1'='1", 'malicious': True},
                {'event_id': 'test_sqli_2', 'url': "http://example.com?id=1; DROP TABLE users", 'malicious': True},
            ]
        )
    
    def _generate_rce_rule(self, indicator: Dict[str, Any]) -> GeneratedRule:
        """Generate RCE detection rule"""
        rule_id = f"AUTO-{self.next_rule_id:03d}"
        self.next_rule_id += 1
        
        python_code = f'''def detect_{rule_id.lower().replace("-", "_")}(events):
    """
    Threat Intel: {indicator.get('source', 'Unknown')}
    Description: Remote Code Execution detection
    Generated: {datetime.utcnow().isoformat()}
    """
    rce_patterns = [
        r"\\$\\(.*?\\)",  # Command substitution
        r"`.*?`",  # Backtick execution
        r"\\b(eval|exec|system|passthru|shell_exec)\\s*\\(",
        r";\\s*bash\\s+-c",
        r";\\s*sh\\s+-c",
        r"\\|\\s*bash",
        r"\\|\\s*python\\d*\\s+-c",
        r"\\|\\s*perl\\s+-e",
        r"\\|\\s*nc\\s+-[el]",
        r"bash\\s+-i\\s+\>&\\s+/dev/tcp/",
        r"python\\d*\\s+-c\\s+['\"]import\\s+socket",
        r"ruby\\s+-rsocket",
    ]
    
    import re
    detected = []
    
    for event in events:
        url = event.get("url") or ""
        request = event.get("request") or ""
        body = event.get("body") or event.get("data") or ""
        command = event.get("command") or event.get("cmd") or ""
        
        content = f"{{url}} {{request}} {{body}} {{command}}"
        
        for pattern in rce_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(event["event_id"])
                break
    
    return detected
'''
        
        return GeneratedRule(
            rule_id=rule_id,
            name=f"RCE Detection: {indicator.get('title', 'CVE')}",
            description=f"Detects remote code execution from {indicator.get('source', 'Unknown')}",
            source_intel=indicator.get('hash_id', ''),
            mitre_techniques=['T1059', 'T1203'] + indicator.get('mitre_techniques', []),
            severity='critical',
            python_code=python_code,
            test_cases=[]
        )
    
    def _generate_auth_bypass_rule(self, indicator: Dict[str, Any]) -> GeneratedRule:
        """Generate authentication bypass detection rule"""
        rule_id = f"AUTO-{self.next_rule_id:03d}"
        self.next_rule_id += 1
        
        python_code = f'''def detect_{rule_id.lower().replace("-", "_")}(events):
    """
    Threat Intel: {indicator.get('source', 'Unknown')}
    Description: Authentication Bypass detection
    Generated: {datetime.utcnow().isoformat()}
    """
    bypass_patterns = [
        r"admin['\"]?\\s*:\\s*['\"]?admin",
        r"['\"]or['\"]?\\s*[=1]+",
        r"['\"]\\s*or\\s*['\"]1['\"]\\s*=\\s*['\"]1",
        r"X-Forwarded-For:\\s*127\\.0\\.0\\.1",
        r"X-Real-IP:\\s*127\\.0\\.0\\.1",
        r"X-Originating-IP:\\s*127\\.0\\.0\\.1",
        r"X-Remote-IP:\\s*127\\.0\\.0\\.1",
        r"X-Remote-Addr:\\s*127\\.0\\.0\\.1",
        r"X-Client-IP:\\s*127\\.0\\.0\\.1",
        r"X-Host:\\s*127\\.0\\.0\\.1",
        r"X-Forwarded-Host:\\s*127\\.0\\.0\\.1",
    ]
    
    import re
    detected = []
    
    for event in events:
        headers = event.get("headers") or event.get("request_headers") or {}
        url = event.get("url") or ""
        body = event.get("body") or ""
        
        content = f"{{url}} {{body}} {{json.dumps(headers)}}"
        
        for pattern in bypass_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(event["event_id"])
                break
    
    return detected
'''
        
        return GeneratedRule(
            rule_id=rule_id,
            name=f"Auth Bypass: {indicator.get('title', 'CVE')}",
            description=f"Detects authentication bypass attempts from {indicator.get('source', 'Unknown')}",
            source_intel=indicator.get('hash_id', ''),
            mitre_techniques=['T1552', 'T1078'] + indicator.get('mitre_techniques', []),
            severity='critical',
            python_code=python_code,
            test_cases=[]
        )
    
    def _generate_generic_anomaly_rule(self, indicator: Dict[str, Any]) -> Optional[GeneratedRule]:
        """Generate generic anomaly detection for unclassified threats"""
        # Skip if we can't determine the attack type
        return None
    
    def _generate_path_traversal_rule(self, indicator: Dict[str, Any]) -> GeneratedRule:
        """Generate path traversal detection rule"""
        rule_id = f"AUTO-{self.next_rule_id:03d}"
        self.next_rule_id += 1
        
        python_code = f'''def detect_{rule_id.lower().replace("-", "_")}(events):
    """
    Threat Intel: {indicator.get('source', 'Unknown')}
    Description: Path Traversal detection
    Generated: {datetime.utcnow().isoformat()}
    """
    traversal_patterns = [
        r"\\.\\./",
        r"\\.\\.\\\\",
        r"%2e%2e%2f",
        r"%252e%252e%252f",
        r"..%252f",
        r"%252e%252e/",
        r"..%c0%af",
        r"%c0%ae%c0%ae/",
        r"....//",
        r"....\\\\",
    ]
    
    import re
    detected = []
    
    for event in events:
        url = event.get("url") or ""
        request = event.get("request") or ""
        filepath = event.get("filepath") or event.get("path") or ""
        
        content = f"{{url}} {{request}} {{filepath}}"
        
        for pattern in traversal_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(event["event_id"])
                break
    
    return detected
'''
        
        return GeneratedRule(
            rule_id=rule_id,
            name=f"Path Traversal: {indicator.get('title', 'CVE')}",
            description=f"Detects path traversal from {indicator.get('source', 'Unknown')}",
            source_intel=indicator.get('hash_id', ''),
            mitre_techniques=['T1083'] + indicator.get('mitre_techniques', []),
            severity='high',
            python_code=python_code,
            test_cases=[]
        )
    
    def _generate_command_injection_rule(self, indicator: Dict[str, Any]) -> GeneratedRule:
        """Generate command injection detection rule"""
        return self._generate_rce_rule(indicator)  # Similar patterns
    
    def _generate_xss_rule(self, indicator: Dict[str, Any]) -> GeneratedRule:
        """Generate XSS detection rule"""
        rule_id = f"AUTO-{self.next_rule_id:03d}"
        self.next_rule_id += 1
        
        python_code = f'''def detect_{rule_id.lower().replace("-", "_")}(events):
    """
    Threat Intel: {indicator.get('source', 'Unknown')}
    Description: XSS detection
    Generated: {datetime.utcnow().isoformat()}
    """
    xss_patterns = [
        r"<script[^>]*>[\\s\\S]*?</script>",
        r"javascript:",
        r"on\\w+\\s*=",
        r"<iframe",
        r"<object",
        r"<embed",
        r"expression\\s*\\(",
        r"alert\\s*\\(",
        r"confirm\\s*\\(",
        r"prompt\\s*\\(",
        r"document\\.cookie",
        r"document\\.location",
        r"window\\.location",
    ]
    
    import re
    detected = []
    
    for event in events:
        url = event.get("url") or ""
        body = event.get("body") or ""
        request = event.get("request") or ""
        
        content = f"{{url}} {{body}} {{request}}"
        
        for pattern in xss_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(event["event_id"])
                break
    
    return detected
'''
        
        return GeneratedRule(
            rule_id=rule_id,
            name=f"XSS: {indicator.get('title', 'CVE')}",
            description=f"Detects XSS from {indicator.get('source', 'Unknown')}",
            source_intel=indicator.get('hash_id', ''),
            mitre_techniques=['T1189'] + indicator.get('mitre_techniques', []),
            severity='medium',
            python_code=python_code,
            test_cases=[]
        )
    
    def _generate_memory_corruption_rule(self, indicator: Dict[str, Any]) -> Optional[GeneratedRule]:
        """Memory corruption is hard to detect at network level"""
        return None
    
    def _generate_privesc_rule(self, indicator: Dict[str, Any]) -> GeneratedRule:
        """Generate privilege escalation detection rule"""
        rule_id = f"AUTO-{self.next_rule_id:03d}"
        self.next_rule_id += 1
        
        python_code = f'''def detect_{rule_id.lower().replace("-", "_")}(events):
    """
    Threat Intel: {indicator.get('source', 'Unknown')}
    Description: Privilege Escalation detection
    Generated: {datetime.utcnow().isoformat()}
    """
    privesc_indicators = [
        r"sudo\\s+-l",
        r"sudo\\s+su",
        r"su\\s+-",
        r"pkexec",
        r"/etc/sudoers",
        r"/etc/passwd",
        r"/etc/shadow",
        r"setuid",
        r"chmod\\s+[0-9]*7",
        r"chown\\s+root",
    ]
    
    import re
    detected = []
    
    for event in events:
        command = event.get("command") or event.get("cmd") or ""
        process = event.get("process") or event.get("process_name") or ""
        
        content = f"{{command}} {{process}}"
        
        for pattern in privesc_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(event["event_id"])
                break
    
    return detected
'''
        
        return GeneratedRule(
            rule_id=rule_id,
            name=f"PrivEsc: {indicator.get('title', 'CVE')}",
            description=f"Detects privilege escalation from {indicator.get('source', 'Unknown')}",
            source_intel=indicator.get('hash_id', ''),
            mitre_techniques=['T1068', 'T1548'] + indicator.get('mitre_techniques', []),
            severity='high',
            python_code=python_code,
            test_cases=[]
        )
    
    def generate_all_rules(self) -> List[GeneratedRule]:
        """Generate rules from all threat intelligence"""
        indicators = self.load_threat_intel()
        
        if not indicators:
            print("[ERROR] No threat intelligence to process")
            return []
        
        print(f"[GEN] Processing {len(indicators)} indicators...")
        
        for indicator in indicators:
            # Skip if too old (30 days)
            try:
                from datetime import datetime
                pub_date = indicator.get('published_date', '')
                if pub_date:
                    date = datetime.fromisoformat(pub_date.replace('Z', '+00:00'))
                    if (datetime.utcnow() - date).days > 30:
                        continue
            except:
                pass
            
            # Generate rule based on indicator type
            source_type = indicator.get('source_type', '')
            
            if source_type == 'cve':
                rule = self.generate_rule_from_cve(indicator)
            elif source_type in ['rss', 'github']:
                # Try IOC-based first, then CVE-based
                rule = self.generate_rule_from_iocs(indicator)
                if not rule:
                    rule = self.generate_rule_from_cve(indicator)
            else:
                rule = self.generate_rule_from_iocs(indicator)
            
            if rule:
                self.rules.append(rule)
                print(f"[GEN] Generated {rule.rule_id}: {rule.name[:60]}...")
        
        print(f"[GEN] Total rules generated: {len(self.rules)}")
        return self.rules
    
    def save_rules(self):
        """Save generated rules to Python files"""
        for rule in self.rules:
            filename = f"auto_rule_{rule.rule_id.lower().replace('-', '_')}.py"
            filepath = os.path.join(RULES_OUTPUT_DIR, filename)
            
            with open(filepath, 'w') as f:
                f.write(f'"""\n')
                f.write(f'{rule.name}\n')
                f.write(f'{"=" * len(rule.name)}\n\n')
                f.write(f'Description: {rule.description}\n')
                f.write(f'Severity: {rule.severity}\n')
                f.write(f'MITRE: {", ".join(rule.mitre_techniques)}\n')
                f.write(f'Source: {rule.source_intel}\n')
                f.write(f'Generated: {datetime.utcnow().isoformat()}\n')
                f.write(f'"""\n\n')
                f.write(rule.python_code)
            
            print(f"[SAVE] {filepath}")
        
        # Save metadata
        metadata = {
            'generated_at': datetime.utcnow().isoformat(),
            'count': len(self.rules),
            'rules': [{
                'rule_id': r.rule_id,
                'name': r.name,
                'severity': r.severity,
                'mitre': r.mitre_techniques,
                'source': r.source_intel,
            } for r in self.rules]
        }
        
        with open(os.path.join(RULES_OUTPUT_DIR, 'metadata.json'), 'w') as f:
            json.dump(metadata, f, indent=2)


if __name__ == '__main__':
    generator = AdaptiveRuleGenerator()
    generator.generate_all_rules()
    generator.save_rules()
