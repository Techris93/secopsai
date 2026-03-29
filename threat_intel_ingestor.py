#!/usr/bin/env python3
"""
SecOpsAI Threat Intelligence Ingestor
Actively learns from security sources and adapts detection rules.
"""

import os
import json
import re
import hashlib
import feedparser
import requests
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from urllib.parse import urlparse
import time

# Configuration
THREAT_INTEL_DIR = os.path.expanduser("~/.openclaw/workspace/secopsai/threat_intel")
CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
RSS_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://feeds.arstechnica.com/arstechnica/index",
    "https://krebsonsecurity.com/feed/",
    "https://www.schneier.com/blog/atom.xml",
    "https://blog.google/threat-analysis-group/rss/",
    "https://www.microsoft.com/en-us/security/blog/feed/",
    "https://www.wired.com/feed/category/security/latest/rss",
    "https://thehackernews.com/feeds/posts/default",
]

os.makedirs(THREAT_INTEL_DIR, exist_ok=True)


@dataclass
class ThreatIndicator:
    """Structured threat intelligence indicator"""
    source: str
    source_type: str  # 'cve', 'rss', 'github', 'misp'
    title: str
    description: str
    published_date: str
    iocs: List[Dict[str, Any]]  # IPs, domains, hashes, patterns
    mitre_techniques: List[str]
    severity: str  # 'critical', 'high', 'medium', 'low'
    raw_data: Dict[str, Any]
    hash_id: str = ""
    
    def __post_init__(self):
        if not self.hash_id:
            content = f"{self.title}{self.description}{self.published_date}"
            self.hash_id = hashlib.sha256(content.encode()).hexdigest()[:16]


class ThreatIntelIngestor:
    """Main ingestor that fetches from multiple sources"""
    
    def __init__(self):
        self.indicators: List[ThreatIndicator] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'SecOpsAI-ThreatIntel/1.0 (Security Research)'
        })
    
    def fetch_cves(self, days_back: int = 7) -> List[ThreatIndicator]:
        """Fetch recent CVEs from NVD"""
        indicators = []
        
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        params = {
            'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
            'resultsPerPage': 100
        }
        
        try:
            resp = self.session.get(CVE_API_URL, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            
            for vuln in data.get('vulnerabilities', []):
                cve = vuln.get('cve', {})
                cve_id = cve.get('id', 'Unknown')
                
                # Extract description
                descriptions = cve.get('descriptions', [])
                desc = next((d['value'] for d in descriptions if d.get('lang') == 'en'), 
                           descriptions[0]['value'] if descriptions else '')
                
                # Extract severity
                metrics = cve.get('metrics', {})
                cvss = metrics.get('cvssMetricV31', [{}])[0] if metrics.get('cvssMetricV31') else {}
                severity = cvss.get('cvssData', {}).get('baseSeverity', 'UNKNOWN').lower()
                
                # Extract CPEs (affected products)
                configurations = cve.get('configurations', [])
                affected_products = []
                for config in configurations:
                    for node in config.get('nodes', []):
                        for match in node.get('cpeMatch', []):
                            if match.get('vulnerable'):
                                affected_products.append(match.get('criteria', ''))
                
                # Extract potential IOCs from description
                iocs = self._extract_iocs(desc)
                
                # Extract MITRE techniques
                techniques = self._extract_mitre_techniques(desc)
                
                indicator = ThreatIndicator(
                    source=f"NVD-{cve_id}",
                    source_type='cve',
                    title=cve_id,
                    description=desc,
                    published_date=cve.get('published', ''),
                    iocs=iocs,
                    mitre_techniques=techniques,
                    severity=severity if severity in ['critical', 'high', 'medium', 'low'] else 'medium',
                    raw_data=vuln
                )
                indicators.append(indicator)
                
        except Exception as e:
            print(f"[ERROR] Failed to fetch CVEs: {e}")
        
        print(f"[CVE] Fetched {len(indicators)} CVEs")
        return indicators
    
    def fetch_rss_feeds(self) -> List[ThreatIndicator]:
        """Fetch from security RSS feeds"""
        indicators = []
        
        for feed_url in RSS_FEEDS:
            try:
                feed = feedparser.parse(feed_url)
                source_name = urlparse(feed_url).netloc
                
                for entry in feed.entries[:10]:  # Last 10 entries per feed
                    # Skip if too old (7 days)
                    published = entry.get('published_parsed') or entry.get('updated_parsed')
                    if published:
                        pub_date = datetime(*published[:6])
                        if datetime.utcnow() - pub_date > timedelta(days=7):
                            continue
                    
                    title = entry.get('title', '')
                    summary = entry.get('summary', '') or entry.get('description', '')
                    content = f"{title} {summary}"
                    
                    # Only process if security-relevant
                    if not self._is_security_relevant(content):
                        continue
                    
                    # Extract IOCs
                    iocs = self._extract_iocs(content)
                    
                    # Determine severity from keywords
                    severity = self._determine_severity(content)
                    
                    # Extract techniques
                    techniques = self._extract_mitre_techniques(content)
                    
                    indicator = ThreatIndicator(
                        source=source_name,
                        source_type='rss',
                        title=title,
                        description=summary[:500] + '...' if len(summary) > 500 else summary,
                        published_date=entry.get('published', datetime.utcnow().isoformat()),
                        iocs=iocs,
                        mitre_techniques=techniques,
                        severity=severity,
                        raw_data={'link': entry.get('link', '')}
                    )
                    indicators.append(indicator)
                    
                time.sleep(1)  # Be nice to RSS servers
                
            except Exception as e:
                print(f"[ERROR] Failed to fetch {feed_url}: {e}")
        
        print(f"[RSS] Fetched {len(indicators)} articles")
        return indicators
    
    def fetch_github_pocs(self, days_back: int = 7) -> List[ThreatIndicator]:
        """Fetch recent exploit PoCs from GitHub"""
        indicators = []
        
        # GitHub tokens for higher rate limits
        github_token = os.environ.get('GITHUB_TOKEN', '')
        headers = {'Authorization': f'token {github_token}'} if github_token else {}
        
        search_queries = [
            'exploit poc created:>' + (datetime.utcnow() - timedelta(days=days_back)).strftime('%Y-%m-%d'),
            'cve poc created:>' + (datetime.utcnow() - timedelta(days=days_back)).strftime('%Y-%m-%d'),
            'malware analysis created:>' + (datetime.utcnow() - timedelta(days=days_back)).strftime('%Y-%m-%d'),
        ]
        
        for query in search_queries:
            try:
                params = {
                    'q': query,
                    'sort': 'updated',
                    'order': 'desc',
                    'per_page': 20
                }
                resp = self.session.get(GITHUB_SEARCH_URL, params=params, 
                                       headers=headers, timeout=30)
                
                if resp.status_code == 403:  # Rate limited
                    print(f"[WARN] GitHub rate limited, skipping")
                    continue
                
                resp.raise_for_status()
                data = resp.json()
                
                for repo in data.get('items', []):
                    description = repo.get('description', '') or ''
                    name = repo.get('name', '')
                    
                    # Extract IOCs from description
                    iocs = self._extract_iocs(description + ' ' + name)
                    
                    # Extract CVE if present
                    cve_match = re.search(r'CVE-\d{4}-\d{4,}', name + ' ' + description)
                    cve_id = cve_match.group(0) if cve_match else None
                    
                    indicator = ThreatIndicator(
                        source=f"github.com/{repo.get('full_name', '')}",
                        source_type='github',
                        title=name,
                        description=description[:500] if description else 'No description',
                        published_date=repo.get('created_at', ''),
                        iocs=iocs,
                        mitre_techniques=self._extract_mitre_techniques(description),
                        severity='high' if cve_id else 'medium',
                        raw_data={
                            'url': repo.get('html_url', ''),
                            'stars': repo.get('stargazers_count', 0),
                            'cve': cve_id
                        }
                    )
                    indicators.append(indicator)
                
                time.sleep(2)  # GitHub rate limits
                
            except Exception as e:
                print(f"[ERROR] Failed to search GitHub: {e}")
        
        print(f"[GitHub] Fetched {len(indicators)} PoCs")
        return indicators
    
    def _extract_iocs(self, text: str) -> List[Dict[str, Any]]:
        """Extract IOCs from text using regex patterns"""
        iocs = []
        
        # IP addresses
        ip_pattern = r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        for match in re.finditer(ip_pattern, text):
            ip = match.group(0)
            if not ip.startswith(('10.', '192.168.', '127.', '0.', '255.')):
                iocs.append({'type': 'ip', 'value': ip, 'context': text[max(0,match.start()-50):match.end()+50]})
        
        # Domains (simplified)
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        common_tlds = ['.com', '.org', '.net', '.io', '.co', '.app', '.dev']
        for match in re.finditer(domain_pattern, text):
            domain = match.group(0).lower()
            if any(domain.endswith(tld) for tld in common_tlds):
                if not any(x in domain for x in ['google.', 'microsoft.', 'apple.', 'amazon.', 'github.', 'wikipedia.']):
                    iocs.append({'type': 'domain', 'value': domain, 'context': text[max(0,match.start()-50):match.end()+50]})
        
        # SHA256 hashes
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        for match in re.finditer(sha256_pattern, text):
            iocs.append({'type': 'hash_sha256', 'value': match.group(0), 'context': 'File hash'})
        
        # MD5 hashes
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        for match in re.finditer(md5_pattern, text):
            iocs.append({'type': 'hash_md5', 'value': match.group(0), 'context': 'File hash'})
        
        # CVE IDs
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        for match in re.finditer(cve_pattern, text, re.IGNORECASE):
            iocs.append({'type': 'cve', 'value': match.group(0).upper(), 'context': 'Vulnerability reference'})
        
        return iocs
    
    def _extract_mitre_techniques(self, text: str) -> List[str]:
        """Extract MITRE ATT&CK technique references"""
        techniques = []
        
        # Pattern: T1234 or T1234.001
        pattern = r'T\d{4}(?:\.\d{3})?'
        for match in re.finditer(pattern, text):
            techniques.append(match.group(0))
        
        # Common technique names
        technique_keywords = {
            'phishing': 'T1566',
            'spearphishing': 'T1566.001',
            'malware': 'T1204',
            'ransomware': 'T1486',
            'lateral movement': 'T1021',
            'persistence': 'T1543',
            'privilege escalation': 'T1068',
            'credential dumping': 'T1003',
            'data exfiltration': 'T1041',
            'command and control': 'T1071',
            'reconnaissance': 'T1595',
            'brute force': 'T1110',
            'sql injection': 'T1190',
            'xss': 'T1189',
        }
        
        text_lower = text.lower()
        for keyword, technique in technique_keywords.items():
            if keyword in text_lower and technique not in techniques:
                techniques.append(technique)
        
        return list(set(techniques))
    
    def _is_security_relevant(self, text: str) -> bool:
        """Check if content is security-relevant"""
        security_keywords = [
            'vulnerability', 'exploit', 'malware', 'ransomware', 'phishing',
            'breach', 'attack', 'threat', 'cve-', '0-day', 'zero-day',
            'backdoor', 'trojan', 'worm', 'apt', 'c2', 'command and control',
            'lateral movement', 'persistence', 'privilege escalation',
            'data exfiltration', 'credential theft', 'supply chain'
        ]
        text_lower = text.lower()
        return any(kw in text_lower for kw in security_keywords)
    
    def _determine_severity(self, text: str) -> str:
        """Determine severity from text content"""
        text_lower = text.lower()
        
        critical_keywords = ['critical', '0-day', 'zero-day', 'ransomware', 'worm', 'widespread']
        high_keywords = ['high', 'exploit', 'active', 'in the wild', 'poc', 'cve-202']
        
        if any(kw in text_lower for kw in critical_keywords):
            return 'critical'
        elif any(kw in text_lower for kw in high_keywords):
            return 'high'
        elif 'medium' in text_lower:
            return 'medium'
        else:
            return 'medium'
    
    def run(self) -> List[ThreatIndicator]:
        """Run full ingestion cycle"""
        print("=" * 60)
        print("SecOpsAI Threat Intelligence Ingestor")
        print(f"Started: {datetime.utcnow().isoformat()}")
        print("=" * 60)
        
        all_indicators = []
        
        # Fetch from all sources
        all_indicators.extend(self.fetch_cves())
        all_indicators.extend(self.fetch_rss_feeds())
        all_indicators.extend(self.fetch_github_pocs())
        
        # Deduplicate by hash_id
        seen_hashes = set()
        unique_indicators = []
        for ind in all_indicators:
            if ind.hash_id not in seen_hashes:
                seen_hashes.add(ind.hash_id)
                unique_indicators.append(ind)
        
        self.indicators = unique_indicators
        
        # Save to disk
        self._save_indicators()
        
        print(f"\n[SUMMARY] Total unique indicators: {len(unique_indicators)}")
        print(f"  - Critical: {sum(1 for i in unique_indicators if i.severity == 'critical')}")
        print(f"  - High: {sum(1 for i in unique_indicators if i.severity == 'high')}")
        print(f"  - Medium: {sum(1 for i in unique_indicators if i.severity == 'medium')}")
        print(f"  - Low: {sum(1 for i in unique_indicators if i.severity == 'low')}")
        
        return unique_indicators
    
    def _save_indicators(self):
        """Save indicators to JSON for rule generator"""
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filepath = os.path.join(THREAT_INTEL_DIR, f'indicators_{timestamp}.json')
        
        data = {
            'generated_at': datetime.utcnow().isoformat(),
            'count': len(self.indicators),
            'indicators': [asdict(ind) for ind in self.indicators]
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        # Also save latest
        latest_path = os.path.join(THREAT_INTEL_DIR, 'latest_indicators.json')
        with open(latest_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f"[SAVE] Indicators saved to {filepath}")


if __name__ == '__main__':
    ingestor = ThreatIntelIngestor()
    indicators = ingestor.run()
