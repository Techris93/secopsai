"""Cross-platform correlation rules for SecOpsAI."""

from typing import Dict, List, Any
from collections import defaultdict


def correlate_by_ip(findings: List[Dict], time_window_minutes: int = 60) -> List[Dict]:
    """
    Detect suspicious activity: same IP appearing on multiple platforms.
    
    Returns correlated findings with cross_platform flag.
    """
    # Group findings by IP
    by_ip = defaultdict(list)
    
    for finding in findings:
        # Check actor IP
        actor_ip = finding.get('actor', {}).get('ip')
        if actor_ip:
            by_ip[actor_ip].append(finding)
        
        # Check target IP
        target_ip = finding.get('target', {}).get('ip')
        if target_ip:
            by_ip[target_ip].append(finding)
    
    # Find IPs seen on multiple platforms
    correlations = []
    for ip, ip_findings in by_ip.items():
        platforms = set(f.get('platform') for f in ip_findings)
        if len(platforms) > 1:
            correlations.append({
                'correlation_type': 'cross_platform_ip',
                'ip': ip,
                'platforms': list(platforms),
                'findings': ip_findings,
                'severity': 'high',
                'description': f"IP {ip} seen on {len(platforms)} platforms: {', '.join(platforms)}"
            })
    
    return correlations


def correlate_by_user(findings: List[Dict], time_window_minutes: int = 60) -> List[Dict]:
    """
    Detect lateral movement: same user active on multiple platforms.
    """
    by_user = defaultdict(lambda: defaultdict(list))
    
    for finding in findings:
        user = finding.get('actor', {}).get('user')
        platform = finding.get('platform')
        if user and platform:
            by_user[user][platform].append(finding)
    
    correlations = []
    for user, platforms in by_user.items():
        if len(platforms) > 1:
            all_findings = []
            for pf in platforms.values():
                all_findings.extend(pf)
            
            correlations.append({
                'correlation_type': 'cross_platform_user',
                'user': user,
                'platforms': list(platforms.keys()),
                'findings': all_findings,
                'severity': 'critical' if any(f.get('severity') == 'critical' for f in all_findings) else 'high',
                'description': f"User {user} active on {len(platforms)} platforms"
            })
    
    return correlations


def run_correlation(findings: List[Dict]) -> Dict[str, Any]:
    """Run all correlation rules."""
    results = {
        'cross_platform_ip': correlate_by_ip(findings),
        'cross_platform_user': correlate_by_user(findings),
        'total_correlations': 0
    }
    results['total_correlations'] = sum(len(v) for v in results.values() if isinstance(v, list))
    return results


def correlate_by_time(findings: List[Dict], time_window_minutes: int = 10) -> List[Dict]:
    """
    Detect attack chains: multiple events in short time window.
    """
    from datetime import datetime, timedelta
    
    # Filter out findings with missing timestamps
    valid_findings = [f for f in findings if f.get('timestamp')]
    
    if len(valid_findings) < 3:
        return []
    
    # Sort by timestamp
    sorted_findings = sorted(valid_findings, key=lambda x: x.get('timestamp', ''))
    
    correlations = []
    window = timedelta(minutes=time_window_minutes)
    
    for i, f1 in enumerate(sorted_findings):
        chain = [f1]
        ts1 = f1.get('timestamp', '').replace('Z', '+00:00')
        try:
            f1_time = datetime.fromisoformat(ts1)
        except ValueError:
            continue
        
        for f2 in sorted_findings[i+1:]:
            ts2 = f2.get('timestamp', '').replace('Z', '+00:00')
            try:
                f2_time = datetime.fromisoformat(ts2)
                if f2_time - f1_time <= window:
                    chain.append(f2)
            except ValueError:
                continue
        
        if len(chain) >= 3:  # 3+ events in window
            platforms = set(f.get('platform') for f in chain if f.get('platform'))
            if len(platforms) > 1:
                correlations.append({
                    'correlation_type': 'time_cluster',
                    'window_minutes': time_window_minutes,
                    'event_count': len(chain),
                    'platforms': list(platforms),
                    'findings': chain,
                    'severity': 'high',
                    'description': f"{len(chain)} events in {time_window_minutes} min across {len(platforms)} platforms"
                })
    
    return correlations


def correlate_by_file_hash(findings: List[Dict]) -> List[Dict]:
    """
    Detect malware spread: same file hash on multiple systems.
    """
    by_hash = defaultdict(lambda: defaultdict(list))
    
    for finding in findings:
        file_hash = finding.get('target', {}).get('file_hash')
        platform = finding.get('platform')
        if file_hash and platform:
            by_hash[file_hash][platform].append(finding)
    
    correlations = []
    for file_hash, platforms in by_hash.items():
        if len(platforms) > 1:
            all_findings = []
            for pf in platforms.values():
                all_findings.extend(pf)
            
            correlations.append({
                'correlation_type': 'file_hash_spread',
                'file_hash': file_hash,
                'platforms': list(platforms.keys()),
                'findings': all_findings,
                'severity': 'critical',
                'description': f"Malware hash {file_hash[:16]}... found on {len(platforms)} platforms"
            })
    
    return correlations


def run_correlation(findings: List[Dict], time_window: int = 60) -> Dict[str, Any]:
    """Run all correlation rules."""
    results = {
        'cross_platform_ip': correlate_by_ip(findings, time_window),
        'cross_platform_user': correlate_by_user(findings, time_window),
        'time_cluster': correlate_by_time(findings, time_window // 6),  # Shorter window for time clusters
        'file_hash_spread': correlate_by_file_hash(findings),
        'total_correlations': 0
    }
    results['total_correlations'] = sum(len(v) for v in results.values() if isinstance(v, list))
    return results
