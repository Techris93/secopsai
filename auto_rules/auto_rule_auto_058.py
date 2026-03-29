"""
Threat Intel: Microsoft Xbox One Hacked
=======================================

Description: Detects IOCs from www.schneier.com
Severity: high
MITRE: 
Source: d00b267de7cfd9e7
Generated: 2026-03-29T20:16:54.444739
"""

def detect_auto_058(events):
    """
    Threat Intel: www.schneier.com
    Description: <p>It&#8217;s an <a href="https://www.tomshardware.com/video-games/console-gaming/microsofts-unhacka...
    Generated: 2026-03-29T20:16:54.438958
    """
    malicious_ips = []
    malicious_domains = ['www.tomshardware.com', 'www.tomshardware.com']
    malicious_hashes = []
    
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
