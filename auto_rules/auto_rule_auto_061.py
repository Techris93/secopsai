"""
Path Traversal: CVE-2026-31802
==============================

Description: Detects path traversal from github.com/Recorded-texteditor120/CVE-2026-31802
Severity: high
MITRE: T1083
Source: fc9c217abe76d064
Generated: 2026-03-29T20:16:54.444934
"""

def detect_auto_061(events):
    """
    Threat Intel: github.com/Recorded-texteditor120/CVE-2026-31802
    Description: Path Traversal detection
    Generated: 2026-03-29T20:16:54.439242
    """
    traversal_patterns = [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e%2f",
        r"%252e%252e%252f",
        r"..%252f",
        r"%252e%252e/",
        r"..%c0%af",
        r"%c0%ae%c0%ae/",
        r"....//",
        r"....\\",
    ]
    
    import re
    detected = []
    
    for event in events:
        url = event.get("url") or ""
        request = event.get("request") or ""
        filepath = event.get("filepath") or event.get("path") or ""
        
        content = url + " " + request + " " + filepath
        
        for pattern in traversal_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(event["event_id"])
                break
    
    return detected
