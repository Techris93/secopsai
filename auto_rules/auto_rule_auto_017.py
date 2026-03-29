"""
XSS: CVE-2025-6229
==================

Description: Detects XSS from NVD-CVE-2025-6229
Severity: medium
MITRE: T1189
Source: ac84a1700003bbd1
Generated: 2026-03-29T20:16:54.441935
"""

def detect_auto_017(events):
    """
    Threat Intel: NVD-CVE-2025-6229
    Description: XSS detection
    Generated: 2026-03-29T20:16:54.437744
    """
    xss_patterns = [
        r"<script[^>]*>[\s\S]*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe",
        r"<object",
        r"<embed",
        r"expression\s*\(",
        r"alert\s*\(",
        r"confirm\s*\(",
        r"prompt\s*\(",
        r"document\.cookie",
        r"document\.location",
        r"window\.location",
    ]
    
    import re
    detected = []
    
    for event in events:
        url = event.get("url") or ""
        body = event.get("body") or ""
        request = event.get("request") or ""
        
        content = url + " " + body + " " + request
        
        for pattern in xss_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(event["event_id"])
                break
    
    return detected
