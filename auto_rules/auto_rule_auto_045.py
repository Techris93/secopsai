"""
XSS: CVE-2024-51223
===================

Description: Detects XSS from NVD-CVE-2024-51223
Severity: medium
MITRE: T1189, T1189
Source: 42f7351666d590fe
Generated: 2026-03-29T20:16:54.443841
"""

def detect_auto_045(events):
    """
    Threat Intel: NVD-CVE-2024-51223
    Description: XSS detection
    Generated: 2026-03-29T20:16:54.438670
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
