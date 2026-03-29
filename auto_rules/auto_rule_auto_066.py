"""
XSS: xss-coding-challenge
=========================

Description: Detects XSS from github.com/PXL-Security-Essentials/xss-coding-challenge
Severity: medium
MITRE: T1189, T1189
Source: 1b5f5099ef97cc2a
Generated: 2026-03-29T19:53:18.135802
"""

def detect_auto_066(events):
    """
    Threat Intel: github.com/PXL-Security-Essentials/xss-coding-challenge
    Description: XSS detection
    Generated: 2026-03-29T19:53:18.131490
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
