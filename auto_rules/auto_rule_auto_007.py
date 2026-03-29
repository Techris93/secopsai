"""
SQL Injection: CVE-2026-4571
============================

Description: Detects SQL injection patterns from NVD-CVE-2026-4571
Severity: high
MITRE: T1190, T1190
Source: a37995e0a2a51b02
Generated: 2026-03-29T19:53:18.132682
"""

def detect_auto_007(events):
    """
    Threat Intel: NVD-CVE-2026-4571
    Description: SQL Injection detection
    Generated: 2026-03-29T19:53:18.129669
    """
    sqli_patterns = [
        r"(%27)|(')|(--)|(%23)|(#)",
        r"((%3D)|(=))[^\n]*((%27)|(')|(--)|(%3B)|(;))",
        r"\w*((%27)|('))((%6F)|o|(%4F))((%72)|r|(%52))",
        r"((%27)|('))union",
        r"exec(\s|\+)+(s|x)p\w+",
        r"UNION\s+SELECT",
        r"INSERT\s+INTO",
        r"DELETE\s+FROM",
        r"DROP\s+TABLE",
    ]
    
    import re
    detected = []
    
    for event in events:
        # Check URL and request body
        url = event.get("url") or ""
        request = event.get("request") or event.get("http_request") or ""
        body = event.get("body") or event.get("data") or ""
        
        content = url + " " + request + " " + body
        
        for pattern in sqli_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(event["event_id"])
                break
    
    return detected
