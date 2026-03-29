"""
SQL Injection: CVE-2026-33352
=============================

Description: Detects SQL injection patterns from NVD-CVE-2026-33352
Severity: high
MITRE: T1190, T1190
Source: c94738966e00b2b3
Generated: 2026-03-29T20:16:54.443002
"""

def detect_auto_033(events):
    """
    Threat Intel: NVD-CVE-2026-33352
    Description: SQL Injection detection
    Generated: 2026-03-29T20:16:54.438459
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
