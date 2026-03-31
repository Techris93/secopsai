"""
RCE Detection: CVE_2025_23209
=============================

Description: Detects remote code execution from github.com/farid-khelil/CVE_2025_23209
Severity: critical
MITRE: T1059, T1203
Source: ed5db595f59ffe5c
Generated: 2026-03-29T20:16:54.444860
"""

def detect_auto_060(events):
    """
    Threat Intel: github.com/farid-khelil/CVE_2025_23209
    Description: Remote Code Execution detection
    Generated: 2026-03-29T20:16:54.439203
    """
    rce_patterns = [
        r"\$\(.*?\)",  # Command substitution
        r"`.*?`",  # Backtick execution
        r"\b(eval|exec|system|passthru|shell_exec)\s*\(",
        r";\s*bash\s+-c",
        r";\s*sh\s+-c",
        r"\|\s*bash",
        r"\|\s*python\d*\s+-c",
        r"\|\s*perl\s+-e",
        r"\|\s*nc\s+-[el]",
        r"bash\s+-i\s+\>&\s+/dev/tcp/",
        r"python\d*\s+-c\s+['\"]import\s+socket",
        r"ruby\s+-rsocket",
    ]
    
    import re
    detected = []
    
    for event in events:
        url = event.get("url") or ""
        request = event.get("request") or ""
        body = event.get("body") or event.get("data") or ""
        command = event.get("command") or event.get("cmd") or ""
        
        content = url + " " + request + " " + body + " " + command
        
        for pattern in rce_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(event["event_id"])
                break
    
    return detected
