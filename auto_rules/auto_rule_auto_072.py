"""
RCE Detection: huntframework
============================

Description: Detects remote code execution from github.com/osnolanarf/huntframework
Severity: critical
MITRE: T1059, T1203, T1204
Source: 5f9f0ce8e66f2610
Generated: 2026-03-29T20:16:54.445630
"""

def detect_auto_072(events):
    """
    Threat Intel: github.com/osnolanarf/huntframework
    Description: Remote Code Execution detection
    Generated: 2026-03-29T20:16:54.439701
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
