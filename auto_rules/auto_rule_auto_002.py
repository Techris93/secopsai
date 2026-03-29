"""
PrivEsc: CVE-2026-4606
======================

Description: Detects privilege escalation from NVD-CVE-2026-4606
Severity: high
MITRE: T1068, T1548, T1068
Source: 555cfb7ce3cdea77
Generated: 2026-03-29T19:53:18.132411
"""

def detect_auto_002(events):
    """
    Threat Intel: NVD-CVE-2026-4606
    Description: Privilege Escalation detection
    Generated: 2026-03-29T19:53:18.129558
    """
    privesc_indicators = [
        r"sudo\s+-l",
        r"sudo\s+su",
        r"su\s+-",
        r"pkexec",
        r"/etc/sudoers",
        r"/etc/passwd",
        r"/etc/shadow",
        r"setuid",
        r"chmod\s+[0-9]*7",
        r"chown\s+root",
    ]
    
    import re
    detected = []
    
    for event in events:
        command = event.get("command") or event.get("cmd") or ""
        process = event.get("process") or event.get("process_name") or ""
        
        content = command + " " + process
        
        for pattern in privesc_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                detected.append(event["event_id"])
                break
    
    return detected
