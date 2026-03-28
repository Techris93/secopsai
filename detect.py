"""
SecOps Autoresearch — Detection Rules
The ONLY file the AI agent modifies.

Contains detection rules, anomaly thresholds, and scoring logic.
The agent iterates on these to maximize the F1-score computed by evaluate.py.

Current baseline: Rules ported from OpenSentinel with initial thresholds.
"""

import re
import math
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Iterable
from collections import Counter, defaultdict
import hashlib


# ═══ Configuration ═══════════════════════════════════════════════════════════
# The agent can tune all of these values.

# Anomaly detector settings
ANOMALY_Z_THRESHOLD = 2.5
ANOMALY_MIN_SAMPLES = 10
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

BENIGN_DNS_BASE_DOMAINS = {
    "amazon.com",
    "cloudflare.com",
    "cloudfront.net",
    "github.com",
    "google.com",
    "googleapis.com",
    "microsoft.com",
    "office365.com",
    "slack.com",
    "zoom.us",
    "azurewebsites.net",
}

FILELESS_PATTERNS = {
    "mshta.exe": [r"vbscript:", r"https?://", r"createobject"],
    "certutil.exe": [r"-urlcache", r"-split", r"https?://"],
    "regsvr32.exe": [r"/i:https?://", r"scrobj\.dll"],
    "rundll32.exe": [r"javascript:", r"runhtmlapplication", r"mshtml"],
    "wscript.exe": [r"\\users\\public\\", r"https?://", r"\.vbs\b"],
    "cscript.exe": [r"\\users\\public\\", r"https?://", r"\.vbs\b"],
}

# ═══ Tunable Rule Thresholds ═════════════════════════════════════════════════
# tune.py patches this dict at runtime to sweep the parameter space.
# The agent may also modify individual values when optimizing detect.py.

RULE_THRESHOLDS: dict = {
    "brute_force": {
        # tune.py (quick grid, 2026-03-17): RAPID_THRESHOLD 6→4, WINDOW 10→5 min
        # lifted overall F1 from 0.720 → 0.796 by catching more slow/distributed bursts.
        "RAPID_THRESHOLD": 4,
        "RAPID_WINDOW_MINUTES": 5,
        "SLOW_THRESHOLD": 2,
        "SLOW_MIN_SPAN_MINUTES": 15,
        "COMPROMISE_WINDOW_MINUTES": 20,
        "SOURCELESS_THRESHOLD": 8,
    },
    "dns_exfiltration": {
        "MIN_QUERIES_PER_DOMAIN": 3,
        "MIN_LABEL_LENGTH": 10,
        "MIN_ENTROPY": 2.5,
        "MIN_UNIQUE_LABEL_RATIO": 0.6,
        "FALLBACK_LABEL_LENGTH": 20,
        "FALLBACK_UNIQUE_RATIO": 0.7,
    },
    "c2_beaconing": {
        "MIN_CONNECTIONS": 3,
        "MAX_BYTES_OUT": 500,
        "MAX_BYTES_IN": 250,
    },
    "lateral_movement": {
        "UNIQUE_DEST_THRESHOLD": 3,
        "WINDOW_MINUTES": 20,
        "MAX_AVERAGE_GAP_SECONDS": 240,
        "MAX_TRANSFER_BYTES": 50000,
    },
}


def parse_timestamp(timestamp: str) -> datetime:
    normalized = timestamp[:-1] if timestamp.endswith("Z") else timestamp
    return datetime.fromisoformat(normalized)


def is_internal_ip(ip: str) -> bool:
    if not ip:
        return False
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        octets = ip.split(".")
        if len(octets) > 1 and octets[1].isdigit():
            return 16 <= int(octets[1]) <= 31
    return False


def is_external_ip(ip: str) -> bool:
    return bool(ip) and not is_internal_ip(ip)


def minutes_between(start: Dict, end: Dict) -> float:
    return (parse_timestamp(end["timestamp"]) - parse_timestamp(start["timestamp"])).total_seconds() / 60.0


def base_domain(query: str) -> str:
    parts = query.lower().split(".")
    if len(parts) < 2:
        return query.lower()
    return ".".join(parts[-2:])


def first_label(query: str) -> str:
    return query.lower().split(".", 1)[0]


def digit_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(char.isdigit() for char in text) / len(text)


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0

    counts = defaultdict(int)
    for char in text:
        counts[char] += 1

    entropy = 0.0
    length = len(text)
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def average(values: Iterable[float]) -> float:
    values = list(values)
    return sum(values) / len(values) if values else 0.0


def coefficient_of_variation(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0

    avg = average(values)
    if avg == 0:
        return 0.0

    variance = sum((value - avg) ** 2 for value in values) / len(values)
    return math.sqrt(variance) / avg


def is_openclaw_event(event: Dict[str, Any], surface: Optional[str] = None) -> bool:
    sourcetype = str(event.get("sourcetype", ""))
    if not sourcetype.startswith("openclaw_"):
        return False
    if surface is None:
        return True
    return sourcetype == f"openclaw_{surface}"


def openclaw_session_key(event: Dict[str, Any]) -> str:
    return (
        event.get("session_key")
        or event.get("requester_session_key")
        or event.get("child_session_key")
        or ""
    )


def extract_command_text(event: Dict[str, Any]) -> str:
    for key in ("command", "message"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def is_openclaw_exec_like(event: Dict[str, Any]) -> bool:
    return is_openclaw_event(event, "tool") or is_openclaw_event(event, "exec")

# ═══ Detection Rules ═════════════════════════════════════════════════════════
# Each rule has:
#   - id, name, mitre: metadata
#   - detect(events): function that returns list of detected event_ids
#
# The agent can modify thresholds, logic, add new rules, or remove weak ones.

def detect_brute_force(events: List[Dict]) -> List[str]:
    """
    T1110 — Brute Force Detection
    Detects multiple failed login attempts from a single source IP.
    """
    _t = RULE_THRESHOLDS["brute_force"]
    RAPID_THRESHOLD = _t["RAPID_THRESHOLD"]
    RAPID_WINDOW_MINUTES = _t["RAPID_WINDOW_MINUTES"]
    SLOW_THRESHOLD = _t["SLOW_THRESHOLD"]
    SLOW_MIN_SPAN_MINUTES = _t["SLOW_MIN_SPAN_MINUTES"]
    COMPROMISE_WINDOW_MINUTES = _t["COMPROMISE_WINDOW_MINUTES"]
    SOURCELESS_THRESHOLD = _t["SOURCELESS_THRESHOLD"]

    failures_by_actor: Dict[tuple[str, str], List[Dict]] = defaultdict(list)
    successes_by_actor: Dict[tuple[str, str], List[Dict]] = defaultdict(list)

    for event in events:
        if event.get("sourcetype") != "auth":
            continue

        actor = (event.get("src_ip", ""), event.get("user", ""))
        if event.get("action") == "failure":
            failures_by_actor[actor].append(event)
        elif event.get("action") == "success":
            successes_by_actor[actor].append(event)

    detected = set()
    for actor, failures in failures_by_actor.items():
        src_ip, _user = actor
        sourceless_actor = not src_ip
        if not sourceless_actor and not is_external_ip(src_ip):
            continue

        ordered_failures = sorted(failures, key=lambda event: event["timestamp"])
        ordered_successes = sorted(successes_by_actor.get(actor, []), key=lambda event: event["timestamp"])
        compromise_after_failure = False

        window_start = 0
        for window_end, event in enumerate(ordered_failures):
            while minutes_between(ordered_failures[window_start], event) > RAPID_WINDOW_MINUTES:
                window_start += 1

            if window_end - window_start + 1 >= RAPID_THRESHOLD:
                compromise_after_failure = True
                for flagged in ordered_failures[window_start:window_end + 1]:
                    detected.add(flagged["event_id"])

        if len(ordered_failures) >= SLOW_THRESHOLD:
            span_minutes = minutes_between(ordered_failures[0], ordered_failures[-1])
            if span_minutes >= SLOW_MIN_SPAN_MINUTES and not ordered_successes:
                for flagged in ordered_failures:
                    detected.add(flagged["event_id"])

        # BOTSv3 and similar logs can omit src_ip for host-local brute-force bursts.
        if sourceless_actor and len(ordered_failures) >= SOURCELESS_THRESHOLD and not ordered_successes:
            for flagged in ordered_failures:
                detected.add(flagged["event_id"])

        if compromise_after_failure:
            last_failure = ordered_failures[-1]
            for success in ordered_successes:
                if 0 <= minutes_between(last_failure, success) <= COMPROMISE_WINDOW_MINUTES:
                    detected.add(success["event_id"])

    return list(detected)


def detect_dns_exfiltration(events: List[Dict]) -> List[str]:
    """
    T1048.003 — DNS Exfiltration
    Detects unusually long DNS queries indicating data exfiltration.
    """
    _t = RULE_THRESHOLDS["dns_exfiltration"]
    MIN_QUERIES_PER_DOMAIN = _t["MIN_QUERIES_PER_DOMAIN"]
    MIN_LABEL_LENGTH = _t["MIN_LABEL_LENGTH"]
    MIN_ENTROPY = _t["MIN_ENTROPY"]
    MIN_UNIQUE_LABEL_RATIO = _t["MIN_UNIQUE_LABEL_RATIO"]
    FALLBACK_LABEL_LENGTH = _t["FALLBACK_LABEL_LENGTH"]
    FALLBACK_UNIQUE_RATIO = _t["FALLBACK_UNIQUE_RATIO"]

    queries_by_src_and_domain: Dict[tuple[str, str], List[Dict]] = defaultdict(list)
    for event in events:
        if event.get("sourcetype") == "dns":
            query = event.get("query", "")
            queries_by_src_and_domain[(event.get("src_ip", ""), base_domain(query))].append(event)

    detected = set()
    for (_src_ip, domain), queries in queries_by_src_and_domain.items():
        if domain in BENIGN_DNS_BASE_DOMAINS or len(queries) < MIN_QUERIES_PER_DOMAIN:
            continue

        labels = [first_label(event.get("query", "")) for event in queries]
        suspicious_labels = [
            label for label in labels
            if len(label) >= MIN_LABEL_LENGTH and (
                shannon_entropy(label) >= MIN_ENTROPY or digit_ratio(label) >= 0.2
            )
        ]
        average_label_len = average(len(label) for label in labels)
        unique_ratio = len(set(labels)) / len(labels)
        has_txt_queries = any(event.get("query_type") == "TXT" for event in queries)
        has_long_queries = any(event.get("query_length", len(event.get("query", ""))) >= 40 for event in queries)

        if unique_ratio >= MIN_UNIQUE_LABEL_RATIO and len(suspicious_labels) >= max(3, len(queries) // 2):
            if has_txt_queries or has_long_queries or len(queries) >= 8:
                for event in queries:
                    detected.add(event["event_id"])
            continue

        # Fallback for high-volume randomized subdomain patterns common in DNS exfil.
        if average_label_len >= FALLBACK_LABEL_LENGTH and unique_ratio >= FALLBACK_UNIQUE_RATIO and has_long_queries:
            for event in queries:
                detected.add(event["event_id"])

    return list(detected)


def detect_c2_beaconing(events: List[Dict]) -> List[str]:
    """
    T1071 — C2 Beaconing
    Detects periodic outbound connections to the same destination.
    """
    _t = RULE_THRESHOLDS["c2_beaconing"]
    MIN_CONNECTIONS = _t["MIN_CONNECTIONS"]
    MAX_BYTES_OUT = _t["MAX_BYTES_OUT"]
    MAX_BYTES_IN = _t["MAX_BYTES_IN"]
    SUSPICIOUS_PORTS = {11211, 4444, 1080, 9001, 9030, 6667, 6697}

    connections: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        if (event.get("sourcetype") == "firewall" and
            event.get("direction") == "outbound" and
            event.get("action") == "allowed"):
            key = f"{event.get('src_ip')}:{event.get('dest_ip')}"
            connections[key].append(event)

    detected = set()
    for _key, conn_events in connections.items():
        if len(conn_events) < MIN_CONNECTIONS:
            continue

        ordered = sorted(conn_events, key=lambda event: event["timestamp"])
        max_bytes_out = max(event.get("bytes_out", 0) for event in ordered)
        max_bytes_in = max(event.get("bytes_in", 0) for event in ordered)
        ports = {event.get("dest_port") for event in ordered}
        low_volume = max_bytes_out <= MAX_BYTES_OUT and max_bytes_in <= MAX_BYTES_IN
        stealth_low_volume = max_bytes_out <= 350 and max_bytes_in <= 170
        has_suspicious_port = any(port in SUSPICIOUS_PORTS for port in ports)

        if len(ordered) >= 15 and low_volume:
            for event in ordered:
                detected.add(event["event_id"])
        elif len(ordered) >= 5 and low_volume and stealth_low_volume and ports == {443}:
            for event in ordered:
                detected.add(event["event_id"])
        elif len(ordered) >= 8 and has_suspicious_port and low_volume:
            for event in ordered:
                detected.add(event["event_id"])

    return list(detected)


def detect_lateral_movement(events: List[Dict]) -> List[str]:
    """
    T1021.002 — Lateral Movement via SMB
    Detects a single IP connecting to multiple internal hosts on port 445.
    """
    _t = RULE_THRESHOLDS["lateral_movement"]
    UNIQUE_DEST_THRESHOLD = _t["UNIQUE_DEST_THRESHOLD"]
    WINDOW_MINUTES = _t["WINDOW_MINUTES"]
    MAX_AVERAGE_GAP_SECONDS = _t["MAX_AVERAGE_GAP_SECONDS"]
    MAX_TRANSFER_BYTES = _t["MAX_TRANSFER_BYTES"]

    smb_by_src: Dict[str, Dict[str, List[Dict]]] = defaultdict(lambda: defaultdict(list))
    detected = set()
    for event in events:
        if (event.get("sourcetype") == "firewall" and
            event.get("dest_port") == 445):
            src = event.get("src_ip", "")
            dest = event.get("dest_ip", "")
            smb_by_src[src][dest].append(event)

            # External SMB attempts to internal assets are high-confidence lateral probes.
            if is_external_ip(src) and is_internal_ip(dest):
                detected.add(event["event_id"])

    for _src, destinations in smb_by_src.items():
        flat_events = sorted(
            [event for dest_events in destinations.values() for event in dest_events],
            key=lambda event: event["timestamp"],
        )
        if len(flat_events) < UNIQUE_DEST_THRESHOLD:
            continue

        window_start = 0
        for window_end, event in enumerate(flat_events):
            while minutes_between(flat_events[window_start], event) > WINDOW_MINUTES:
                window_start += 1

            candidate_events = flat_events[window_start:window_end + 1]
            unique_destinations = {candidate.get("dest_ip") for candidate in candidate_events}
            if len(unique_destinations) < UNIQUE_DEST_THRESHOLD:
                continue

            deltas = [
                (parse_timestamp(current["timestamp"]) - parse_timestamp(previous["timestamp"])).total_seconds()
                for previous, current in zip(candidate_events, candidate_events[1:])
            ]
            average_gap = average(deltas)
            max_transfer = max(candidate.get("bytes_out", 0) for candidate in candidate_events)

            if average_gap <= MAX_AVERAGE_GAP_SECONDS and max_transfer <= MAX_TRANSFER_BYTES:
                for candidate in candidate_events:
                    detected.add(candidate["event_id"])

    return list(detected)


def detect_powershell_abuse(events: List[Dict]) -> List[str]:
    """
    T1059.001 — Suspicious PowerShell Execution
    Detects encoded or obfuscated PowerShell commands.
    """
    SUSPICIOUS_PATTERNS = [
        r"(?i)(encodedcommand|-enc\b)",
        r"(?i)(bypass)",
        r"(?i)(hidden)",
        r"(?i)(invoke-mimikatz|invoke-expression|iex\b)",
        r"(?i)(downloadstring|downloadfile)",
        r"(?i)(-nop\b|-w\s+hidden)",
    ]

    detected = []
    for event in events:
        if event.get("sourcetype") == "sysmon":
            process = event.get("process", "").lower()
            cmd = event.get("command_line", "")

            if "powershell" in process or "pwsh" in process:
                for pattern in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, cmd):
                        detected.append(event["event_id"])
                        break

    return detected


def detect_privilege_escalation(events: List[Dict]) -> List[str]:
    """
    T1068 — Privilege Escalation
    Detects privilege escalation attempts.
    """
    EXCLUDED_USERS = ["root", "SYSTEM", "admin"]
    SUSPICIOUS_COMMAND = re.compile(
        r"(?i)(\brunas\b|\bpkexec\b|sudo\s+(su\b|/bin/(?:ba)?sh\b|-l\b))"
    )

    detected = []
    for event in events:
        if event.get("action") == "escalation":
            user = event.get("user", "")
            command = event.get("command", "")
            if user not in EXCLUDED_USERS and SUSPICIOUS_COMMAND.search(command):
                detected.append(event["event_id"])

    return detected


def detect_fileless_lolbins(events: List[Dict]) -> List[str]:
    """
    T1218 — Fileless / LOLBin Abuse
    Detects suspicious use of trusted Windows binaries for payload execution.
    """
    detected = []

    for event in events:
        if event.get("sourcetype") != "sysmon":
            continue

        process = event.get("process", "").lower()
        command = event.get("command_line", "")
        patterns = FILELESS_PATTERNS.get(process)
        if patterns and any(re.search(pattern, command, re.IGNORECASE) for pattern in patterns):
            detected.append(event["event_id"])

    return detected


def _event_actor_user(event: Dict[str, Any]) -> str:
    actor = event.get("actor")
    if isinstance(actor, dict):
        user = actor.get("user")
        if isinstance(user, str):
            return user
    user = event.get("user")
    return user if isinstance(user, str) else ""


def _event_actor_process(event: Dict[str, Any]) -> str:
    actor = event.get("actor")
    if isinstance(actor, dict):
        process = actor.get("process") or actor.get("command_line")
        if isinstance(process, str):
            return process
    for key in ("process", "process_name", "command", "command_line"):
        value = event.get(key)
        if isinstance(value, str):
            return value
    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        for key in ("macos_process", "process", "command", "path", "binary_path", "script_path"):
            value = metadata.get(key)
            if isinstance(value, str):
                return value
    return ""


def _event_message(event: Dict[str, Any]) -> str:
    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        for key in ("macos_message", "message", "event_message"):
            value = metadata.get(key)
            if isinstance(value, str) and value.strip():
                return value
    for key in ("message", "command", "command_line"):
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _is_macos_event(event: Dict[str, Any]) -> bool:
    return str(event.get("platform", "")).lower() == "macos"


def detect_macos_authentication_failures(events: List[Dict]) -> List[str]:
    """
    T1110 — Suspicious macOS authentication failure bursts.
    """
    grouped: Dict[tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for event in events:
        if not _is_macos_event(event):
            continue
        if event.get("event_type") not in {"auth_failure", "auth_attempt"}:
            continue
        if str(event.get("outcome", "")).lower() not in {"failure", "unknown"}:
            continue
        user = _event_actor_user(event) or "unknown"
        process = _event_actor_process(event) or str(event.get("source", "unknown"))
        grouped[(user, process)].append(event)

    detected: set[str] = set()
    for failures in grouped.values():
        ordered = sorted(failures, key=lambda item: item["timestamp"])
        if len(ordered) >= 4:
            for start in range(len(ordered) - 3):
                end = start + 3
                if minutes_between(ordered[start], ordered[end]) <= 10:
                    detected.update(event["event_id"] for event in ordered[start:end + 1])
    return sorted(detected)


def detect_macos_sudo_misuse(events: List[Dict]) -> List[str]:
    """
    T1548.003 — Suspicious sudo and privilege escalation usage on macOS.
    """
    suspicious = re.compile(
        r"(?i)(incorrect password attempts|authentication failure|sudoers|user .* is not allowed to run sudo|3 incorrect password attempts|sudo\s+-l|sudo\s+su\b|sudo\s+/bin/(?:ba)?sh\b|sudo\s+-u\s+root)"
    )
    detected = []
    for event in events:
        if not _is_macos_event(event):
            continue
        message = _event_message(event)
        process = _event_actor_process(event)
        if "sudo" not in (message + " " + process).lower():
            continue
        if suspicious.search(message) or suspicious.search(process):
            detected.append(event["event_id"])
    return detected


def detect_macos_persistence_creation(events: List[Dict]) -> List[str]:
    """
    T1543 / T1547 — LaunchAgent/LaunchDaemon and other persistence creation on macOS.
    """
    path_pattern = re.compile(
        r"(?i)(/library/launch(?:agents|daemons)/|~/library/launchagents/|login items|crontab\b|emond\.d|launchctl\s+(?:load|bootstrap|enable|kickstart))"
    )
    detected = []
    for event in events:
        if not _is_macos_event(event):
            continue
        message = _event_message(event)
        process = _event_actor_process(event)
        combined = f"{message} {process}"
        if path_pattern.search(combined):
            detected.append(event["event_id"])
    return detected


def detect_macos_unusual_script_execution(events: List[Dict]) -> List[str]:
    """
    T1059 — Unusual shell or script execution chains on macOS.
    """
    suspicious = re.compile(
        r"(?i)(osascript|curl\s+[^|]+\|\s*(?:bash|sh)|python3?\s+-c\b|perl\s+-e\b|bash\s+-c\b|zsh\s+-c\b|sh\s+-c\b|base64\s+-d|chmod\s+\+x.*(?:/tmp|/private/tmp|/users/shared)|/tmp/|/private/tmp/|/users/shared/|https?://)"
    )
    detected = []
    for event in events:
        if not _is_macos_event(event):
            continue
        combined = f"{_event_actor_process(event)} {_event_message(event)}"
        if suspicious.search(combined):
            detected.append(event["event_id"])
    return detected


def detect_macos_suspicious_binary_execution(events: List[Dict]) -> List[str]:
    """
    T1204 / T1553 — Unsigned or suspicious binary execution paths on macOS.
    """
    unsigned_markers = re.compile(r"(?i)(unsigned|not notarized|signature invalid|code signature|quarantine)")
    risky_paths = re.compile(r"(?i)(/users/shared/|/tmp/|/private/tmp/|/volumes/|/applications/[^\s]+\.app/contents/macos/)")
    suspicious_names = re.compile(r"(?i)(installer|updater|agent|helper|payload|runme|launch|osascript)")
    detected = []
    for event in events:
        if not _is_macos_event(event):
            continue
        message = _event_message(event)
        process = _event_actor_process(event)
        combined = f"{process} {message}"
        if unsigned_markers.search(message) or (risky_paths.search(combined) and suspicious_names.search(combined)):
            detected.append(event["event_id"])
    return detected


def detect_macos_suspicious_system_activity(events: List[Dict]) -> List[str]:
    """
    T1562 / T1518 — Security control tampering and unusual host activity patterns on macOS.
    """
    suspicious = re.compile(
        r"(?i)(spctl\s+--master-disable|csrutil\s+disable|systemextensionsctl\s+(?:install|uninstall|reset)|tccutil\s+reset|xattr\s+-d\s+com\.apple\.quarantine|defaults\s+write\s+com\.apple\.(?:loginwindow|security)|launchctl\s+disable\s+system/|kextload\b|kmutil\b|mdfind\s+kMDItemWhereFroms)"
    )
    detected = []
    for event in events:
        if not _is_macos_event(event):
            continue
        combined = f"{_event_actor_process(event)} {_event_message(event)}"
        if suspicious.search(combined):
            detected.append(event["event_id"])
    return detected


def detect_openclaw_dangerous_exec(events: List[Dict]) -> List[str]:
    """
    OpenClaw-specific dangerous exec detection.
    Flags obviously risky command execution patterns in OpenClaw exec tool usage.
    """
    suspicious_patterns = [
        r"(?i)curl\s+.*https?://.*\|\s*(bash|sh)",
        r"(?i)wget\s+.*https?://.*\|\s*(bash|sh)",
        r"(?i)bash\s+-c\s+.*curl",
        r"(?i)chmod\s+\+x\s+.*&&\s*(bash|sh)",
        r"(?i)\bnc\b.*\s-e\s",
        r"(?i)\bssh\s+root@",
        r"(?i)\bscp\b.*root@",
        r"(?i)\brm\s+-rf\s+/(?!Users(?:/|$)|tmp(?:/|$))",
        r"(?i)authorization:\s*bearer",
    ]

    DANGEROUS_TOOL_NAMES = {"exec", "run_in_terminal", "execute_command", "shell", "bash", "sh"}

    detected = []
    for event in events:
        if not is_openclaw_exec_like(event):
            continue
        tool_name = event.get("tool_name")
        if is_openclaw_event(event, "tool") and tool_name not in DANGEROUS_TOOL_NAMES:
            continue

        command = extract_command_text(event)
        if not command:
            continue

        if any(re.search(pattern, command) for pattern in suspicious_patterns):
            detected.append(event["event_id"])

    return detected


def detect_openclaw_sensitive_config_change(events: List[Dict]) -> List[str]:
    """
    OpenClaw-specific sensitive config mutation detection.
    """
    sensitive_prefixes = (
        "gateway.auth",
        "tools.exec",
        "commands",
        "channels.",
        "skills.entries.",
        "auth.",
        "system.permissions",
        "system.sandbox",
        "network.allowedHosts",
        "network.proxy",
    )

    detected = []
    for event in events:
        if not is_openclaw_event(event, "config"):
            continue
        changed_paths = event.get("changed_paths", [])
        if not isinstance(changed_paths, list):
            continue
        if any(str(path).startswith(sensitive_prefixes) for path in changed_paths):
            detected.append(event["event_id"])

    return detected


def detect_openclaw_skill_source_drift(events: List[Dict]) -> List[str]:
    """
    OpenClaw-specific untrusted skill source detection.
    """
    trusted_sources = {"bundled", "clawhub", "local", "managed", "workspace"}

    detected = []
    for event in events:
        if not is_openclaw_event(event, "skills"):
            continue
        if event.get("action") not in {"install", "enable", "update"}:
            continue

        source = str(event.get("skill_source") or "").strip().lower()
        if source and source not in trusted_sources:
            detected.append(event["event_id"])

    return detected


def detect_openclaw_repeated_policy_denials(events: List[Dict]) -> List[str]:
    """
    OpenClaw-specific repeated blocked action detection.
    """
    DENIAL_THRESHOLD = 3
    WINDOW_MINUTES = 15

    denied_by_session: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        if not is_openclaw_event(event):
            continue
        is_denied = (
            bool(event.get("denied"))
            or event.get("status") in {"blocked", "approval-unavailable"}
            or event.get("approval_state") in {"denied", "blocked", "approval-unavailable"}
        )
        if not is_denied:
            continue

        session_key = openclaw_session_key(event)
        if session_key:
            denied_by_session[session_key].append(event)

    detected = set()
    for session_key, denied_events in denied_by_session.items():
        _ = session_key
        ordered = sorted(denied_events, key=lambda event: event["timestamp"])
        window_start = 0
        for window_end, event in enumerate(ordered):
            while minutes_between(ordered[window_start], event) > WINDOW_MINUTES:
                window_start += 1
            if window_end - window_start + 1 >= DENIAL_THRESHOLD:
                for flagged in ordered[window_start:window_end + 1]:
                    detected.add(flagged["event_id"])

    return list(detected)


def detect_openclaw_tool_burst(events: List[Dict]) -> List[str]:
    """
    OpenClaw-specific bursty tool activity detection.
    Detects concentrated tool starts in a single session with enough breadth or mutation.
    """
    BURST_THRESHOLD = 5
    WINDOW_MINUTES = 2
    MIN_UNIQUE_TOOLS = 4
    MIN_MUTATING_EVENTS = 3
    RISKY_SEVERITY_HINTS = {"medium", "high", "critical"}

    tool_starts_by_session: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        if not is_openclaw_event(event, "tool"):
            continue
        if event.get("action") != "start":
            continue
        session_key = openclaw_session_key(event)
        if session_key:
            tool_starts_by_session[session_key].append(event)

    detected = set()
    for session_key, tool_events in tool_starts_by_session.items():
        _ = session_key
        ordered = sorted(tool_events, key=lambda event: event["timestamp"])
        window_start = 0
        for window_end, event in enumerate(ordered):
            while minutes_between(ordered[window_start], event) > WINDOW_MINUTES:
                window_start += 1

            candidate_events = ordered[window_start:window_end + 1]
            if len(candidate_events) < BURST_THRESHOLD:
                continue

            unique_tools = {candidate.get("tool_name") for candidate in candidate_events}
            mutating_count = sum(bool(candidate.get("mutating")) for candidate in candidate_events)
            has_risky_context = any(
                str(candidate.get("severity_hint") or "").lower() in RISKY_SEVERITY_HINTS
                or bool(candidate.get("denied"))
                or str(candidate.get("status") or "").lower() in {"blocked", "failed", "error"}
                for candidate in candidate_events
            )
            if not has_risky_context:
                continue

            if len(unique_tools) >= MIN_UNIQUE_TOOLS or mutating_count >= MIN_MUTATING_EVENTS:
                for candidate in candidate_events:
                    detected.add(candidate["event_id"])

    return list(detected)


def detect_openclaw_pairing_churn(events: List[Dict]) -> List[str]:
    """
    OpenClaw-specific suspicious pairing churn detection.
    Flags repeated pairing transitions in a short window for one session.
    """
    CHURN_THRESHOLD = 3
    WINDOW_MINUTES = 10

    pairing_by_session: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        if not is_openclaw_event(event, "pairing") and not is_openclaw_event(event, "session"):
            continue
        if not is_openclaw_event(event, "session") and event.get("action") is None:
            continue
        session_key = openclaw_session_key(event)
        if session_key:
            pairing_by_session[session_key].append(event)

    detected = set()

    # Original pairing-surface logic: distinct actions + statuses within window
    for pairing_events in pairing_by_session.values():
        if not any(is_openclaw_event(e, "pairing") for e in pairing_events):
            continue
        ordered = sorted(pairing_events, key=lambda event: event["timestamp"])
        window_start = 0
        for window_end, event in enumerate(ordered):
            while minutes_between(ordered[window_start], event) > WINDOW_MINUTES:
                window_start += 1
            candidate_events = ordered[window_start:window_end + 1]
            statuses = {candidate.get("status") for candidate in candidate_events}
            actions = {candidate.get("action") for candidate in candidate_events}
            if len(candidate_events) >= CHURN_THRESHOLD and len(actions) >= 2 and len(statuses) >= 2:
                for candidate in candidate_events:
                    detected.add(candidate["event_id"])

    # Session-surface churn: many session_start events from same agent in window
    SESSION_START_THRESHOLD = 4
    session_starts_by_agent: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        if not is_openclaw_event(event, "session"):
            continue
        if event.get("action") != "start":
            continue
        agent_id = event.get("agent_id") or event.get("channel") or ""
        if agent_id:
            session_starts_by_agent[agent_id].append(event)

    for session_events in session_starts_by_agent.values():
        ordered = sorted(session_events, key=lambda event: event["timestamp"])
        window_start = 0
        for window_end, event in enumerate(ordered):
            while minutes_between(ordered[window_start], event) > WINDOW_MINUTES:
                window_start += 1
            candidate_events = ordered[window_start:window_end + 1]
            if len(candidate_events) >= SESSION_START_THRESHOLD:
                for candidate in candidate_events:
                    detected.add(candidate["event_id"])

    return list(detected)


def detect_openclaw_subagent_fanout(events: List[Dict]) -> List[str]:
    """
    OpenClaw-specific suspicious subagent fanout detection.
    Flags rapid spawning of multiple child sessions from one requester session.
    """
    FANOUT_THRESHOLD = 3
    WINDOW_MINUTES = 5

    subagents_by_requester: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        if not is_openclaw_event(event, "subagent"):
            continue
        if event.get("action") != "spawn":
            continue
        requester_session_key = event.get("requester_session_key") or openclaw_session_key(event)
        if requester_session_key:
            subagents_by_requester[str(requester_session_key)].append(event)

    detected = set()
    for spawn_events in subagents_by_requester.values():
        ordered = sorted(spawn_events, key=lambda event: event["timestamp"])
        window_start = 0
        for window_end, event in enumerate(ordered):
            while minutes_between(ordered[window_start], event) > WINDOW_MINUTES:
                window_start += 1

            candidate_events = ordered[window_start:window_end + 1]
            unique_children = {candidate.get("child_session_key") for candidate in candidate_events}
            if len(candidate_events) >= FANOUT_THRESHOLD and len(unique_children) >= FANOUT_THRESHOLD:
                for candidate in candidate_events:
                    detected.add(candidate["event_id"])

    return list(detected)


def detect_openclaw_restart_loop(events: List[Dict]) -> List[str]:
    """
    OpenClaw-specific suspicious restart loop detection.
    Flags repeated restart scheduling in one session over a short interval.
    """
    RESTART_THRESHOLD = 2
    WINDOW_MINUTES = 5
    SUSPICIOUS_POLICY_DECISIONS = {"forced", "deny", "denied", "block", "blocked"}

    restarts_by_session: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        if not is_openclaw_event(event, "restart"):
            continue
        session_key = openclaw_session_key(event)
        if session_key:
            restarts_by_session[session_key].append(event)

    detected = set()
    for restart_events in restarts_by_session.values():
        ordered = sorted(restart_events, key=lambda event: event["timestamp"])
        window_start = 0
        for window_end, event in enumerate(ordered):
            while minutes_between(ordered[window_start], event) > WINDOW_MINUTES:
                window_start += 1
            candidate_events = ordered[window_start:window_end + 1]
            if len(candidate_events) < RESTART_THRESHOLD:
                continue

            has_suspicious_context = any(
                str(candidate.get("policy_decision") or "").lower() in SUSPICIOUS_POLICY_DECISIONS
                or str(candidate.get("status") or "").lower() in {"failed", "error", "blocked"}
                or str(candidate.get("severity_hint") or "").lower() in {"medium", "high", "critical"}
                for candidate in candidate_events
            )
            if not has_suspicious_context:
                continue

            if len(candidate_events) >= RESTART_THRESHOLD:
                for candidate in ordered[window_start:window_end + 1]:
                    detected.add(candidate["event_id"])

    return list(detected)


def detect_openclaw_data_exfiltration(events: List[Dict]) -> List[str]:
    """
    OpenClaw-specific data exfiltration detection.
    Flags high-confidence command patterns that indicate staging and outbound transfer.
    """
    exfil_patterns = [
        r"(?i)curl\s+.*\s-F\s+.*@",
        r"(?i)wget\s+--post-file",
        r"(?i)rclone\s+(copy|sync)\s+.*(remote:|s3:|gdrive:)",
        r"(?i)rsync\s+.*\s+\w+@[^\s:]+:",
        r"(?i)nc\s+[^\s]+\s+\d+\s*<\s*[^\s]+",
        r"(?i)(tar|zip)\s+.*&&\s*(curl|wget)\s+",
        r"(?i)python\s+-c\s+.*(requests|httpx).*post",
        r"(?i)exfil(trat(e|ion))?",
    ]

    detected = []
    for event in events:
        if not is_openclaw_exec_like(event):
            continue

        command = extract_command_text(event)
        if not command:
            continue

        if any(re.search(pattern, command) for pattern in exfil_patterns):
            detected.append(event["event_id"])

    return detected


def detect_openclaw_malware_presence(events: List[Dict]) -> List[str]:
    """
    OpenClaw-specific malware presence detection.
    Flags command-line or skill indicators tied to known malware tooling/families.
    """
    malware_patterns = [
        r"(?i)\bmimikatz\b",
        r"(?i)\bcobalt\s*strike\b|\bbeacon\b",
        r"(?i)\bmeterpreter\b|\bmsfvenom\b|\bmetasploit\b",
        r"(?i)\bxmrig\b|\bminerd\b|\bcoinhive\b",
        r"(?i)\bransom(ware)?\b|\bencrypt(or|ion)\b",
        r"(?i)\bnjrat\b|\bquasar\b|\bdarkcomet\b|\bremcos\b",
        r"(?i)invoke-mimikatz|sekurlsa::logonpasswords",
    ]

    detected = []
    for event in events:
        if is_openclaw_exec_like(event):
            command = extract_command_text(event)
            if command and any(re.search(pattern, command) for pattern in malware_patterns):
                detected.append(event["event_id"])
                continue

        if is_openclaw_event(event, "skills"):
            skill_key = str(event.get("skill_key") or "")
            skill_source = str(event.get("skill_source") or "")
            combined = f"{skill_key} {skill_source}"
            if any(re.search(pattern, combined) for pattern in malware_patterns):
                detected.append(event["event_id"])

    return detected


# ═══ Anomaly Detection ═══════════════════════════════════════════════════════

class AnomalyDetector:
    """
    Z-score based anomaly detection on event metrics.
    The agent can change the algorithm, thresholds, or metrics tracked.
    """

    def __init__(self, z_threshold: float = ANOMALY_Z_THRESHOLD):
        self.z_threshold = z_threshold
        self.metrics: Dict[str, List[float]] = defaultdict(list)

    def add_and_check(self, metric_name: str, value: float) -> Optional[str]:
        """Add a value and return 'anomaly' if it's an outlier."""
        self.metrics[metric_name].append(value)
        history = self.metrics[metric_name]

        if len(history) < ANOMALY_MIN_SAMPLES:
            return None

        avg = sum(history) / len(history)
        variance = sum((x - avg) ** 2 for x in history) / len(history)
        std_dev = math.sqrt(variance) if variance > 0 else 0.001
        z_score = (value - avg) / std_dev

        if abs(z_score) > self.z_threshold:
            return "anomaly"
        return None


# ═══ Finding Shaping ══════════════════════════════════════════════════════════

RULE_FINDING_PROFILES: Dict[str, Dict[str, Any]] = {
    "RULE-201": {
        "title": "macOS authentication failures",
        "severity": "medium",
        "severity_score": 56,
        "summary": "Repeated failed authentication attempts were observed on a macOS host over a short interval.",
        "recommended_actions": [
            "Review the target account and process for expected login activity.",
            "Check whether the source process or terminal session was user-initiated or scripted.",
            "If the failures are unexpected, lock or reset the account and inspect adjacent successful logins.",
        ],
    },
    "RULE-202": {
        "title": "macOS sudo misuse",
        "severity": "high",
        "severity_score": 72,
        "summary": "Suspicious sudo or privilege-escalation behavior was observed on a macOS host.",
        "recommended_actions": [
            "Validate whether the sudo attempt was expected administrative activity.",
            "Review shell history, terminal parent processes, and affected accounts for abuse.",
            "Tighten sudoers scope or require stronger approval controls if the behavior is not expected.",
        ],
    },
    "RULE-203": {
        "title": "macOS persistence creation",
        "severity": "high",
        "severity_score": 78,
        "summary": "A macOS persistence mechanism such as a LaunchAgent, LaunchDaemon, or related autorun path was touched.",
        "recommended_actions": [
            "Inspect the referenced plist, login item, or autorun path for unexpected executables.",
            "Disable and remove any unauthorized persistence entry and collect the backing binary for review.",
            "Check whether the same user or host recently executed suspicious installers or scripts.",
        ],
    },
    "RULE-204": {
        "title": "macOS unusual script execution",
        "severity": "medium",
        "severity_score": 61,
        "summary": "Potentially risky shell or script execution was detected on a macOS host.",
        "recommended_actions": [
            "Review the full command line, parent process, and touched paths for staging behavior.",
            "Quarantine or block downloaded scripts if they were not part of an approved workflow.",
            "Hunt for related outbound connections or follow-on persistence creation from the same user context.",
        ],
    },
    "RULE-205": {
        "title": "macOS suspicious binary execution",
        "severity": "high",
        "severity_score": 74,
        "summary": "A suspicious or potentially unsigned binary executed from a risky macOS path.",
        "recommended_actions": [
            "Validate the binary signature, notarization status, and provenance before re-running it.",
            "Collect the file hash and execution path, then compare against known-good software inventory.",
            "If unapproved, remove the binary and investigate how it landed on the host.",
        ],
    },
    "RULE-206": {
        "title": "macOS suspicious system activity",
        "severity": "high",
        "severity_score": 76,
        "summary": "Potential security-control tampering or unusual system-level activity was detected on macOS.",
        "recommended_actions": [
            "Review whether Gatekeeper, quarantine, TCC, or system extension settings were changed intentionally.",
            "Re-enable any disabled protections and verify the initiating user and process tree.",
            "Inspect the host for follow-on persistence, downloaded payloads, or user-approved exceptions.",
        ],
    },
}


def _stable_detection_finding_id(rule_id: str, event_ids: List[str]) -> str:
    digest = hashlib.blake2s(
        f"{rule_id}|{'|'.join(sorted(event_ids))}".encode("utf-8"), digest_size=8
    ).hexdigest()
    return f"SCX-{digest.upper()}"



def _format_evidence_line(event: Dict[str, Any]) -> str:
    actor = _event_actor_user(event) or "unknown-user"
    process = _event_actor_process(event) or event.get("source") or event.get("sourcetype") or "unknown-process"
    message = _event_message(event) or event.get("event_type") or "no message"
    timestamp = str(event.get("timestamp") or "unknown-time")
    return f"{timestamp} | {actor} | {process} | {message}"[:320]



def build_detection_findings(events: List[Dict[str, Any]], rule_results: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    events_by_id = {str(event.get("event_id")): event for event in events if event.get("event_id")}
    rule_by_id = {rule["id"]: rule for rule in DETECTION_RULES}
    findings: List[Dict[str, Any]] = []

    for rule_id, detected_ids in rule_results.items():
        if not detected_ids or rule_id not in RULE_FINDING_PROFILES:
            continue
        matched_events = [events_by_id[event_id] for event_id in detected_ids if event_id in events_by_id]
        if not matched_events:
            continue

        profile = RULE_FINDING_PROFILES[rule_id]
        rule = rule_by_id.get(rule_id, {"name": rule_id, "mitre": ""})
        ordered = sorted(matched_events, key=lambda event: str(event.get("timestamp", "")))
        evidence = [_format_evidence_line(event) for event in ordered[:5]]
        top_users = [user for user, _count in Counter((_event_actor_user(event) or "unknown") for event in ordered).most_common(3)]
        top_processes = [proc for proc, _count in Counter((_event_actor_process(event) or "unknown") for event in ordered).most_common(3)]

        severity_score = max(
            int(profile["severity_score"]),
            min(100, int(profile["severity_score"]) + max(0, len(ordered) - 1) * 2),
        )

        findings.append({
            "finding_id": _stable_detection_finding_id(rule_id, [event["event_id"] for event in ordered]),
            "rule_id": rule_id,
            "rule_ids": [rule_id],
            "rule_name": rule.get("name", rule_id),
            "rule_names": [rule.get("name", rule_id)],
            "mitre": rule.get("mitre", ""),
            "mitre_ids": [rule.get("mitre", "")],
            "platform": "macos",
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "status": "open",
            "disposition": "unreviewed",
            "title": profile["title"],
            "summary": profile["summary"],
            "severity": profile["severity"],
            "severity_score": severity_score,
            "event_count": len(ordered),
            "event_ids": [event["event_id"] for event in ordered],
            "first_seen": str(ordered[0].get("timestamp")),
            "last_seen": str(ordered[-1].get("timestamp")),
            "affected_users": top_users,
            "affected_processes": top_processes,
            "evidence": evidence,
            "events": ordered[:10],
            "recommended_actions": list(profile["recommended_actions"]),
        })

    findings.sort(key=lambda finding: (-int(finding["severity_score"]), str(finding["first_seen"])))
    return findings


# ═══ Main Detection Pipeline ═════════════════════════════════════════════════

# Registry of all active detection rules
DETECTION_RULES = [
    {"id": "RULE-001", "name": "Brute Force",           "mitre": "T1110",     "fn": detect_brute_force},
    {"id": "RULE-002", "name": "DNS Exfiltration",       "mitre": "T1048.003", "fn": detect_dns_exfiltration},
    {"id": "RULE-003", "name": "C2 Beaconing",           "mitre": "T1071",     "fn": detect_c2_beaconing},
    {"id": "RULE-004", "name": "Lateral Movement (SMB)", "mitre": "T1021.002", "fn": detect_lateral_movement},
    {"id": "RULE-005", "name": "PowerShell Abuse",       "mitre": "T1059.001", "fn": detect_powershell_abuse},
    {"id": "RULE-006", "name": "Privilege Escalation",   "mitre": "T1068",     "fn": detect_privilege_escalation},
    {"id": "RULE-007", "name": "Fileless LOLBins",       "mitre": "T1218",     "fn": detect_fileless_lolbins},
    {"id": "RULE-201", "name": "macOS Authentication Failures", "mitre": "T1110", "fn": detect_macos_authentication_failures},
    {"id": "RULE-202", "name": "macOS Sudo Misuse",            "mitre": "T1548.003", "fn": detect_macos_sudo_misuse},
    {"id": "RULE-203", "name": "macOS Persistence Creation",   "mitre": "T1543", "fn": detect_macos_persistence_creation},
    {"id": "RULE-204", "name": "macOS Unusual Script Execution", "mitre": "T1059", "fn": detect_macos_unusual_script_execution},
    {"id": "RULE-205", "name": "macOS Suspicious Binary Execution", "mitre": "T1553", "fn": detect_macos_suspicious_binary_execution},
    {"id": "RULE-206", "name": "macOS Suspicious System Activity", "mitre": "T1562", "fn": detect_macos_suspicious_system_activity},
    {"id": "RULE-101", "name": "OpenClaw Dangerous Exec",      "mitre": "T1059", "fn": detect_openclaw_dangerous_exec},
    {"id": "RULE-102", "name": "OpenClaw Sensitive Config",    "mitre": "T1098", "fn": detect_openclaw_sensitive_config_change},
    {"id": "RULE-103", "name": "OpenClaw Skill Source Drift",  "mitre": "T1587", "fn": detect_openclaw_skill_source_drift},
    {"id": "RULE-104", "name": "OpenClaw Policy Denials",      "mitre": "T1622", "fn": detect_openclaw_repeated_policy_denials},
    {"id": "RULE-105", "name": "OpenClaw Tool Burst",          "mitre": "T1082", "fn": detect_openclaw_tool_burst},
    {"id": "RULE-106", "name": "OpenClaw Pairing Churn",       "mitre": "T1078", "fn": detect_openclaw_pairing_churn},
    {"id": "RULE-107", "name": "OpenClaw Subagent Fanout",     "mitre": "T1098", "fn": detect_openclaw_subagent_fanout},
    {"id": "RULE-108", "name": "OpenClaw Restart Loop",        "mitre": "T1529", "fn": detect_openclaw_restart_loop},
    {"id": "RULE-109", "name": "OpenClaw Data Exfiltration",   "mitre": "T1048", "fn": detect_openclaw_data_exfiltration},
    {"id": "RULE-110", "name": "OpenClaw Malware Presence",    "mitre": "T1204", "fn": detect_openclaw_malware_presence},
]


def run_detection(events: List[Dict]) -> Dict[str, Any]:
    """
    Run all detection rules against the event set.

    Returns:
        {
            "detected_event_ids": [list of event_ids flagged as malicious],
            "rule_results": {rule_id: [event_ids], ...},
            "total_events": int,
            "total_detections": int,
        }
    """
    all_detected = set()
    rule_results = {}

    for rule in DETECTION_RULES:
        try:
            detected_ids = rule["fn"](events)
            rule_results[rule["id"]] = detected_ids
            all_detected.update(detected_ids)
        except (KeyError, TypeError, ValueError, ZeroDivisionError, re.error) as e:
            print(f"  ⚠️  Rule {rule['id']} ({rule['name']}) error: {e}")
            rule_results[rule["id"]] = []

    findings = build_detection_findings(events, rule_results)

    return {
        "detected_event_ids": list(all_detected),
        "rule_results": rule_results,
        "total_events": len(events),
        "total_detections": len(all_detected),
        "findings": findings,
    }
