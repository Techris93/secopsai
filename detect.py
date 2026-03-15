"""
SecOps Autoresearch — Detection Rules
The ONLY file the AI agent modifies.

Contains detection rules, anomaly thresholds, and scoring logic.
The agent iterates on these to maximize the F1-score computed by evaluate.py.

Current baseline: Rules ported from OpenSentinel with initial thresholds.
"""

import re
import math
from datetime import datetime
from typing import List, Dict, Any, Optional, Iterable
from collections import defaultdict


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
    RAPID_THRESHOLD = 6
    RAPID_WINDOW_MINUTES = 10
    SLOW_THRESHOLD = 3
    SLOW_MIN_SPAN_MINUTES = 30
    COMPROMISE_WINDOW_MINUTES = 20
    SOURCELESS_THRESHOLD = 8

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
    MIN_QUERIES_PER_DOMAIN = 5
    MIN_LABEL_LENGTH = 15
    MIN_ENTROPY = 3.0
    MIN_UNIQUE_LABEL_RATIO = 0.8
    FALLBACK_LABEL_LENGTH = 20
    FALLBACK_UNIQUE_RATIO = 0.7

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
    MIN_CONNECTIONS = 5
    MAX_BYTES_OUT = 600
    MAX_BYTES_IN = 250
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
    UNIQUE_DEST_THRESHOLD = 4
    WINDOW_MINUTES = 20
    MAX_AVERAGE_GAP_SECONDS = 240
    MAX_TRANSFER_BYTES = 100000

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


def detect_openclaw_dangerous_exec(events: List[Dict]) -> List[str]:
    """
    OpenClaw-specific dangerous exec detection.
    Flags obviously risky command execution patterns in OpenClaw exec tool usage.
    """
    suspicious_patterns = [
        r"(?i)curl\s+.*https?://.*\|\s*(bash|sh)",
        r"(?i)wget\s+.*https?://.*\|\s*(bash|sh)",
        r"(?i)\bnc\b.*\s-e\s",
        r"(?i)\bssh\s+root@",
        r"(?i)authorization:\s*bearer",
    ]

    detected = []
    for event in events:
        if not is_openclaw_event(event, "tool"):
            continue
        if event.get("tool_name") != "exec":
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
        if not event.get("denied") and event.get("status") not in {"blocked", "approval-unavailable"}:
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
        if not is_openclaw_event(event, "pairing"):
            continue
        session_key = openclaw_session_key(event)
        if session_key:
            pairing_by_session[session_key].append(event)

    detected = set()
    for pairing_events in pairing_by_session.values():
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
            if window_end - window_start + 1 >= RESTART_THRESHOLD:
                for candidate in ordered[window_start:window_end + 1]:
                    detected.add(candidate["event_id"])

    return list(detected)


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
    {"id": "RULE-101", "name": "OpenClaw Dangerous Exec",      "mitre": "T1059", "fn": detect_openclaw_dangerous_exec},
    {"id": "RULE-102", "name": "OpenClaw Sensitive Config",    "mitre": "T1098", "fn": detect_openclaw_sensitive_config_change},
    {"id": "RULE-103", "name": "OpenClaw Skill Source Drift",  "mitre": "T1587", "fn": detect_openclaw_skill_source_drift},
    {"id": "RULE-104", "name": "OpenClaw Policy Denials",      "mitre": "T1622", "fn": detect_openclaw_repeated_policy_denials},
    {"id": "RULE-105", "name": "OpenClaw Tool Burst",          "mitre": "T1082", "fn": detect_openclaw_tool_burst},
    {"id": "RULE-106", "name": "OpenClaw Pairing Churn",       "mitre": "T1078", "fn": detect_openclaw_pairing_churn},
    {"id": "RULE-107", "name": "OpenClaw Subagent Fanout",     "mitre": "T1098", "fn": detect_openclaw_subagent_fanout},
    {"id": "RULE-108", "name": "OpenClaw Restart Loop",        "mitre": "T1529", "fn": detect_openclaw_restart_loop},
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

    return {
        "detected_event_ids": list(all_detected),
        "rule_results": rule_results,
        "total_events": len(events),
        "total_detections": len(all_detected),
    }
