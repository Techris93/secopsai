"""
SecOps Autoresearch — Detection Rules
The ONLY file the AI agent modifies.

Contains detection rules, anomaly thresholds, and scoring logic.
The agent iterates on these to maximize the F1-score computed by evaluate.py.

Current baseline: Rules ported from OpenSentinel with initial thresholds.
"""

import re
import math
from typing import List, Dict, Any, Optional
from collections import defaultdict


# ═══ Configuration ═══════════════════════════════════════════════════════════
# The agent can tune all of these values.

# Anomaly detector settings
ANOMALY_Z_THRESHOLD = 2.5
ANOMALY_MIN_SAMPLES = 10

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
    THRESHOLD = 5  # min failed attempts to flag
    WINDOW_MINUTES = 5

    # Group auth failures by source IP
    failures_by_ip: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        if (event.get("sourcetype") == "auth" and
            event.get("action") == "failure"):
            failures_by_ip[event.get("src_ip", "")].append(event)

    detected = []
    for ip, fails in failures_by_ip.items():
        if len(fails) >= THRESHOLD:
            # Flag all events from this IP as malicious
            for event in fails:
                detected.append(event["event_id"])
            # Also flag any successful auth from same IP (compromised account)
            for event in events:
                if (event.get("src_ip") == ip and
                    event.get("sourcetype") == "auth" and
                    event.get("action") == "success" and
                    event["event_id"] not in detected):
                    detected.append(event["event_id"])

    return detected


def detect_dns_exfiltration(events: List[Dict]) -> List[str]:
    """
    T1048.003 — DNS Exfiltration
    Detects unusually long DNS queries indicating data exfiltration.
    """
    QUERY_LENGTH_THRESHOLD = 50
    MIN_SUSPICIOUS_QUERIES = 3  # from same source

    # Find long DNS queries grouped by source
    long_queries_by_src: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        if event.get("sourcetype") == "dns":
            query_len = event.get("query_length", len(event.get("query", "")))
            if query_len > QUERY_LENGTH_THRESHOLD:
                long_queries_by_src[event.get("src_ip", "")].append(event)

    detected = []
    for ip, queries in long_queries_by_src.items():
        if len(queries) >= MIN_SUSPICIOUS_QUERIES:
            for event in queries:
                detected.append(event["event_id"])

    return detected


def detect_c2_beaconing(events: List[Dict]) -> List[str]:
    """
    T1071 — C2 Beaconing
    Detects periodic outbound connections to the same destination.
    """
    MIN_CONNECTIONS = 15
    MAX_JITTER_RATIO = 0.3  # max coefficient of variation

    # Group outbound firewall events by (src, dest) pairs
    connections: Dict[str, List[Dict]] = defaultdict(list)
    for event in events:
        if (event.get("sourcetype") == "firewall" and
            event.get("direction") == "outbound" and
            event.get("action") == "allowed"):
            key = f"{event.get('src_ip')}:{event.get('dest_ip')}"
            connections[key].append(event)

    detected = []
    for key, conn_events in connections.items():
        if len(conn_events) >= MIN_CONNECTIONS:
            # Check for periodicity by analyzing inter-arrival times
            # Simple heuristic: many connections to same dest = suspicious
            for event in conn_events:
                detected.append(event["event_id"])

    return detected


def detect_lateral_movement(events: List[Dict]) -> List[str]:
    """
    T1021.002 — Lateral Movement via SMB
    Detects a single IP connecting to multiple internal hosts on port 445.
    """
    UNIQUE_DEST_THRESHOLD = 3

    # Group SMB connections by source
    smb_by_src: Dict[str, Dict[str, List[Dict]]] = defaultdict(lambda: defaultdict(list))
    for event in events:
        if (event.get("sourcetype") == "firewall" and
            event.get("dest_port") == 445):
            src = event.get("src_ip", "")
            dest = event.get("dest_ip", "")
            smb_by_src[src][dest].append(event)

    detected = []
    for src, destinations in smb_by_src.items():
        if len(destinations) >= UNIQUE_DEST_THRESHOLD:
            for dest_events in destinations.values():
                for event in dest_events:
                    detected.append(event["event_id"])

    return detected


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
    ESCALATION_COMMANDS = ["sudo", "su", "runas", "pkexec"]
    EXCLUDED_USERS = ["root", "SYSTEM", "admin"]

    detected = []
    for event in events:
        if event.get("action") == "escalation":
            user = event.get("user", "")
            if user not in EXCLUDED_USERS:
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

        mean = sum(history) / len(history)
        variance = sum((x - mean) ** 2 for x in history) / len(history)
        std_dev = math.sqrt(variance) if variance > 0 else 0.001
        z_score = (value - mean) / std_dev

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
        except Exception as e:
            print(f"  ⚠️  Rule {rule['id']} ({rule['name']}) error: {e}")
            rule_results[rule["id"]] = []

    return {
        "detected_event_ids": list(all_detected),
        "rule_results": rule_results,
        "total_events": len(events),
        "total_detections": len(all_detected),
    }
