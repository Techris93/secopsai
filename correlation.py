"""Enhanced cross-platform correlation rules for SecOpsAI.

This module provides correlation between macOS host telemetry and OpenClaw events
to detect multi-stage attacks that span both application and host layers.
"""

from typing import Dict, List, Any, Optional, Set, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
import re


def parse_timestamp(ts: str) -> Optional[datetime]:
    """Parse ISO timestamp string to datetime."""
    if not ts:
        return None
    try:
        # Handle various formats
        ts = ts.replace("Z", "+00:00")
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def correlate_macos_with_openclaw(
    macos_events: List[Dict],
    openclaw_events: List[Dict],
    time_window_minutes: int = 15
) -> List[Dict]:
    """
    Detect suspicious patterns that correlate macOS host events with OpenClaw activity.
    
    Patterns detected:
    1. Host auth failure + OpenClaw sensitive action (compromised account usage)
    2. Host exfil pattern + OpenClaw data export (coordinated data theft)
    3. Host persistence creation + OpenClaw config change (establishing foothold)
    4. Host security control disabled + OpenClaw policy change (defense evasion)
    5. Host suspicious execution + OpenClaw tool burst (automated attack)
    6. Host credential access + OpenClaw secret access (credential harvesting)
    
    Returns:
        List of correlation findings with type, confidence, and related events.
    """
    correlations = []
    window = timedelta(minutes=time_window_minutes)
    
    # Index events by timestamp for efficient lookup
    macos_by_time = [(e, parse_timestamp(e.get("timestamp"))) for e in macos_events]
    openclaw_by_time = [(e, parse_timestamp(e.get("timestamp"))) for e in openclaw_events]
    
    # Filter out events with unparseable timestamps
    macos_by_time = [(e, ts) for e, ts in macos_by_time if ts]
    openclaw_by_time = [(e, ts) for e, ts in openclaw_by_time if ts]
    
    # Pattern 1: Host authentication failure followed by OpenClaw sensitive action
    correlations.extend(_correlate_auth_then_openclaw_sensitive(
        macos_by_time, openclaw_by_time, window
    ))
    
    # Pattern 2: Host suspicious network activity + OpenClaw data export
    correlations.extend(_correlate_network_then_export(
        macos_by_time, openclaw_by_time, window
    ))
    
    # Pattern 3: Host persistence + OpenClaw config change
    correlations.extend(_correlate_persistence_then_config(
        macos_by_time, openclaw_by_time, window
    ))
    
    # Pattern 4: Host security control disabled + OpenClaw policy change
    correlations.extend(_correlate_defense_evasion(
        macos_by_time, openclaw_by_time, window
    ))
    
    # Pattern 5: Host suspicious execution + OpenClaw tool burst
    correlations.extend(_correlate_execution_then_burst(
        macos_by_time, openclaw_by_time, window
    ))
    
    # Pattern 6: Host credential access + OpenClaw secret access
    correlations.extend(_correlate_credential_harvest(
        macos_by_time, openclaw_by_time, window
    ))
    
    return correlations


def _correlate_auth_then_openclaw_sensitive(
    macos_by_time: List[Tuple[Dict, datetime]],
    openclaw_by_time: List[Tuple[Dict, datetime]],
    window: timedelta
) -> List[Dict]:
    """
    Pattern: Failed macOS auth followed by OpenClaw sensitive action.
    Indicates potential account compromise.
    """
    correlations = []
    
    # Find macOS auth failures
    auth_failures = [
        (e, ts) for e, ts in macos_by_time
        if e.get("event_type") == "auth_failure"
        or "auth" in str(e.get("event_type", ""))
        or e.get("outcome") == "failure"
    ]
    
    # Find OpenClaw sensitive actions
    sensitive_actions = [
        (e, ts) for e, ts in openclaw_by_time
        if _is_openclaw_sensitive_action(e)
    ]
    
    for mac_event, mac_ts in auth_failures:
        user = _get_actor_user(mac_event)
        
        for oc_event, oc_ts in sensitive_actions:
            # Check temporal proximity (OpenClaw after macOS, within window)
            if timedelta(0) <= oc_ts - mac_ts <= window:
                # Check user correlation if available
                oc_user = _get_openclaw_user(oc_event)
                
                confidence = "medium"
                if user and oc_user and user.lower() == oc_user.lower():
                    confidence = "high"
                
                correlations.append({
                    "correlation_type": "auth_compromise_then_abuse",
                    "description": f"macOS auth failure followed by OpenClaw sensitive action",
                    "confidence": confidence,
                    "time_delta_minutes": (oc_ts - mac_ts).total_seconds() / 60,
                    "macos_event": mac_event,
                    "openclaw_event": oc_event,
                    "user_context": user or oc_user,
                    "severity": "high",
                    "mitre_techniques": ["T1078", "T1098"],
                })
    
    return correlations


def _correlate_network_then_export(
    macos_by_time: List[Tuple[Dict, datetime]],
    openclaw_by_time: List[Tuple[Dict, datetime]],
    window: timedelta
) -> List[Dict]:
    """
    Pattern: macOS suspicious network activity followed by OpenClaw data export.
    Indicates potential data exfiltration.
    """
    correlations = []
    
    # Find macOS network anomalies
    network_events = [
        (e, ts) for e, ts in macos_by_time
        if e.get("event_type") == "network_connection"
        or "network" in e.get("risk_tags", [])
        or _has_suspicious_network_pattern(e)
    ]
    
    # Find OpenClaw data export patterns
    export_events = [
        (e, ts) for e, ts in openclaw_by_time
        if _is_data_export_event(e)
    ]
    
    for mac_event, mac_ts in network_events:
        for oc_event, oc_ts in export_events:
            if timedelta(0) <= oc_ts - mac_ts <= window:
                correlations.append({
                    "correlation_type": "potential_exfiltration",
                    "description": "Suspicious host network activity followed by OpenClaw data export",
                    "confidence": "high",
                    "time_delta_minutes": (oc_ts - mac_ts).total_seconds() / 60,
                    "macos_event": mac_event,
                    "openclaw_event": oc_event,
                    "severity": "critical",
                    "mitre_techniques": ["T1048", "T1041"],
                })
    
    return correlations


def _correlate_persistence_then_config(
    macos_by_time: List[Tuple[Dict, datetime]],
    openclaw_by_time: List[Tuple[Dict, datetime]],
    window: timedelta
) -> List[Dict]:
    """
    Pattern: macOS persistence creation followed by OpenClaw config change.
    Indicates establishment of persistent access.
    """
    correlations = []
    
    # Find macOS persistence events
    persistence_events = [
        (e, ts) for e, ts in macos_by_time
        if e.get("event_type") in ["persistence_created", "persistence_created"]
        or e.get("persistence_category") is not None
        or "persistence" in e.get("risk_tags", [])
    ]
    
    # Find OpenClaw config changes
    config_events = [
        (e, ts) for e, ts in openclaw_by_time
        if _is_config_change_event(e)
    ]
    
    for mac_event, mac_ts in persistence_events:
        for oc_event, oc_ts in config_events:
            if timedelta(0) <= oc_ts - mac_ts <= window:
                persistence_type = mac_event.get("persistence_category", "unknown")
                
                correlations.append({
                    "correlation_type": "persistence_then_config_change",
                    "description": f"Host persistence ({persistence_type}) followed by OpenClaw config change",
                    "confidence": "medium",
                    "time_delta_minutes": (oc_ts - mac_ts).total_seconds() / 60,
                    "macos_event": mac_event,
                    "openclaw_event": oc_event,
                    "persistence_type": persistence_type,
                    "severity": "high",
                    "mitre_techniques": ["T1543", "T1098"],
                })
    
    return correlations


def _correlate_defense_evasion(
    macos_by_time: List[Tuple[Dict, datetime]],
    openclaw_by_time: List[Tuple[Dict, datetime]],
    window: timedelta
) -> List[Dict]:
    """
    Pattern: macOS security control disabled + OpenClaw policy change.
    Indicates defense evasion attempt.
    """
    correlations = []
    
    # Find macOS security control tampering
    tamper_events = [
        (e, ts) for e, ts in macos_by_time
        if e.get("event_type") == "security_control_disabled"
        or "security_evasion" in e.get("risk_tags", [])
        or _is_security_tampering(e)
    ]
    
    # Find OpenClaw policy changes
    policy_events = [
        (e, ts) for e, ts in openclaw_by_time
        if _is_policy_change_event(e)
    ]
    
    for mac_event, mac_ts in tamper_events:
        for oc_event, oc_ts in policy_events:
            if abs((oc_ts - mac_ts).total_seconds()) <= window.total_seconds():
                correlations.append({
                    "correlation_type": "defense_evasion",
                    "description": "Host security control disabled with OpenClaw policy change",
                    "confidence": "high",
                    "time_delta_minutes": abs((oc_ts - mac_ts).total_seconds()) / 60,
                    "macos_event": mac_event,
                    "openclaw_event": oc_event,
                    "severity": "critical",
                    "mitre_techniques": ["T1562", "T1622"],
                })
    
    return correlations


def _correlate_execution_then_burst(
    macos_by_time: List[Tuple[Dict, datetime]],
    openclaw_by_time: List[Tuple[Dict, datetime]],
    window: timedelta
) -> List[Dict]:
    """
    Pattern: macOS suspicious execution followed by OpenClaw tool burst.
    Indicates potential automated attack.
    """
    correlations = []
    
    # Find macOS suspicious execution
    exec_events = [
        (e, ts) for e, ts in macos_by_time
        if e.get("event_type") in ["script_execution", "process_execution"]
        and ("suspicious" in e.get("risk_tags", [])
             or "pipe_to_shell" in e.get("risk_tags", []))
    ]
    
    # Find OpenClaw tool bursts (high-frequency tool usage)
    burst_events = [
        (e, ts) for e, ts in openclaw_by_time
        if _is_tool_burst_event(e)
    ]
    
    for mac_event, mac_ts in exec_events:
        for oc_event, oc_ts in burst_events:
            if timedelta(0) <= oc_ts - mac_ts <= window:
                correlations.append({
                    "correlation_type": "suspicious_execution_then_burst",
                    "description": "Host suspicious execution followed by OpenClaw tool burst",
                    "confidence": "medium",
                    "time_delta_minutes": (oc_ts - mac_ts).total_seconds() / 60,
                    "macos_event": mac_event,
                    "openclaw_event": oc_event,
                    "severity": "high",
                    "mitre_techniques": ["T1059", "T1082"],
                })
    
    return correlations


def _correlate_credential_harvest(
    macos_by_time: List[Tuple[Dict, datetime]],
    openclaw_by_time: List[Tuple[Dict, datetime]],
    window: timedelta
) -> List[Dict]:
    """
    Pattern: macOS credential access followed by OpenClaw secret access.
    Indicates credential harvesting and usage.
    """
    correlations = []
    
    # Find macOS credential access
    cred_events = [
        (e, ts) for e, ts in macos_by_time
        if e.get("event_type") == "keychain_access"
        or "credentials" in e.get("risk_tags", [])
        or e.get("mitre_technique") == "T1003"
    ]
    
    # Find OpenClaw secret access
    secret_events = [
        (e, ts) for e, ts in openclaw_by_time
        if _is_secret_access_event(e)
    ]
    
    for mac_event, mac_ts in cred_events:
        for oc_event, oc_ts in secret_events:
            if timedelta(0) <= oc_ts - mac_ts <= window:
                correlations.append({
                    "correlation_type": "credential_harvest_and_use",
                    "description": "Host credential access followed by OpenClaw secret/tool access",
                    "confidence": "high",
                    "time_delta_minutes": (oc_ts - mac_ts).total_seconds() / 60,
                    "macos_event": mac_event,
                    "openclaw_event": oc_event,
                    "severity": "critical",
                    "mitre_techniques": ["T1003", "T1552"],
                })
    
    return correlations


# Helper functions for correlation logic

def _is_openclaw_sensitive_action(event: Dict) -> bool:
    """Check if an OpenClaw event represents a sensitive action."""
    event_type = str(event.get("sourcetype", "")).lower()
    tool_name = str(event.get("tool_name", "")).lower()
    message = str(event.get("message", "")).lower()
    
    sensitive_tools = {
        "exec", "run_in_terminal", "execute_command", "shell", "bash", "sh",
        "write", "edit", "modify", "delete", "remove"
    }
    
    if any(st in tool_name for st in sensitive_tools):
        return True
    
    sensitive_patterns = re.compile(
        r"(?i)(config.*change|policy.*change|credential|secret|password|key)"
    )
    if sensitive_patterns.search(message):
        return True
    
    return False


def _is_data_export_event(event: Dict) -> bool:
    """Check if an OpenClaw event represents data export."""
    message = str(event.get("message", "")).lower()
    command = str(event.get("command", "")).lower()
    tool_name = str(event.get("tool_name", "")).lower()
    
    export_indicators = [
        r"(?i)\b(curl|wget)\b.*\b(-o|--output|-d|--data)\b",
        r"(?i)\brsync\b.*\b\w+@\b",
        r"(?i)\bscp\b.*\b\w+@\b",
        r"(?i)\brclone\b",
        r"(?i)exfil",
        r"(?i)upload.*remote",
        r"(?i)send.*to.*server",
    ]
    
    combined = f"{message} {command} {tool_name}"
    return any(re.search(pattern, combined) for pattern in export_indicators)


def _is_config_change_event(event: Dict) -> bool:
    """Check if an OpenClaw event represents a configuration change."""
    message = str(event.get("message", "")).lower()
    tool_name = str(event.get("tool_name", "")).lower()
    
    return any(x in message or x in tool_name for x in [
        "config", "setting", "policy", "permission", "acl",
        "add_member", "remove_member", "update", "patch"
    ])


def _is_policy_change_event(event: Dict) -> bool:
    """Check if an OpenClaw event represents a policy change."""
    message = str(event.get("message", "")).lower()
    policy_decision = str(event.get("policy_decision", "")).lower()
    
    return (
        "policy" in message
        or policy_decision in ["allowed", "denied", "blocked"]
        or "approval" in message
    )


def _is_tool_burst_event(event: Dict) -> bool:
    """Check if an OpenClaw event indicates high-frequency tool usage."""
    # Look for tool burst indicators in metadata
    metadata = event.get("metadata", {})
    if metadata.get("tool_count", 0) > 5:
        return True
    
    message = str(event.get("message", "")).lower()
    return "burst" in message or "rapid" in message or "multiple" in message


def _is_secret_access_event(event: Dict) -> bool:
    """Check if an OpenClaw event represents secret/credential access."""
    message = str(event.get("message", "")).lower()
    tool_name = str(event.get("tool_name", "")).lower()
    
    return any(x in message or x in tool_name for x in [
        "secret", "credential", "password", "key", "token",
        "vault", "kms", "encrypt", "decrypt"
    ])


def _has_suspicious_network_pattern(event: Dict) -> bool:
    """Check if a macOS event has suspicious network indicators."""
    message = str(event.get("message", "")).lower()
    process = str(event.get("actor", {}).get("process", "")).lower()
    
    patterns = [
        r"(?i)\|\s*(nc|netcat|bash|sh)",
        r"(?i)curl.*\|.*bash",
        r"(?i)wget.*\|.*bash",
        r"(?i)reverse.*shell",
        r"(?i)bind.*shell",
    ]
    
    combined = f"{message} {process}"
    return any(re.search(pattern, combined) for pattern in patterns)


def _is_security_tampering(event: Dict) -> bool:
    """Check if a macOS event represents security control tampering."""
    message = str(event.get("message", "")).lower()
    
    tamper_indicators = [
        "spctl", "gatekeeper", "csrutil", "sip", "tccutil",
        "xattr -d", "quarantine", "disable"
    ]
    
    return any(ind in message for ind in tamper_indicators)


def _get_actor_user(event: Dict) -> Optional[str]:
    """Extract user from event actor field."""
    actor = event.get("actor", {})
    return actor.get("user") or actor.get("username")


def _get_openclaw_user(event: Dict) -> Optional[str]:
    """Extract user from OpenClaw event."""
    return (
        event.get("requester_user")
        or event.get("user")
        or event.get("session_user")
    )


# Original correlation functions (kept for backwards compatibility)

def correlate_by_ip(findings: List[Dict], time_window_minutes: int = 60) -> List[Dict]:
    """
    Detect suspicious activity: same IP appearing on multiple platforms.
    
    Returns correlated findings with cross_platform flag.
    """
    by_ip = defaultdict(list)
    
    for finding in findings:
        actor_ip = finding.get("actor", {}).get("ip")
        if actor_ip:
            by_ip[actor_ip].append(finding)
        
        target_ip = finding.get("target", {}).get("ip")
        if target_ip:
            by_ip[target_ip].append(finding)
    
    correlations = []
    for ip, ip_findings in by_ip.items():
        platforms = set(f.get("platform") for f in ip_findings)
        if len(platforms) > 1:
            correlations.append({
                "correlation_type": "cross_platform_ip",
                "ip": ip,
                "platforms": list(platforms),
                "findings": ip_findings,
                "severity": "high",
                "description": f"IP {ip} seen on {len(platforms)} platforms: {', '.join(platforms)}"
            })
    
    return correlations


def correlate_by_user(findings: List[Dict], time_window_minutes: int = 60) -> List[Dict]:
    """
    Detect lateral movement: same user active on multiple platforms.
    """
    by_user = defaultdict(lambda: defaultdict(list))
    
    for finding in findings:
        user = finding.get("actor", {}).get("user")
        platform = finding.get("platform")
        if user and platform:
            by_user[user][platform].append(finding)
    
    correlations = []
    for user, platforms in by_user.items():
        if len(platforms) > 1:
            all_findings = []
            for pf in platforms.values():
                all_findings.extend(pf)
            
            correlations.append({
                "correlation_type": "cross_platform_user",
                "user": user,
                "platforms": list(platforms.keys()),
                "findings": all_findings,
                "severity": "critical" if any(f.get("severity") == "critical" for f in all_findings) else "high",
                "description": f"User {user} active on {len(platforms)} platforms"
            })
    
    return correlations


def correlate_by_time(findings: List[Dict], time_window_minutes: int = 10) -> List[Dict]:
    """
    Detect attack chains: multiple events in short time window.
    """
    valid_findings = [f for f in findings if f.get("timestamp")]
    
    if len(valid_findings) < 3:
        return []
    
    sorted_findings = sorted(valid_findings, key=lambda x: x.get("timestamp", ""))
    
    correlations = []
    window = timedelta(minutes=time_window_minutes)
    
    for i, f1 in enumerate(sorted_findings):
        chain = [f1]
        ts1 = str(f1.get("timestamp", "")).replace("Z", "+00:00")
        try:
            f1_time = datetime.fromisoformat(ts1)
        except ValueError:
            continue
        
        for f2 in sorted_findings[i+1:]:
            ts2 = str(f2.get("timestamp", "")).replace("Z", "+00:00")
            try:
                f2_time = datetime.fromisoformat(ts2)
                if f2_time - f1_time <= window:
                    chain.append(f2)
            except ValueError:
                continue
        
        if len(chain) >= 3:
            platforms = set(f.get("platform") for f in chain if f.get("platform"))
            if len(platforms) > 1:
                correlations.append({
                    "correlation_type": "time_cluster",
                    "window_minutes": time_window_minutes,
                    "event_count": len(chain),
                    "platforms": list(platforms),
                    "findings": chain,
                    "severity": "high",
                    "description": f"{len(chain)} events in {time_window_minutes} min across {len(platforms)} platforms"
                })
    
    return correlations


def correlate_by_file_hash(findings: List[Dict]) -> List[Dict]:
    """
    Detect malware spread: same file hash on multiple systems.
    """
    by_hash = defaultdict(lambda: defaultdict(list))
    
    for finding in findings:
        file_hash = finding.get("target", {}).get("file_hash")
        platform = finding.get("platform")
        if file_hash and platform:
            by_hash[file_hash][platform].append(finding)
    
    correlations = []
    for file_hash, platforms in by_hash.items():
        if len(platforms) > 1:
            all_findings = []
            for pf in platforms.values():
                all_findings.extend(pf)
            
            correlations.append({
                "correlation_type": "cross_platform_file",
                "file_hash": file_hash,
                "platforms": list(platforms.keys()),
                "findings": all_findings,
                "severity": "critical",
                "description": f"File hash {file_hash[:16]}... seen on {len(platforms)} platforms"
            })
    
    return correlations


def run_correlation(findings: List[Dict]) -> Dict[str, Any]:
    """Run all correlation rules."""
    results = {
        "cross_platform_ip": correlate_by_ip(findings),
        "cross_platform_user": correlate_by_user(findings),
        "time_cluster": correlate_by_time(findings),
        "cross_platform_file": correlate_by_file_hash(findings),
        "total_correlations": 0
    }
    results["total_correlations"] = sum(len(v) for v in results.values() if isinstance(v, list))
    return results


def run_macos_openclaw_correlation(
    macos_events: List[Dict],
    openclaw_events: List[Dict]
) -> Dict[str, Any]:
    """
    Run macOS-OpenClaw cross-correlation analysis.
    
    Returns:
        Dictionary with correlation results and summary statistics.
    """
    correlations = correlate_macos_with_openclaw(macos_events, openclaw_events)
    
    # Group by correlation type
    by_type = defaultdict(list)
    for corr in correlations:
        by_type[corr["correlation_type"]].append(corr)
    
    # Calculate severity distribution
    severity_counts = defaultdict(int)
    for corr in correlations:
        severity_counts[corr.get("severity", "unknown")] += 1
    
    # Calculate confidence distribution
    confidence_counts = defaultdict(int)
    for corr in correlations:
        confidence_counts[corr.get("confidence", "unknown")] += 1
    
    return {
        "correlations": correlations,
        "by_type": dict(by_type),
        "total_correlations": len(correlations),
        "severity_distribution": dict(severity_counts),
        "confidence_distribution": dict(confidence_counts),
        "high_confidence_count": len([c for c in correlations if c.get("confidence") == "high"]),
    }
