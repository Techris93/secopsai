"""Enhanced macOS adapter - collects comprehensive security events from unified logging."""

import json
import re
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional, Set

from adapters.base import BaseAdapter, AdapterRegistry


# Expanded log predicates for comprehensive macOS telemetry
MACOS_PREDICATES = [
    # Security subsystem (existing)
    'subsystem == "com.apple.security"',
    
    # Auth/Privilege (existing)
    'process == "sudo"',
    'process == "sshd"',
    'process == "loginwindow"',
    
    # TCC / Privacy (NEW)
    'subsystem == "com.apple.TCC"',
    'subsystem == "com.apple.privacy"',
    'process == "tccd"',
    
    # Gatekeeper / XProtect / MRT (NEW)
    'process == "syspolicyd"',
    'process == "XProtect"',
    'process == "MRT"',
    'subsystem == "com.apple.syspolicy"',
    'subsystem == "com.apple.quarantine"',
    
    # Launchd / Persistence (NEW)
    'process == "launchd"',
    'subsystem == "com.apple.launchd"',
    'process == "launchctl"',
    
    # Execution tracking (NEW)
    'subsystem == "com.apple.kernel.exec"',
    'subsystem == "com.apple.bsd.dir_helper"',
    
    # Authorization (NEW)
    'subsystem == "com.apple.Authorization"',
    'process == "authd"',
    'process == "securityd"',
    
    # System extensions / Kernel (NEW)
    'subsystem == "com.apple.systemextensions"',
    'subsystem == "com.apple.kextd"',
    'process == "kextd"',
    
    # Network (NEW)
    'subsystem == "com.apple.networkextension"',
    'process == "NEHelper"',
    'subsystem == "com.apple.networking.networkextension"',
    
    # Keychain / Credentials (NEW)
    'subsystem == "com.apple.securityd"',
    'process == "secinitd"',
    
    # Login/Session (NEW)
    'process == "loginwindow"',
    'process == "sessionlogoutd"',
    'subsystem == "com.apple.sessionlogoutd"',
]

# Event type patterns for classification
EVENT_TYPE_PATTERNS = {
    # Authentication events
    "auth_success": [
        re.compile(r"(?i)authentication (succeeded|successful|accepted)"),
        re.compile(r"(?i)login (succeeded|successful)"),
        re.compile(r"(?i)accepted.*password"),
    ],
    "auth_failure": [
        re.compile(r"(?i)authentication (failed|failure|denied|rejected)"),
        re.compile(r"(?i)login (failed|failure)"),
        re.compile(r"(?i)failed.*password"),
        re.compile(r"(?i)invalid.*credential"),
        re.compile(r"(?i)incorrect.*password"),
    ],
    "auth_attempt": [
        re.compile(r"(?i)authentication (attempt|requested)"),
        re.compile(r"(?i)loginwindow.*login"),
    ],
    
    # Privilege escalation
    "privilege_escalation": [
        re.compile(r"(?i)\bsudo\b"),
        re.compile(r"(?i)privilege escalation"),
        re.compile(r"(?i)authorization (granted|elevated)"),
    ],
    
    # Execution events
    "process_execution": [
        re.compile(r"(?i)execve?\s*\("),
        re.compile(r"(?i)process.*started"),
        re.compile(r"(?i)spawned.*process"),
    ],
    "script_execution": [
        re.compile(r"(?i)osascript|applescript"),
        re.compile(r"(?i)python\d?\s+-c"),
        re.compile(r"(?i)perl\s+-e"),
        re.compile(r"(?i)ruby\s+-e"),
        re.compile(r"(?i)bash\s+-c|sh\s+-c|zsh\s+-c"),
    ],
    
    # Persistence events
    "persistence_created": [
        re.compile(r"(?i)launchctl\s+(load|bootstrap|enable)"),
        re.compile(r"(?i)launchd.*started"),
        re.compile(r"(?i)created.*plist"),
        re.compile(r"(?i)login\s+item.*added"),
    ],
    "persistence_removed": [
        re.compile(r"(?i)launchctl\s+(unload|bootout|disable)"),
        re.compile(r"(?i)removed.*plist"),
    ],
    
    # TCC / Privacy
    "tcc_access": [
        re.compile(r"(?i)tcc.*access"),
        re.compile(r"(?i)privacy.*access"),
        re.compile(r"(?i)user\s+approved"),
    ],
    "tcc_denied": [
        re.compile(r"(?i)tcc.*denied"),
        re.compile(r"(?i)privacy.*denied"),
        re.compile(r"(?i)access\s+denied.*privacy"),
    ],
    "tcc_modified": [
        re.compile(r"(?i)tccutil\s+reset"),
        re.compile(r"(?i)tcc.*modified"),
        re.compile(r"(?i)privacy.*database"),
    ],
    
    # Security tool events
    "malware_blocked": [
        re.compile(r"(?i)xprotect.*detected"),
        re.compile(r"(?i)malware.*detected"),
        re.compile(r"(?i)gatekeeper.*blocked"),
        re.compile(r"(?i)quarantined.*threat"),
        re.compile(r"(?i)mrt.*removed"),
    ],
    "security_control_disabled": [
        re.compile(r"(?i)spctl\s+--master-disable"),
        re.compile(r"(?i)gatekeeper.*disabled"),
        re.compile(r"(?i)csrutil\s+disable"),
    ],
    "quarantine_modified": [
        re.compile(r"(?i)xattr.*quarantine"),
        re.compile(r"(?i)quarantine.*removed"),
        re.compile(r"(?i)com\.apple\.quarantine"),
    ],
    
    # Network events
    "network_connection": [
        re.compile(r"(?i)socket.*connected"),
        re.compile(r"(?i)network.*connection"),
    ],
    "firewall_event": [
        re.compile(r"(?i)firewall.*blocked"),
        re.compile(r"(?i)pfctl"),
        re.compile(r"(?i)packet\s+filter"),
    ],
    
    # Credential events
    "keychain_access": [
        re.compile(r"(?i)keychain.*access"),
        re.compile(r"(?i)secitem.*read"),
        re.compile(r"(?i)security\s+find"),
    ],
    "password_changed": [
        re.compile(r"(?i)password.*changed"),
        re.compile(r"(?i)passwd\s+"),
    ],
}

# Risk category mapping
RISK_CATEGORIES: Dict[str, List[str]] = {
    "persistence": [
        "persistence_created", "persistence_removed", "launchctl_load",
    ],
    "execution": [
        "process_execution", "script_execution", "shell_execution",
    ],
    "authentication": [
        "auth_success", "auth_failure", "auth_attempt", "privilege_escalation",
    ],
    "privilege": [
        "privilege_escalation", "sudo_usage", "admin_action",
    ],
    "privacy": [
        "tcc_access", "tcc_denied", "tcc_modified",
    ],
    "security_tools": [
        "malware_blocked", "security_control_disabled", "quarantine_modified",
    ],
    "network": [
        "network_connection", "firewall_event",
    ],
    "credentials": [
        "keychain_access", "password_changed",
    ],
}

# MITRE technique mapping
MITRE_MAPPING: Dict[str, str] = {
    "persistence_created": "T1543.001",
    "persistence_removed": "T1543.001",
    "privilege_escalation": "T1548.003",
    "script_execution": "T1059.002",
    "auth_failure": "T1110",
    "tcc_modified": "T1078",
    "security_control_disabled": "T1562.001",
    "malware_blocked": "T1204.002",
    "keychain_access": "T1003",
}


class MacOSAdapter(BaseAdapter):
    """Enhanced adapter for macOS security events with comprehensive coverage."""
    
    @property
    def name(self) -> str:
        return "macos"
    
    @property
    def version(self) -> str:
        return "2.0.0"
    
    def collect(self, start_time: Optional[datetime] = None,
                end_time: Optional[datetime] = None,
                **kwargs) -> Iterable[Dict[str, Any]]:
        """Collect macOS security events from multiple sources."""
        if not start_time:
            start_time = datetime.utcnow() - timedelta(hours=1)
        if not end_time:
            end_time = datetime.utcnow()
        
        # Calculate duration for log command
        delta = end_time - start_time
        hours = int(delta.total_seconds() / 3600)
        duration = f"{max(1, min(hours, 24))}h"
        
        # Collect from unified logging
        yield from self._collect_unified_logs(duration)
        
        # Collect from additional sources if available
        yield from self._collect_additional_telemetry()
    
    def stream(self, **kwargs) -> Iterable[Dict[str, Any]]:
        """Stream macOS events in real-time with expanded predicates."""
        # Build compound predicate for streaming
        predicate_parts = [
            'subsystem == "com.apple.security"',
            'subsystem == "com.apple.TCC"',
            'process == "sudo"',
            'process == "syspolicyd"',
            'process == "XProtect"',
        ]
        predicate = " OR ".join(predicate_parts)
        
        cmd = [
            "log", "stream",
            "--predicate", f'eventType == logEvent AND ({predicate})',
            "--style", "json"
        ]
        
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                normalized = self.normalize({"source": "log_stream", "raw": event})
                if normalized:
                    yield normalized
            except json.JSONDecodeError:
                continue
    
    def normalize(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert macOS event to enriched unified schema."""
        raw = raw_event.get("raw", {})
        
        # Handle case where raw is a list (from JSON array)
        if isinstance(raw, list):
            if len(raw) == 0:
                return None
            raw = raw[0]
        
        # Handle case where raw is still not a dict
        if not isinstance(raw, dict):
            return None
        
        message = self._extract_message(raw)
        event_type = self._classify_event_type(message, raw)
        
        # Extract process hierarchy
        process_info = self._extract_process_info(raw)
        
        # Extract actor and target
        actor = self._extract_actor(raw, process_info)
        target = self._extract_target(raw, message)
        
        # Determine outcome
        outcome = self._determine_outcome(message, raw)
        
        # Get risk tags
        risk_tags = self._get_risk_tags(event_type, message, raw)
        
        # Get categories
        persistence_cat = self._get_persistence_category(event_type, message)
        execution_cat = self._get_execution_category(event_type, message, raw)
        
        # Calculate confidence
        confidence = self._calculate_confidence(raw, event_type)
        
        # Get MITRE technique
        mitre_technique = MITRE_MAPPING.get(event_type, "")
        
        normalized = {
            # Core fields
            "timestamp": self._parse_timestamp(raw.get("timestamp")),
            "event_type": event_type,
            "platform": "macos",
            "source": "unified_logging",
            "source_subsystem": raw.get("subsystem") or raw.get("category"),
            "source_process": process_info.get("process_name"),
            "host": raw.get("host") or self.hostname,
            "event_id": self.generate_event_id(raw),
            
            # Actor information (enhanced)
            "actor": actor,
            
            # Target information (enhanced)
            "target": target,
            
            # Action and outcome
            "action": self._extract_action(event_type, message),
            "outcome": outcome,
            
            # Risk and categorization (NEW)
            "risk_tags": risk_tags,
            "persistence_category": persistence_cat,
            "execution_category": execution_cat,
            "mitre_technique": mitre_technique,
            
            # Confidence scoring (NEW)
            "confidence": confidence,
            "severity_hint": self._infer_severity(event_type, risk_tags, actor),
            
            # Extended metadata
            "metadata": {
                "macos_subsystem": raw.get("subsystem"),
                "macos_category": raw.get("category"),
                "macos_process": process_info.get("process_name"),
                "macos_pid": process_info.get("pid"),
                "macos_message": message,
                "log_level": raw.get("eventType"),
                "raw_event": raw,  # Keep raw for deep inspection
            }
        }
        
        return self.enrich_event(normalized)
    
    def _collect_unified_logs(self, duration: str) -> Iterable[Dict[str, Any]]:
        """Collect events from unified logging system."""
        for predicate in MACOS_PREDICATES:
            try:
                cmd = ["log", "show", "--predicate", predicate, "--style", "json", "--last", duration]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        # Try as JSON array first
                        data = json.loads(result.stdout)
                        if isinstance(data, list):
                            for event in data:
                                normalized = self.normalize({"source": "log", "raw": event, "predicate": predicate})
                                if normalized:
                                    yield normalized
                        else:
                            # Single object
                            normalized = self.normalize({"source": "log", "raw": data, "predicate": predicate})
                            if normalized:
                                yield normalized
                    except json.JSONDecodeError:
                        # Try line by line
                        for line in result.stdout.strip().split("\n"):
                            if not line:
                                continue
                            try:
                                event = json.loads(line)
                                normalized = self.normalize({"source": "log", "raw": event, "predicate": predicate})
                                if normalized:
                                    yield normalized
                            except json.JSONDecodeError:
                                continue
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
    
    def _collect_additional_telemetry(self) -> Iterable[Dict[str, Any]]:
        """Collect from additional macOS telemetry sources."""
        # Could add: audit logs, endpoint security events, etc.
        # For now, unified logging is the primary source
        return
        yield  # Make it a generator
    
    def _extract_message(self, raw: Dict[str, Any]) -> str:
        """Extract message from various macOS log formats."""
        # Try different message fields
        for key in ["eventMessage", "message", "formattedMessage", "messageType"]:
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""
    
    def _classify_event_type(self, message: str, raw: Dict[str, Any]) -> str:
        """Classify event type from message content."""
        # Check against patterns
        for event_type, patterns in EVENT_TYPE_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(message):
                    return event_type
        
        # Fallback classification based on subsystem/process
        subsystem = str(raw.get("subsystem", "")).lower()
        process = str(raw.get("process", "")).lower()
        
        if "tcc" in subsystem or process == "tccd":
            return "tcc_access"
        if "security" in subsystem:
            return "security_event"
        if process in ["sudo", "su", "dseditgroup"]:
            return "privilege_escalation"
        if process in ["sshd", "loginwindow", "sessionlogoutd"]:
            return "session_event"
        
        return "unknown"
    
    def _extract_process_info(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Extract process information from raw event."""
        info = {
            "process_name": raw.get("process") or raw.get("processName"),
            "pid": raw.get("processID") or raw.get("pid"),
            "ppid": raw.get("parentProcessID") or raw.get("ppid"),
            "executable_path": None,
            "parent_process": None,
            "parent_executable": None,
        }
        
        # Try to extract from message if available
        message = self._extract_message(raw)
        
        # Pattern: "process[pid]: message" or "process: message"
        proc_match = re.search(r"^(\w+)\[(\d+)\]:", message)
        if proc_match:
            info["process_name"] = proc_match.group(1)
            info["pid"] = int(proc_match.group(2))
        
        # Pattern: "Parent: process[pid]"
        parent_match = re.search(r"[Pp]arent[:\s]+(\w+)\[(\d+)\]", message)
        if parent_match:
            info["parent_process"] = parent_match.group(1)
            info["ppid"] = int(parent_match.group(2))
        
        # Pattern: executable path
        path_match = re.search(r"(/[\w/\.\-]+\.app/[\w/\.\-]+)", message)
        if path_match:
            info["executable_path"] = path_match.group(1)
        
        return info
    
    def _extract_actor(self, raw: Dict[str, Any], process_info: Dict[str, Any]) -> Dict[str, Any]:
        """Extract actor information from event."""
        actor = {
            "user": raw.get("user") or self._extract_user_from_message(raw),
            "process": process_info.get("process_name"),
            "process_id": process_info.get("pid"),
            "executable_path": process_info.get("executable_path"),
            "parent_process": process_info.get("parent_process"),
            "parent_pid": process_info.get("ppid"),
            "session_id": raw.get("sessionID"),
            "uid": raw.get("uid"),
            "gid": raw.get("gid"),
        }
        
        # Clean up None values
        return {k: v for k, v in actor.items() if v is not None}
    
    def _extract_target(self, raw: Dict[str, Any], message: str) -> Dict[str, Any]:
        """Extract target information from event."""
        target = {
            "resource": None,
            "resource_type": None,
            "user": None,
            "path": None,
        }
        
        # Extract target user from sudo messages
        sudo_match = re.search(r"sudo:\s+\w+\s*:\s*user\s+(\w+)", message)
        if sudo_match:
            target["user"] = sudo_match.group(1)
            target["resource_type"] = "user_account"
        
        # Extract file paths
        path_match = re.search(r"(/[\w/\.\-]+\.plist)", message)
        if path_match:
            target["path"] = path_match.group(1)
            target["resource"] = path_match.group(1)
            target["resource_type"] = "file"
        
        # Extract TCC service
        tcc_match = re.search(r"[Tt][Cc][Cc]\s+(?:for|access to)\s+([\w\s]+?)(?:\s|$)", message)
        if tcc_match:
            target["resource"] = tcc_match.group(1).strip()
            target["resource_type"] = "privacy_service"
        
        # Clean up None values
        return {k: v for k, v in target.items() if v is not None}
    
    def _extract_action(self, event_type: str, message: str) -> str:
        """Extract action from event type and message."""
        action_map = {
            "auth_success": "authenticate",
            "auth_failure": "authenticate",
            "auth_attempt": "authenticate",
            "privilege_escalation": "escalate_privilege",
            "process_execution": "execute",
            "script_execution": "execute_script",
            "persistence_created": "create_persistence",
            "persistence_removed": "remove_persistence",
            "tcc_access": "access_privacy_resource",
            "tcc_denied": "deny_privacy_access",
            "malware_blocked": "block_malware",
            "security_control_disabled": "disable_security",
            "keychain_access": "access_credential",
        }
        return action_map.get(event_type, "unknown")
    
    def _determine_outcome(self, message: str, raw: Dict[str, Any]) -> str:
        """Determine event outcome from message content."""
        msg_lower = message.lower()
        
        # Success indicators
        if any(x in msg_lower for x in ["succeeded", "successful", "accepted", "granted", "allowed", "approved"]):
            return "success"
        
        # Failure indicators
        if any(x in msg_lower for x in ["failed", "failure", "denied", "rejected", "blocked", "prevented", "unauthorized"]):
            return "failure"
        
        # Check event type for implied outcome
        event_type = raw.get("eventType", "").lower()
        if "error" in event_type:
            return "failure"
        
        return "unknown"
    
    def _get_risk_tags(self, event_type: str, message: str, raw: Dict[str, Any]) -> List[str]:
        """Generate risk tags based on event characteristics."""
        tags: Set[str] = set()
        msg_lower = message.lower()
        
        # Base tags from event type
        for category, types in RISK_CATEGORIES.items():
            if event_type in types:
                tags.add(category)
        
        # Additional context-based tags
        if "sudo" in msg_lower:
            tags.add("privilege_escalation")
        
        if "root" in msg_lower:
            tags.add("admin_context")
        
        if any(x in msg_lower for x in ["/tmp/", "/private/tmp/", "/var/tmp/", "/users/shared/"]):
            tags.add("unusual_path")
            tags.add("temp_execution")
        
        if "unsigned" in msg_lower or "not notarized" in msg_lower:
            tags.add("unsigned_binary")
        
        if "quarantine" in msg_lower:
            tags.add("quarantine")
        
        if "xattr -d" in msg_lower:
            tags.add("security_evasion")
        
        if any(x in msg_lower for x in ["curl", "wget", "ftp"]):
            tags.add("network_tool")
        
        if any(x in msg_lower for x in ["base64", "decode", "openssl enc"]):
            tags.add("encoding_obfuscation")
        
        if "osascript" in msg_lower or "applescript" in msg_lower:
            tags.add("script_execution")
        
        # Check for shell execution
        shell_pattern = re.search(r"\|\s*(bash|sh|zsh)\s*", msg_lower)
        if shell_pattern:
            tags.add("pipe_to_shell")
            tags.add("suspicious_chain")
        
        return sorted(list(tags))
    
    def _get_persistence_category(self, event_type: str, message: str) -> Optional[str]:
        """Classify persistence mechanism type."""
        msg_lower = message.lower()
        
        if "launchagent" in msg_lower or "launchagents" in msg_lower:
            return "launchagent"
        if "launchdaemon" in msg_lower or "launchdaemons" in msg_lower:
            return "launchdaemon"
        if "login item" in msg_lower or "loginitem" in msg_lower:
            return "login_item"
        if "crontab" in msg_lower or "cron" in msg_lower:
            return "cron"
        if "emond" in msg_lower:
            return "emond"
        if "periodic" in msg_lower:
            return "periodic"
        if event_type in ["persistence_created", "persistence_removed"]:
            return "unknown_persistence"
        
        return None
    
    def _get_execution_category(self, event_type: str, message: str, raw: Dict[str, Any]) -> Optional[str]:
        """Classify execution type and context."""
        msg_lower = message.lower()
        
        if "osascript" in msg_lower:
            return "applescript"
        if re.search(r"python\d?\s+-c", msg_lower):
            return "python_inline"
        if re.search(r"(bash|sh|zsh)\s+-c", msg_lower):
            return "shell_inline"
        if "/tmp/" in msg_lower or "/private/tmp/" in msg_lower:
            return "temp_directory"
        if "/downloads/" in msg_lower or "/users/" in msg_lower and "/downloads/" in msg_lower:
            return "downloads_directory"
        if "unsigned" in msg_lower:
            return "unsigned_binary"
        if "quarantine" in msg_lower:
            return "quarantined_file"
        
        return None
    
    def _calculate_confidence(self, raw: Dict[str, Any], event_type: str) -> str:
        """Calculate confidence level based on data quality."""
        score = 0
        
        # Has timestamp
        if raw.get("timestamp"):
            score += 20
        
        # Has process info
        if raw.get("process") or raw.get("processName"):
            score += 20
        
        # Has subsystem/category
        if raw.get("subsystem") or raw.get("category"):
            score += 15
        
        # Has message content
        if self._extract_message(raw):
            score += 20
        
        # Has user context
        if raw.get("user"):
            score += 15
        
        # Known event type increases confidence
        if event_type != "unknown":
            score += 10
        
        if score >= 80:
            return "high"
        elif score >= 50:
            return "medium"
        else:
            return "low"
    
    def _infer_severity(self, event_type: str, risk_tags: List[str], actor: Dict[str, Any]) -> str:
        """Infer severity hint from event characteristics."""
        # Critical events
        if event_type in ["malware_blocked", "security_control_disabled"]:
            return "critical"
        
        # High severity
        if event_type in ["privilege_escalation", "persistence_created"]:
            return "high"
        if "admin_context" in risk_tags and event_type == "auth_failure":
            return "high"
        if "security_evasion" in risk_tags:
            return "high"
        
        # Medium severity
        if event_type in ["auth_failure", "script_execution", "tcc_modified"]:
            return "medium"
        if "unusual_path" in risk_tags:
            return "medium"
        
        # Low severity
        if event_type in ["auth_success", "tcc_access"]:
            return "low"
        
        return "info"
    
    def _extract_user_from_message(self, raw: Dict[str, Any]) -> Optional[str]:
        """Extract username from message content."""
        message = self._extract_message(raw)
        
        # Pattern: "user <name>" or "user: <name>"
        match = re.search(r"[Uu]ser[:\s]+(\w+)", message)
        if match:
            return match.group(1)
        
        # Pattern: sudo messages
        match = re.search(r"sudo:\s+(\w+)\s*:", message)
        if match:
            return match.group(1)
        
        return None
    
    def _parse_timestamp(self, ts: Any) -> str:
        """Parse and normalize timestamp."""
        if not ts:
            return datetime.utcnow().isoformat() + "Z"
        if isinstance(ts, str):
            try:
                # Handle various formats
                if ts.endswith("Z"):
                    return datetime.fromisoformat(ts.replace("Z", "+00:00")).isoformat()
                if "+" in ts or ts.count("-") > 2:
                    return datetime.fromisoformat(ts).isoformat()
                # Try parsing as ISO format
                return datetime.fromisoformat(ts).isoformat()
            except (ValueError, TypeError):
                pass
        return datetime.utcnow().isoformat() + "Z"


AdapterRegistry.register("macos", MacOSAdapter)
