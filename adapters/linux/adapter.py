"""Linux adapter - collects security events from journalctl and auditd."""

import json
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Optional

from adapters.base import BaseAdapter, AdapterRegistry


class LinuxAdapter(BaseAdapter):
    """Adapter for Linux security events."""
    
    @property
    def name(self) -> str:
        return "linux"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def collect(self, start_time: Optional[datetime] = None,
                end_time: Optional[datetime] = None,
                **kwargs) -> Iterable[Dict[str, Any]]:
        """Collect Linux security events."""
        if not start_time:
            start_time = datetime.utcnow() - timedelta(hours=1)
        
        yield from self._collect_journalctl(start_time)
        yield from self._collect_auditd(start_time)
    
    def stream(self, **kwargs) -> Iterable[Dict[str, Any]]:
        """Stream Linux events in real-time."""
        cmd = ["journalctl", "-f", "-o", "json", "-n", "0"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    yield {"source": "journalctl", "raw": event}
                except json.JSONDecodeError:
                    continue
        except FileNotFoundError:
            pass
    
    def normalize(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert Linux event to unified schema."""
        source = raw_event.get("source", "")
        raw = raw_event.get("raw", {})
        
        if not isinstance(raw, dict):
            return None
        
        if source == "journalctl":
            return self._normalize_journalctl(raw)
        elif source == "auditd":
            return self._normalize_auditd(raw)
        
        return None
    
    def _collect_journalctl(self, start_time: datetime):
        """Collect events from systemd journal."""
        since = start_time.strftime("%Y-%m-%d %H:%M:%S")
        services = ["sshd", "sudo", "auditd", "systemd-logind"]
        
        for service in services:
            try:
                cmd = ["journalctl", "-u", service, "--since", since, "-o", "json", "--no-pager"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split("\n"):
                        if not line:
                            continue
                        try:
                            event = json.loads(line)
                            yield {"source": "journalctl", "raw": event, "service": service}
                        except json.JSONDecodeError:
                            continue
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
    
    def _collect_auditd(self, start_time: datetime):
        """Collect events from auditd."""
        try:
            cmd = ["ausearch", "-ts", "recent", "-i", "-r"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                for line in result.stdout.strip().split("\n"):
                    if line.startswith("type="):
                        event = self._parse_auditd_line(line)
                        if event:
                            yield {"source": "auditd", "raw": event}
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
    
    def _parse_auditd_line(self, line: str) -> Dict[str, str]:
        """Parse auditd key=value format."""
        event = {}
        parts = line.split()
        for part in parts:
            if "=" in part:
                key, value = part.split("=", 1)
                event[key] = value
        return event
    
    def _normalize_journalctl(self, raw: Dict) -> Dict[str, Any]:
        """Normalize journalctl event."""
        message = raw.get("MESSAGE", "")
        syslog_id = raw.get("SYSLOG_IDENTIFIER", "")
        
        normalized = {
            "timestamp": self._parse_timestamp(raw.get("__REALTIME_TIMESTAMP")),
            "event_type": self._infer_event_type(message, syslog_id),
            "platform": "linux",
            "source": "journalctl",
            "host": raw.get("_HOSTNAME", self.hostname),
            "event_id": self.generate_event_id(raw),
            "actor": {
                "user": raw.get("UID") or raw.get("_UID"),
                "process": syslog_id or raw.get("_COMM"),
                "command_line": raw.get("_CMDLINE")
            },
            "target": {
                "file": raw.get("FILE")
            },
            "outcome": self._infer_outcome(message),
            "metadata": {
                "linux_service": syslog_id,
                "linux_priority": raw.get("PRIORITY"),
                "linux_unit": raw.get("_SYSTEMD_UNIT"),
                "linux_message": message
            }
        }
        
        return self.enrich_event(normalized)
    
    def _normalize_auditd(self, raw: Dict) -> Dict[str, Any]:
        """Normalize auditd event."""
        audit_type = raw.get("type", "UNKNOWN")
        
        normalized = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": self._map_auditd_type(audit_type),
            "platform": "linux",
            "source": "auditd",
            "host": self.hostname,
            "event_id": self.generate_event_id(raw),
            "actor": {
                "user": raw.get("uid"),
                "process": raw.get("exe"),
                "command_line": raw.get("cmd")
            },
            "target": {
                "file": raw.get("name")
            },
            "outcome": "unknown",
            "metadata": {
                "linux_audit_type": audit_type,
                "linux_audit_raw": raw
            }
        }
        
        return self.enrich_event(normalized)
    
    def _parse_timestamp(self, ts_microseconds):
        """Parse journalctl timestamp."""
        if not ts_microseconds:
            return datetime.utcnow().isoformat() + "Z"
        try:
            ts_seconds = int(ts_microseconds) / 1_000_000
            dt = datetime.utcfromtimestamp(ts_seconds)
            return dt.isoformat() + "Z"
        except (ValueError, TypeError):
            return datetime.utcnow().isoformat() + "Z"
    
    def _infer_event_type(self, message: str, service: str) -> str:
        """Infer event type."""
        msg_lower = message.lower()
        
        if "authentication" in msg_lower or "login" in msg_lower:
            if "failed" in msg_lower or "failure" in msg_lower:
                return "auth_failure"
            return "auth_attempt"
        
        if service == "sudo" or "sudo:" in msg_lower:
            return "privilege_escalation"
        
        if service == "sshd":
            return "auth_attempt"
        
        return "unknown"
    
    def _infer_outcome(self, message: str) -> str:
        """Infer outcome."""
        msg_lower = message.lower()
        if any(x in msg_lower for x in ["failed", "failure", "denied", "error"]):
            return "failure"
        if any(x in msg_lower for x in ["success", "succeeded", "accepted"]):
            return "success"
        return "unknown"
    
    def _map_auditd_type(self, audit_type: str) -> str:
        """Map auditd type to unified event type."""
        type_map = {
            "SYSCALL": "process_exec",
            "EXECVE": "process_exec",
            "USER_LOGIN": "auth_attempt",
            "USER_AUTH": "auth_attempt"
        }
        return type_map.get(audit_type, "unknown")


AdapterRegistry.register("linux", LinuxAdapter)
