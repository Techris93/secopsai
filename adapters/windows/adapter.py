"""Windows adapter - collects security events from Event Logs and Sysmon."""

import json
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Optional

from adapters.base import BaseAdapter, AdapterRegistry


class WindowsAdapter(BaseAdapter):
    """Adapter for Windows security events."""
    
    @property
    def name(self) -> str:
        return "windows"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def collect(self, start_time: Optional[datetime] = None,
                end_time: Optional[datetime] = None,
                **kwargs) -> Iterable[Dict[str, Any]]:
        """Collect Windows security events."""
        if not start_time:
            start_time = datetime.utcnow() - timedelta(hours=1)
        
        yield from self._collect_wevtutil(start_time)
        yield from self._collect_sysmon(start_time)
    
    def stream(self, **kwargs) -> Iterable[Dict[str, Any]]:
        raise NotImplementedError("Windows streaming not yet implemented")
    
    def normalize(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert Windows event to unified schema."""
        source = raw_event.get("source", "")
        raw = raw_event.get("raw", {})
        
        if not isinstance(raw, dict):
            return None
        
        if source == "wevtutil":
            return self._normalize_wevtutil(raw)
        elif source == "sysmon":
            return self._normalize_sysmon(raw)
        
        return None
    
    def _collect_wevtutil(self, start_time: datetime):
        """Collect events using Windows Event Viewer utility."""
        time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S")
        
        channels = [
            "Security",
            "System",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Sysmon/Operational"
        ]
        
        for channel in channels:
            try:
                cmd = [
                    "wevtutil", "qe", channel,
                    "/q:*[System[TimeCreated[@SystemTime>='" + time_str + "']]]",
                    "/f:json", "/c:100"
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        events = json.loads(result.stdout)
                        if isinstance(events, list):
                            for event in events:
                                yield {"source": "wevtutil", "raw": event, "channel": channel}
                        else:
                            yield {"source": "wevtutil", "raw": events, "channel": channel}
                    except json.JSONDecodeError:
                        pass
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
    
    def _collect_sysmon(self, start_time: datetime):
        """Collect Sysmon events."""
        pass
    
    def _normalize_wevtutil(self, raw: Dict) -> Dict[str, Any]:
        """Normalize wevtutil JSON output."""
        system = raw.get("System", {})
        event_id = system.get("EventID", {}).get("#text", 0)
        channel = system.get("Channel", "Unknown")
        time_created = system.get("TimeCreated", {}).get("@SystemTime")
        
        event_type = self._map_windows_event_id(int(event_id), channel)
        
        normalized = {
            "timestamp": self._parse_windows_time(time_created),
            "event_type": event_type,
            "platform": "windows",
            "source": "windows_event_log",
            "host": system.get("Computer", self.hostname),
            "event_id": self.generate_event_id(raw),
            "actor": {
                "user": self._extract_user(raw),
                "process": self._extract_process(raw),
                "command_line": self._extract_command(raw)
            },
            "target": {
                "file": self._extract_target_file(raw),
                "ip": self._extract_target_ip(raw)
            },
            "outcome": self._extract_outcome(raw),
            "metadata": {
                "windows_channel": channel,
                "windows_event_id": event_id,
                "windows_provider": system.get("Provider", {}).get("@Name"),
                "windows_raw": raw
            }
        }
        
        return self.enrich_event(normalized)
    
    def _normalize_sysmon(self, raw: Dict) -> Dict[str, Any]:
        """Normalize Sysmon event."""
        event_data = raw.get("EventData", {})
        
        normalized = {
            "timestamp": self._parse_windows_time(
                raw.get("System", {}).get("TimeCreated", {}).get("@SystemTime")
            ),
            "event_type": self._map_sysmon_event(raw.get("System", {}).get("EventID", 0)),
            "platform": "windows",
            "source": "sysmon",
            "host": raw.get("System", {}).get("Computer", self.hostname),
            "event_id": self.generate_event_id(raw),
            "actor": {
                "user": event_data.get("User"),
                "process": event_data.get("Image"),
                "command_line": event_data.get("CommandLine")
            },
            "target": {
                "file": event_data.get("TargetFilename"),
                "ip": event_data.get("DestinationIp"),
                "domain": event_data.get("DestinationHostname")
            },
            "outcome": "unknown",
            "metadata": {
                "windows_sysmon_event": raw.get("System", {}).get("EventID"),
                "windows_sysmon_data": event_data
            }
        }
        
        return self.enrich_event(normalized)
    
    def _parse_windows_time(self, time_str: Optional[str]) -> str:
        """Parse Windows SystemTime format."""
        if not time_str:
            return datetime.utcnow().isoformat() + "Z"
        try:
            dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
            return dt.isoformat()
        except ValueError:
            return datetime.utcnow().isoformat() + "Z"
    
    def _map_windows_event_id(self, event_id: int, channel: str) -> str:
        """Map Windows Event ID to unified type."""
        auth_events = {4624: "auth_success", 4625: "auth_failure", 4634: "auth_success",
                       4648: "privilege_escalation", 4672: "privilege_escalation"}
        process_events = {4688: "process_exec", 4689: "process_exit"}
        
        if event_id in auth_events:
            return auth_events[event_id]
        if event_id in process_events:
            return process_events[event_id]
        
        return "unknown"
    
    def _map_sysmon_event(self, event_id) -> str:
        """Map Sysmon Event ID to unified type."""
        sysmon_map = {
            1: "process_exec",
            2: "file_modify",
            3: "network_connection",
            5: "process_exit",
            6: "file_create",
            7: "file_access",
            8: "file_access",
            9: "file_access",
            10: "file_access",
            11: "file_create",
            12: "registry_mod",
            13: "registry_mod",
            14: "registry_mod",
            15: "file_create",
            22: "network_connection"
        }
        return sysmon_map.get(int(event_id), "unknown")
    
    def _extract_user(self, raw: Dict) -> Optional[str]:
        """Extract user from Windows event."""
        event_data = raw.get("EventData", {})
        return event_data.get("TargetUserName") or event_data.get("SubjectUserName")
    
    def _extract_process(self, raw: Dict) -> Optional[str]:
        """Extract process name."""
        event_data = raw.get("EventData", {})
        return event_data.get("NewProcessName") or event_data.get("ProcessName")
    
    def _extract_command(self, raw: Dict) -> Optional[str]:
        """Extract command line."""
        event_data = raw.get("EventData", {})
        return event_data.get("CommandLine")
    
    def _extract_target_file(self, raw: Dict) -> Optional[str]:
        """Extract target file."""
        event_data = raw.get("EventData", {})
        return event_data.get("ObjectName") or event_data.get("TargetFilename")
    
    def _extract_target_ip(self, raw: Dict) -> Optional[str]:
        """Extract target IP."""
        event_data = raw.get("EventData", {})
        return event_data.get("IpAddress") or event_data.get("DestinationIp")
    
    def _extract_outcome(self, raw: Dict) -> str:
        """Extract outcome from event."""
        event_data = raw.get("EventData", {})
        status = event_data.get("Status", "0x0")
        if status == "0x0":
            return "success"
        return "failure"


AdapterRegistry.register("windows", WindowsAdapter)
