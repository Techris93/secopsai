"""macOS adapter - collects security events from unified logging."""

import json
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

from adapters.base import BaseAdapter, AdapterRegistry


class MacOSAdapter(BaseAdapter):
    """Adapter for macOS security events."""
    
    @property
    def name(self) -> str:
        return "macos"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def collect(self, start_time: Optional[datetime] = None,
                end_time: Optional[datetime] = None,
                **kwargs) -> Iterable[Dict[str, Any]]:
        """Collect macOS security events."""
        if not start_time:
            start_time = datetime.utcnow() - timedelta(hours=1)
        if not end_time:
            end_time = datetime.utcnow()
        
        predicates = [
            'subsystem == "com.apple.security"',
            'process == "sudo"',
            'process == "sshd"',
            'process == "loginwindow"'
        ]
        
        yield from self._collect_log(start_time, end_time, predicates)
    
    def stream(self, **kwargs) -> Iterable[Dict[str, Any]]:
        """Stream macOS events in real-time."""
        cmd = [
            "log", "stream",
            "--predicate", 'eventType == logEvent AND subsystem == "com.apple.security"',
            "--style", "json"
        ]
        
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                yield {"source": "log_stream", "raw": event}
            except json.JSONDecodeError:
                continue
    
    def normalize(self, raw_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Convert macOS event to unified schema."""
        raw = raw_event.get("raw", {})
        
        # Handle case where raw is a list (from JSON array)
        if isinstance(raw, list):
            if len(raw) == 0:
                return None
            raw = raw[0]
        
        # Handle case where raw is still not a dict
        if not isinstance(raw, dict):
            return None
        
        message = raw.get("eventMessage", "") or raw.get("message", "")
        
        normalized = {
            "timestamp": self._parse_timestamp(raw.get("timestamp")),
            "event_type": self._infer_event_type(message),
            "platform": "macos",
            "source": "unified_logging",
            "host": raw.get("host") or self.hostname,
            "event_id": self.generate_event_id(raw),
            "actor": {
                "user": raw.get("user")
            },
            "target": {},
            "outcome": self._infer_outcome(message),
            "metadata": {
                "macos_subsystem": raw.get("subsystem"),
                "macos_process": raw.get("process"),
                "macos_message": message
            }
        }
        
        return self.enrich_event(normalized)
    
    def _collect_log(self, start_time, end_time, predicates):
        """Collect events using log command."""
        delta = end_time - start_time
        hours = int(delta.total_seconds() / 3600)
        duration = f"{max(1, min(hours, 24))}h"
        
        for predicate in predicates:
            try:
                cmd = ["log", "show", "--predicate", predicate, "--style", "json", "--last", duration]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0 and result.stdout.strip():
                    # Parse JSON output
                    try:
                        # Try as JSON array first
                        data = json.loads(result.stdout)
                        if isinstance(data, list):
                            for event in data:
                                yield {"source": "log", "raw": event, "predicate": predicate}
                        else:
                            # Single object
                            yield {"source": "log", "raw": data, "predicate": predicate}
                    except json.JSONDecodeError:
                        # Try line by line
                        for line in result.stdout.strip().split("\n"):
                            if not line:
                                continue
                            try:
                                event = json.loads(line)
                                yield {"source": "log", "raw": event, "predicate": predicate}
                            except json.JSONDecodeError:
                                continue
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
    
    def _parse_timestamp(self, ts):
        """Parse and normalize timestamp."""
        if not ts:
            return datetime.utcnow().isoformat() + "Z"
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00")).isoformat()
            except ValueError:
                pass
        return datetime.utcnow().isoformat() + "Z"
    
    def _infer_event_type(self, message: str) -> str:
        """Infer event type from log message."""
        msg_lower = message.lower()
        if "authentication" in msg_lower:
            if "failed" in msg_lower or "denied" in msg_lower:
                return "auth_failure"
            elif "succeeded" in msg_lower:
                return "auth_success"
            return "auth_attempt"
        if "sudo" in msg_lower:
            return "privilege_escalation"
        return "unknown"
    
    def _infer_outcome(self, message: str) -> str:
        """Infer outcome from log message."""
        msg_lower = message.lower()
        if "failed" in msg_lower or "denied" in msg_lower:
            return "failure"
        elif "succeeded" in msg_lower or "success" in msg_lower:
            return "success"
        return "unknown"


AdapterRegistry.register("macos", MacOSAdapter)
