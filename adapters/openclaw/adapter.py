"""OpenClaw adapter."""

import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, Iterable, Optional

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT_DIR)

from adapters.base import BaseAdapter, AdapterRegistry


class OpenClawAdapter(BaseAdapter):
    """Adapter for OpenClaw audit logs."""
    
    @property
    def name(self) -> str:
        return "openclaw"
    
    @property
    def version(self) -> str:
        return "1.0.0"
    
    def collect(self, start_time: Optional[datetime] = None,
                end_time: Optional[datetime] = None,
                input_file: Optional[str] = None,
                **kwargs) -> Iterable[Dict[str, Any]]:
        """Collect OpenClaw audit events."""
        if not input_file:
            input_file = os.path.join(ROOT_DIR, "data", "openclaw", "raw", "audit.jsonl")
        
        if not os.path.exists(input_file):
            input_file = os.path.join(ROOT_DIR, "data", "openclaw", "replay", "labeled", "current.json")
        
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"No OpenClaw data found at {input_file}")
        
        with open(input_file, 'r') as f:
            if input_file.endswith('.jsonl'):
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        yield {"source": "audit", "raw": event}
                    except json.JSONDecodeError:
                        continue
            else:
                data = json.load(f)
                if isinstance(data, list):
                    for event in data:
                        yield {"source": "audit", "raw": event}
                else:
                    yield {"source": "audit", "raw": data}
    
    def stream(self, **kwargs) -> Iterable[Dict[str, Any]]:
        raise NotImplementedError("OpenClaw streaming not implemented")
    
    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Convert OpenClaw event to unified schema."""
        record = raw_event.get("raw", {})
        
        # Determine event type from surface
        surface = record.get("surface", "unknown")
        event_type_map = {
            "config": "config_change",
            "exec": "tool_invocation", 
            "tool": "tool_invocation",
            "session": "session_start",
            "agent_event": "tool_invocation",
            "openclaw_tool": "tool_invocation",
            "openclaw_exec": "tool_invocation",
            "openclaw_session": "session_start",
            "openclaw_config": "config_change"
        }
        
        normalized = {
            "timestamp": record.get("timestamp") or record.get("ts") or datetime.utcnow().isoformat() + "Z",
            "event_type": event_type_map.get(surface, "unknown"),
            "platform": "openclaw",
            "source": surface,
            "host": record.get("host", self.hostname),
            "event_id": self.generate_event_id(record),
            "actor": {
                "user": record.get("user"),
                "process": record.get("tool") or record.get("process"),
                "command_line": record.get("command") or record.get("command_line"),
                "ip": record.get("source_ip") or record.get("ip")
            },
            "target": {
                "file": record.get("file"),
                "ip": record.get("dest_ip"),
                "domain": record.get("domain")
            },
            "outcome": record.get("outcome", "success"),
            "severity": record.get("severity", "info"),
            "metadata": {
                "openclaw_surface": surface,
                "openclaw_channel": record.get("channel"),
                "openclaw_tool": record.get("tool"),
                "detection_ids": record.get("detection_ids", []),
                "attack_type": record.get("attack_type")
            }
        }
        
        return self.enrich_event(normalized)


AdapterRegistry.register("openclaw", OpenClawAdapter)
