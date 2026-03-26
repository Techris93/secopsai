"""Base adapter class for SecOpsAI Universal."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Any
import json
import hashlib
import platform as sys_platform
import socket


class BaseAdapter(ABC):
    """Abstract base class for security data adapters."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.hostname = socket.gethostname()
        self.platform_name = self._get_platform_name()
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Adapter identifier."""
        pass
    
    @property
    @abstractmethod
    def version(self) -> str:
        """Adapter version."""
        pass
    
    def _get_platform_name(self) -> str:
        """Get normalized platform name."""
        return sys_platform.system().lower()
    
    @abstractmethod
    def collect(self, start_time: Optional[datetime] = None, 
                end_time: Optional[datetime] = None,
                **kwargs) -> Iterable[Dict[str, Any]]:
        """Batch collection of historical events."""
        pass
    
    @abstractmethod
    def stream(self, **kwargs) -> Iterable[Dict[str, Any]]:
        """Real-time streaming of events."""
        pass
    
    @abstractmethod
    def normalize(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Convert platform-native event to unified schema."""
        pass
    
    def generate_event_id(self, event: Dict[str, Any]) -> str:
        """Generate unique event ID from event content."""
        content = json.dumps(event, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()[:32]
    
    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Add adapter metadata to event."""
        event["adapter"] = self.name
        event["adapter_version"] = self.version
        event["collected_at"] = datetime.utcnow().isoformat() + "Z"
        event["host"] = self.hostname
        if "event_id" not in event:
            event["event_id"] = self.generate_event_id(event)
        return event


class AdapterRegistry:
    """Registry for platform adapters."""
    
    _adapters: Dict[str, type] = {}
    
    @classmethod
    def register(cls, name: str, adapter_class: type):
        """Register an adapter class."""
        if not issubclass(adapter_class, BaseAdapter):
            raise ValueError(f"Adapter must inherit from BaseAdapter")
        cls._adapters[name] = adapter_class
    
    @classmethod
    def get(cls, name: str) -> Optional[type]:
        """Get adapter class by name."""
        return cls._adapters.get(name)
    
    @classmethod
    def list_adapters(cls) -> List[str]:
        """List all registered adapter names."""
        return list(cls._adapters.keys())
    
    @classmethod
    def create(cls, name: str, config: Optional[Dict] = None) -> BaseAdapter:
        """Instantiate an adapter by name."""
        adapter_class = cls.get(name)
        if not adapter_class:
            raise ValueError(f"Unknown adapter: {name}")
        return adapter_class(config)
