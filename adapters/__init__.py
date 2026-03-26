"""SecOpsAI Adapters Package."""
from adapters.base import BaseAdapter, AdapterRegistry

# Import adapters to register them
import adapters.openclaw.adapter
import adapters.macos.adapter
import adapters.linux.adapter
import adapters.windows.adapter

__all__ = ["BaseAdapter", "AdapterRegistry"]
