"""Base definitions for Cybersecurity Tools."""

from dataclasses import dataclass, field
from typing import Any, Optional, Dict
import time


@dataclass
class ToolResult:
    """Standardized response container for all cybersecurity tool executions."""
    success: bool
    data: Optional[Any] = None
    error: Optional[str] = None
    cached: bool = False
    execution_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "cached": self.cached,
            "execution_time_ms": self.execution_time_ms,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }

