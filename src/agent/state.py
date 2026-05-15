from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentState:
    current_function: str | None = None
    memory: dict[str, Any] = field(default_factory=dict)
    tool_history: list[dict] = field(default_factory=list)
    reasoning_trace: list[str] = field(default_factory=list)