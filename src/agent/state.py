from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentState:
    current_function: str | None = None
    memory: dict[str, Any] = field(default_factory=dict)
    tool_history: list[dict] = field(default_factory=list)
    reasoning_trace: list[str] = field(default_factory=list)

    def tool_summary(self) -> str:
        """Human-readable summary of tools called so far."""
        if not self.tool_history:
            return "No tools called."
        lines = []
        for entry in self.tool_history:
            step = entry.get("step", "?")
            tool = entry.get("tool", "?")
            args = entry.get("args", {})
            lines.append(f"  step {step}: {tool}({args})")
        return "\n".join(lines)