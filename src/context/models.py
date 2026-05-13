from dataclasses import dataclass, field


@dataclass
class CallGraphNode:
    function_name: str
    file_path: str

    callers: list[str] = field(default_factory=list)
    callees: list[str] = field(default_factory=list)

    is_entry_point: bool = False