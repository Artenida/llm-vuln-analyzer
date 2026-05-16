from dataclasses import dataclass, field
from typing import List


@dataclass
class CallEdge:
    source: str
    target: str
    confidence: float
    edge_type: str
    resolved_by: str


@dataclass
class GraphNode:
    node_id: str
    function_name: str
    file_path: str

    callers: List[str] = field(default_factory=list)
    callees: List[str] = field(default_factory=list)

    node_type: str = "function"
    is_entry_point: bool = False