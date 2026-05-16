from dataclasses import dataclass
from typing import Dict, List

from src.models import CodeSample
from src.context.call_graph import CallGraphNode


@dataclass
class FunctionContext:
    target: CodeSample
    callers: List[str]
    callees: List[str]
    subgraph: Dict[str, dict]


class ContextBuilder:
    def build(
        self,
        target: CodeSample,
        graph: Dict[str, CallGraphNode],
    ) -> FunctionContext:

        node_id = f"{target.file_path}::{target.function_name}"
        node = graph.get(node_id)

        if not node:
            return FunctionContext(target, [], [], {})

        callers = node.callers
        callees = node.callees

        subgraph = {
            target.function_name: {
                "callers": callers,
                "callees": callees,
            }
        }

        return FunctionContext(
            target=target,
            callers=callers,
            callees=callees,
            subgraph=subgraph,
        )