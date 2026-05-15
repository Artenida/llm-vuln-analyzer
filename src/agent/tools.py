from src.context.call_graph import CallGraphNode


class ToolSet:
    def __init__(self, graph: dict[str, CallGraphNode]):
        self.graph = graph

    def get_callees(self, fn: str):
        node = self.graph.get(fn)
        return node.callees if node else []

    def get_callers(self, fn: str):
        node = self.graph.get(fn)
        return node.callers if node else []

    def is_entry_point(self, fn: str):
        node = self.graph.get(fn)
        return node.is_entry_point if node else False

    def trace_one_hop(self, fn: str):
        return {
            "callers": self.get_callers(fn),
            "callees": self.get_callees(fn),
        }