from collections import deque


class GraphTraversal:
    def get_downstream(self, graph, node_id, depth=3):
        visited = set()
        queue = deque([(node_id, 0)])

        results = []

        while queue:
            current, level = queue.popleft()

            if level > depth:
                continue

            node = graph.get(current)

            if not node:
                continue

            for callee in node.callees:
                if callee not in visited:
                    visited.add(callee)
                    results.append(callee)
                    queue.append((callee, level + 1))

        return results