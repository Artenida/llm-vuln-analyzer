"""
Tests for call-graph subgraph selection (src/results/export_graph.py).

A few-hundred-function repo renders as an unreadable hairball, so the exporter
draws a selected sub-graph. These check that the selection keeps what was asked
for and never leaves a dangling edge behind.
"""
import unittest

from src.results.export_graph import select_subgraph


def _node(name, file="app/a.js", callees=(), callers=(), **flags):
    n = {
        "function_name": name,
        "file_path": file,
        "callees": list(callees),
        "callers": list(callers),
        "is_external": False,
        "is_entry_point": False,
        "is_taint_sink": False,
        "is_taint_source": False,
        "is_infrastructure": False,
    }
    n.update(flags)
    return n


def _graph():
    """route -> service -> dao, plus an unrelated island and an external node.

        handleRoute -> getUser -> findById
        orphan (no edges)
        external::express (external)
    """
    return {
        "app/a.js::handleRoute": _node("handleRoute", callees=["app/a.js::getUser"],
                                       is_entry_point=True),
        "app/a.js::getUser": _node("getUser", callees=["app/a.js::findById"],
                                   callers=["app/a.js::handleRoute"]),
        "app/a.js::findById": _node("findById", callers=["app/a.js::getUser"],
                                    is_infrastructure=True),
        "app/a.js::orphan": _node("orphan"),
        "external::express": _node("express", is_external=True),
    }


FINDINGS = [
    {"function_name": "getUser", "file_path": "app/a.js",
     "vulnerability_found": True, "severity": "high"},
    {"function_name": "orphan", "file_path": "app/a.js",
     "vulnerability_found": False, "severity": None},
]


class TestSelectSubgraph(unittest.TestCase):

    def test_no_filters_keeps_every_internal_node(self):
        out = select_subgraph(_graph())

        self.assertEqual(len(out), 4)
        self.assertNotIn("external::express", out)

    def test_only_findings_with_one_hop_keeps_neighbours_both_ways(self):
        """A vulnerable function's callers matter as much as its callees — the
        caller is how user input reaches it."""
        out = select_subgraph(_graph(), findings=FINDINGS, only_findings=True, hops=1)

        self.assertEqual(
            set(out),
            {"app/a.js::getUser", "app/a.js::handleRoute", "app/a.js::findById"},
        )
        self.assertNotIn("app/a.js::orphan", out)

    def test_hops_zero_keeps_only_the_seeds(self):
        out = select_subgraph(_graph(), findings=FINDINGS, only_findings=True, hops=0)

        self.assertEqual(set(out), {"app/a.js::getUser"})

    def test_focus_accepts_a_bare_function_name(self):
        out = select_subgraph(_graph(), focus="getUser", hops=0)

        self.assertEqual(set(out), {"app/a.js::getUser"})

    def test_focus_accepts_a_fully_qualified_id(self):
        out = select_subgraph(_graph(), focus="app/a.js::getUser", hops=0)

        self.assertEqual(set(out), {"app/a.js::getUser"})

    def test_edges_are_pruned_to_the_kept_set(self):
        """A kept node must not point at a node that was filtered out, or the
        renderer draws an edge to nothing."""
        out = select_subgraph(_graph(), focus="getUser", hops=1)
        kept = set(out)

        for node_id, node in out.items():
            for nb in node["callees"] + node["callers"]:
                self.assertIn(nb, kept, f"{node_id} still references dropped {nb}")

    def test_hide_isolated_drops_edgeless_nodes(self):
        out = select_subgraph(_graph(), hide_isolated=True)

        self.assertNotIn("app/a.js::orphan", out)
        self.assertIn("app/a.js::getUser", out)

    def test_hide_isolated_keeps_a_seed_even_with_no_edges(self):
        """Explicitly asking to focus on something and getting an empty page
        would be worse than useless."""
        g = _graph()
        out = select_subgraph(g, focus="orphan", hops=1, hide_isolated=True)

        self.assertEqual(set(out), {"app/a.js::orphan"})

    def test_unknown_focus_raises_with_a_usable_message(self):
        with self.assertRaises(ValueError) as ctx:
            select_subgraph(_graph(), focus="noSuchFunction")

        self.assertIn("noSuchFunction", str(ctx.exception))

    def test_only_findings_with_no_findings_raises(self):
        clean = [{"function_name": "getUser", "file_path": "app/a.js",
                  "vulnerability_found": False}]

        with self.assertRaises(ValueError):
            select_subgraph(_graph(), findings=clean, only_findings=True)

    def test_selection_does_not_mutate_the_input_graph(self):
        g = _graph()
        select_subgraph(g, focus="getUser", hops=0)

        self.assertEqual(g["app/a.js::getUser"]["callees"], ["app/a.js::findById"])
        self.assertEqual(len(g), 5)


if __name__ == "__main__":
    unittest.main()
