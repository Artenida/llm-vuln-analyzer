"""
Tests for the call-graph node breakdown (src/context/call_graph.graph_counts).

`len(graph)` counts a node per call *target*, so every unresolved call to a
library or runtime function contributes an `external::` stub. On juice-shop
that was 807 of 1306 nodes, and the UI showed the 1306 next to a run that had
analysed 558 functions. These pin the split, and pin that a graph saved before
the split was recorded still reports it on read.
"""
import json
import tempfile
import unittest
from pathlib import Path

from src.context.call_graph import CallGraphNode, graph_counts
from src.results.run_saver import save_call_graph
from src.web.results import _graph_breakdown


def _dict_node(name, file="app/a.js", **flags):
    node = {
        "function_name": name,
        "file_path": file,
        "callers": [],
        "callees": [],
        "is_external": False,
        "is_entry_point": False,
        "is_infrastructure": False,
        "is_taint_source": False,
        "is_taint_sink": False,
        "route_registrations": [],
    }
    node.update(flags)
    return node


def _graph_dicts():
    return {
        "app/a.js::handleRoute": _dict_node("handleRoute"),
        "app/a.js::getUser": _dict_node("getUser"),
        "external::parseInt": _dict_node("parseInt", file="external", is_external=True),
        "external::res.json": _dict_node("res.json", file="external", is_external=True),
    }


class GraphCountsTest(unittest.TestCase):

    def test_external_stubs_are_not_counted_as_project_functions(self):
        self.assertEqual(
            graph_counts(_graph_dicts()),
            {"total_nodes": 4, "project_functions": 2, "external_stubs": 2},
        )

    def test_infrastructure_functions_are_still_project_functions(self):
        """`is_infrastructure` marks a real function, not a stub.

        It is a name-pattern flag set on functions the walk actually found, so
        excluding it here would undercount the project rather than the stubs.
        """
        graph = _graph_dicts()
        graph["app/a.js::initLogger"] = _dict_node("initLogger", is_infrastructure=True)
        self.assertEqual(graph_counts(graph)["project_functions"], 3)

    def test_accepts_the_in_memory_node_form_too(self):
        """The writer holds CallGraphNode objects; the reader holds plain dicts."""
        graph = {
            "app/a.js::getUser": CallGraphNode(
                id="app/a.js::getUser", function_name="getUser", file_path="app/a.js"),
            "external::parseInt": CallGraphNode(
                id="external::parseInt", function_name="parseInt",
                file_path="external", is_external=True),
        }
        self.assertEqual(
            graph_counts(graph),
            {"total_nodes": 2, "project_functions": 1, "external_stubs": 1},
        )

    def test_empty_graph_counts_nothing_rather_than_failing(self):
        self.assertEqual(
            graph_counts({}),
            {"total_nodes": 0, "project_functions": 0, "external_stubs": 0},
        )


class SavedGraphTest(unittest.TestCase):

    def test_saved_payload_carries_the_breakdown(self):
        graph = {
            "app/a.js::getUser": CallGraphNode(
                id="app/a.js::getUser", function_name="getUser", file_path="app/a.js"),
            "external::parseInt": CallGraphNode(
                id="external::parseInt", function_name="parseInt",
                file_path="external", is_external=True),
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = save_call_graph(graph, source_path="X", output_folder=tmp,
                                   filename="call_graph.json")
            saved = json.loads(Path(path).read_text(encoding="utf-8"))

        self.assertEqual(saved["project_functions"], 1)
        self.assertEqual(saved["external_stubs"], 1)
        # Kept: runs already on disk carry it, and the UI still reports it.
        self.assertEqual(saved["total_nodes"], 2)


class WebBreakdownTest(unittest.TestCase):

    def test_recomputed_for_a_run_saved_before_the_split_existed(self):
        legacy = {"total_nodes": 4, "graph": _graph_dicts()}
        self.assertEqual(
            _graph_breakdown(legacy),
            {"graph_project_functions": 2, "graph_external_stubs": 2},
        )

    def test_no_graph_reports_nothing_rather_than_zero(self):
        """A run with no graph and a graph with no project functions differ."""
        self.assertEqual(_graph_breakdown(None), {})
        self.assertEqual(_graph_breakdown({"total_nodes": 0, "graph": {}}), {})


if __name__ == "__main__":
    unittest.main()
