"""
Tests for LLM edge-resolution candidate narrowing (src/context/call_graph.py)
and the cache key that goes with it (src/context/llm_edge_resolver.py).

Every unresolved call used to be sent `list(known)` — every function name in
the project. On Juice Shop that was 1728 names, ~10k tokens, 88% of each
prompt, on a path only reached once static resolution had established that no
name matches. One run spent $10.01 on 708 such calls and never reached the
analysis phase; 4096 of 4513 cached verdicts were "external".

No network anywhere here: the OpenAI client is mocked.
"""
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock

from src.context.call_graph import CallGraphBuilder
from src.context.llm_edge_resolver import LLMEdgeResolver
from src.models import CodeSample
from src.models.code_sample import ImportReference
from src.models.models import Language


def _sample(name, file_path, imports=None):
    return CodeSample(
        function_name=name,
        file_path=file_path,
        code=f"function {name}() {{}}",
        language=Language.JAVASCRIPT,
        start_line=1,
        end_line=1,
        imports=list(imports or []),
    )


def _builder():
    # No api_key: these tests exercise candidate selection, which happens
    # before any resolver would be consulted.
    return CallGraphBuilder(api_key=None)


class TestCandidateNarrowing(unittest.TestCase):

    def test_library_call_gets_no_candidates_and_so_costs_nothing(self):
        """`lodash.groupBy` matches no import and no known name. Previously it
        was worth 1728 names and $0.014 to be told it is external."""
        caller = _sample("handler", "routes/order.js")
        known = {"handler", "createOrder", "findById"}
        names_by_file = {"routes/order.js": {"handler"},
                         "models/order.js": {"createOrder", "findById"}}

        candidates = _builder()._llm_candidates(
            caller, "lodash.groupBy", known, names_by_file
        )

        self.assertEqual(candidates, [])

    def test_import_alias_narrows_to_that_module(self):
        caller = _sample(
            "handler", "routes/order.js",
            imports=[ImportReference(alias="orders", source="../models/order")],
        )
        known = {"handler", "createOrder", "findById", "unrelated"}
        names_by_file = {
            "routes/order.js": {"handler"},
            "models/order.js": {"createOrder", "findById"},
            "lib/other.js": {"unrelated"},
        }

        candidates = _builder()._llm_candidates(
            caller, "orders.persist", known, names_by_file
        )

        self.assertEqual(candidates, ["createOrder", "findById"])
        self.assertNotIn("unrelated", candidates)

    def test_this_call_offers_siblings_in_the_same_file(self):
        caller = _sample("render", "components/view.js")
        known = {"render", "draw", "elsewhere"}
        names_by_file = {"components/view.js": {"render", "draw"},
                         "other/file.js": {"elsewhere"}}

        candidates = _builder()._llm_candidates(
            caller, "this.draw", known, names_by_file
        )

        self.assertIn("draw", candidates)
        self.assertNotIn("elsewhere", candidates)

    def test_caller_is_never_its_own_candidate(self):
        caller = _sample("render", "components/view.js")
        names_by_file = {"components/view.js": {"render", "draw"}}

        candidates = _builder()._llm_candidates(
            caller, "this.render", {"render", "draw"}, names_by_file
        )

        self.assertNotIn("render", candidates)

    def test_near_miss_name_is_offered(self):
        """A renamed import is the case static matching cannot settle."""
        caller = _sample("handler", "routes/order.js")
        known = {"handler", "createOrder"}
        names_by_file = {"routes/order.js": {"handler"},
                         "models/order.js": {"createOrder"}}

        candidates = _builder()._llm_candidates(
            caller, "createOrders", known, names_by_file
        )

        self.assertIn("createOrder", candidates)

    def test_candidate_list_is_capped(self):
        caller = _sample(
            "handler", "routes/order.js",
            imports=[ImportReference(alias="big", source="../models/big")],
        )
        names = {f"fn{i}" for i in range(100)}
        names_by_file = {"models/big.js": names, "routes/order.js": {"handler"}}

        candidates = _builder()._llm_candidates(
            caller, "big.something", names | {"handler"}, names_by_file
        )

        self.assertEqual(len(candidates), CallGraphBuilder.MAX_LLM_CANDIDATES)


class TestCacheKey(unittest.TestCase):

    def _resolver(self, cache_path, target="createOrder"):
        r = LLMEdgeResolver(api_key="sk-test", cache_path=cache_path)
        r.client = MagicMock()
        r.client.resolve_edge.return_value = {
            "target": target, "confidence": 0.9, "reasoning": "internal"}
        return r

    def test_same_question_from_a_different_caller_is_not_re_bought(self):
        """The answer depends on the call and the candidates, not on who asked.
        Keying on the caller made one question N paid answers."""
        with TemporaryDirectory() as tmp:
            cache_path = str(Path(tmp) / "edge_cache.json")
            candidates = ["createOrder", "findById"]

            first = self._resolver(cache_path)
            first.resolve(caller="routes/a.js::handlerA", raw_call="db.persist",
                          caller_code="db.persist()", candidates=candidates)
            self.assertEqual(first.client.resolve_edge.call_count, 1)

            second = self._resolver(cache_path)
            result = second.resolve(caller="routes/b.js::handlerB",
                                    raw_call="db.persist",
                                    caller_code="db.persist()",
                                    candidates=candidates)

            second.client.resolve_edge.assert_not_called()
            self.assertEqual(result["resolved_by"], "cache")
            self.assertEqual(result["target"], "createOrder")

    def test_a_different_candidate_set_is_a_different_question(self):
        with TemporaryDirectory() as tmp:
            cache_path = str(Path(tmp) / "edge_cache.json")

            first = self._resolver(cache_path)
            first.resolve(caller="a.js::x", raw_call="db.persist",
                          caller_code="", candidates=["createOrder", "findById"])

            second = self._resolver(cache_path)
            second.resolve(caller="a.js::x", raw_call="db.persist",
                           caller_code="", candidates=["saveOrder", "findById"])

            second.client.resolve_edge.assert_called_once()


class TestSingleCandidateFastPath(unittest.TestCase):
    """Narrowing makes one-candidate lists common, so the fast path that
    accepts them without asking now has to check the name really matches."""

    def test_lone_candidate_matching_the_call_is_accepted_free(self):
        with TemporaryDirectory() as tmp:
            r = LLMEdgeResolver(api_key="sk-test",
                                cache_path=str(Path(tmp) / "c.json"))
            r.client = MagicMock()

            result = r.resolve(caller="a.js::x", raw_call="orders.createOrder",
                               caller_code="", candidates=["createOrder"])

            r.client.resolve_edge.assert_not_called()
            self.assertEqual(result["target"], "createOrder")

    def test_lone_candidate_with_an_unrelated_name_is_not_assumed(self):
        with TemporaryDirectory() as tmp:
            r = LLMEdgeResolver(api_key="sk-test",
                                cache_path=str(Path(tmp) / "c.json"))
            r.client = MagicMock()
            r.client.resolve_edge.return_value = {
                "target": None, "confidence": 0.9, "reasoning": "external"}

            result = r.resolve(caller="a.js::x", raw_call="orders.shipEverything",
                               caller_code="", candidates=["createOrder"])

            r.client.resolve_edge.assert_called_once()
            self.assertIsNone(result["target"])


if __name__ == "__main__":
    unittest.main()
