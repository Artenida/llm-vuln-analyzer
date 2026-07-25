"""
Tests for edge-resolution caching (src/context/llm_edge_resolver.py).

The write path always cached negative verdicts "to avoid re-querying the same
dead ends", but the read path only served an entry when it had a target. On a
repo where most calls go to built-ins that meant almost the whole call graph
was re-bought on every run — 1447 of 1557 cached entries on Juice Shop, about
$6 a run.

No network anywhere here: the OpenAI client is mocked.
"""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock

from src.context.llm_edge_resolver import LLMEdgeResolver, _is_usable_cache_entry

CALL = dict(caller="a.js::handler", raw_call="doWork",
            caller_code="doWork()", candidates=["doWork", "doOther"])


def _resolver(tmp, response):
    r = LLMEdgeResolver(api_key="sk-test", cache_path=str(Path(tmp) / "edge_cache.json"))
    r.client = MagicMock()
    r.client.resolve_edge.return_value = response
    return r


class TestNegativeCaching(unittest.TestCase):

    def test_negative_verdict_is_served_from_cache_not_re_bought(self):
        with TemporaryDirectory() as tmp:
            cache_path = str(Path(tmp) / "edge_cache.json")
            negative = {"target": None, "confidence": 0.95,
                        "reasoning": "doWork is a built-in, not an internal function"}

            first = LLMEdgeResolver(api_key="sk-test", cache_path=cache_path)
            first.client = MagicMock()
            first.client.resolve_edge.return_value = dict(negative)
            first.resolve(**CALL)
            self.assertEqual(first.client.resolve_edge.call_count, 1)

            second = LLMEdgeResolver(api_key="sk-test", cache_path=cache_path)
            second.client = MagicMock()
            result = second.resolve(**CALL)

            second.client.resolve_edge.assert_not_called()
            self.assertIsNone(result["target"])
            self.assertEqual(result["resolved_by"], "cache")
            self.assertEqual(second.negative_cache_hits, 1)

    def test_positive_verdict_still_served_from_cache(self):
        with TemporaryDirectory() as tmp:
            cache_path = str(Path(tmp) / "edge_cache.json")
            hit = {"target": "doWork", "confidence": 0.9, "reasoning": "internal"}

            first = LLMEdgeResolver(api_key="sk-test", cache_path=cache_path)
            first.client = MagicMock()
            first.client.resolve_edge.return_value = dict(hit)
            first.resolve(**CALL)

            second = LLMEdgeResolver(api_key="sk-test", cache_path=cache_path)
            second.client = MagicMock()
            result = second.resolve(**CALL)

            second.client.resolve_edge.assert_not_called()
            self.assertEqual(result["target"], "doWork")
            self.assertEqual(second.negative_cache_hits, 0)


class TestFailuresAreNotCached(unittest.TestCase):
    """A dropped connection and a genuine 'resolves to nothing' both come back
    with target=None. Confusing them turns one transient failure into an edge
    that is missing forever."""

    def test_failed_resolution_is_not_written_to_the_cache(self):
        with TemporaryDirectory() as tmp:
            cache_path = Path(tmp) / "edge_cache.json"
            r = _resolver(tmp, {"target": None, "confidence": 0.0,
                                "reasoning": "error: 401", "error": "401"})

            r.resolve(**CALL)

            if cache_path.exists():
                self.assertEqual(json.loads(cache_path.read_text(encoding="utf-8")), {})

    def test_failure_is_retried_on_the_next_run(self):
        with TemporaryDirectory() as tmp:
            cache_path = str(Path(tmp) / "edge_cache.json")

            failing = LLMEdgeResolver(api_key="sk-test", cache_path=cache_path)
            failing.client = MagicMock()
            failing.client.resolve_edge.return_value = {
                "target": None, "confidence": 0.0, "reasoning": "error: 401", "error": "401"}
            failing.resolve(**CALL)

            recovered = LLMEdgeResolver(api_key="sk-test", cache_path=cache_path)
            recovered.client = MagicMock()
            recovered.client.resolve_edge.return_value = {
                "target": "doWork", "confidence": 0.9, "reasoning": "internal"}
            result = recovered.resolve(**CALL)

            recovered.client.resolve_edge.assert_called_once()
            self.assertEqual(result["target"], "doWork")


class TestUsableCacheEntry(unittest.TestCase):

    def test_real_negative_verdict_is_usable(self):
        self.assertTrue(_is_usable_cache_entry(
            {"target": None, "confidence": 0.95, "reasoning": "built-in method"}))

    def test_tagged_failure_is_not_usable(self):
        self.assertFalse(_is_usable_cache_entry(
            {"target": None, "reasoning": "error: boom", "error": "boom"}))

    def test_legacy_untagged_failure_is_recognised(self):
        """Entries written before failures carried an `error` key — a real
        edge_cache.json holds cached 401s that would otherwise be believed."""
        self.assertFalse(_is_usable_cache_entry(
            {"target": None, "confidence": 0.0,
             "reasoning": "error: Error code: 401 - Incorrect API key provided"}))

    def test_positive_verdict_is_usable(self):
        self.assertTrue(_is_usable_cache_entry(
            {"target": "doWork", "confidence": 0.9, "reasoning": "internal call"}))


if __name__ == "__main__":
    unittest.main()
