"""
Tests for incremental run persistence (src/results/checkpoint.py) and the
offline edge-resolution mode that makes `analyze --dry-run` actually free.

No LLM calls anywhere in here.
"""
import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from src.llm.client import VulnerabilityReport
from src.llm.pricing import TokenUsage
from src.results.checkpoint import (
    CheckpointHeader,
    CheckpointMismatch,
    RunCheckpoint,
)


def _report(name: str, file_path: str = "app/x.js", found: bool = False,
            prompt: int = 100, completion: int = 20) -> VulnerabilityReport:
    return VulnerabilityReport(
        function_name=name,
        file_path=file_path,
        language="javascript",
        vulnerability_found=found,
        cwe_id="CWE-89" if found else None,
        affected_lines=[12] if found else [],
        severity="high" if found else None,
        explanation="because" if found else "",
        patch_suggestion="",
        confidence=0.9,
        hallucination_flag=False,
        analysis_mode="react_loop",
        token_usage=TokenUsage(prompt_tokens=prompt, completion_tokens=completion,
                               total_tokens=prompt + completion),
        cost_usd=0.001,
    )


class _Sample:
    """Minimal stand-in for CodeSample — only the two fields the checkpoint
    validates against."""
    def __init__(self, function_name, file_path):
        self.function_name = function_name
        self.file_path = file_path


def _header(total=3, model="o4-mini", mode="react_loop", source="app-test/x"):
    return CheckpointHeader(model=model, source_path=source,
                            analysis_mode=mode, total_samples=total)


class TestCheckpointRoundTrip(unittest.TestCase):

    def test_append_then_load_restores_reports(self):
        with TemporaryDirectory() as tmp:
            ck = RunCheckpoint(tmp)
            ck.start(_header())
            ck.append(0, _report("alpha", found=True))
            ck.append(1, _report("beta"))

            loaded = ck.load_completed(_header())

            self.assertEqual(sorted(loaded), [0, 1])
            self.assertEqual(loaded[0].function_name, "alpha")
            self.assertTrue(loaded[0].vulnerability_found)
            self.assertEqual(loaded[0].cwe_id, "CWE-89")
            self.assertFalse(loaded[1].vulnerability_found)

    def test_token_usage_survives_the_round_trip(self):
        """Cost totals on a resumed run are only right if the usage of the
        already-completed functions comes back with them."""
        with TemporaryDirectory() as tmp:
            ck = RunCheckpoint(tmp)
            ck.start(_header())
            ck.append(0, _report("alpha", prompt=300, completion=40))

            restored = ck.load_completed(_header())[0]

            self.assertIsInstance(restored.token_usage, TokenUsage)
            self.assertEqual(restored.token_usage.prompt_tokens, 300)
            self.assertEqual(restored.token_usage.completion_tokens, 40)
            self.assertEqual(restored.token_usage.total_tokens, 340)

    def test_start_is_idempotent_and_keeps_existing_records(self):
        with TemporaryDirectory() as tmp:
            ck = RunCheckpoint(tmp)
            ck.start(_header())
            ck.append(0, _report("alpha"))
            ck.start(_header())          # second invocation, resuming

            self.assertEqual(len(ck.load_completed(_header())), 1)

    def test_clear_removes_the_file(self):
        with TemporaryDirectory() as tmp:
            ck = RunCheckpoint(tmp)
            ck.start(_header())
            ck.append(0, _report("alpha"))
            self.assertTrue(ck.exists)

            ck.clear()

            self.assertFalse(ck.exists)


class TestCheckpointRefusesWrongResume(unittest.TestCase):
    """Resuming the wrong checkpoint silently skips functions that were never
    analysed and reports the result as a complete run — worse than not
    resuming at all. Every one of these must raise."""

    def test_different_model_is_rejected(self):
        with TemporaryDirectory() as tmp:
            ck = RunCheckpoint(tmp)
            ck.start(_header(model="o4-mini"))
            ck.append(0, _report("alpha"))

            with self.assertRaises(CheckpointMismatch):
                ck.load_completed(_header(model="gpt-4o-mini"))

    def test_different_mode_is_rejected(self):
        with TemporaryDirectory() as tmp:
            ck = RunCheckpoint(tmp)
            ck.start(_header(mode="react_loop"))
            ck.append(0, _report("alpha"))

            with self.assertRaises(CheckpointMismatch):
                ck.load_completed(_header(mode="call_graph_context"))

    def test_different_function_count_is_rejected(self):
        with TemporaryDirectory() as tmp:
            ck = RunCheckpoint(tmp)
            ck.start(_header(total=3))
            ck.append(0, _report("alpha"))

            with self.assertRaises(CheckpointMismatch):
                ck.load_completed(_header(total=4))

    def test_function_moved_to_a_different_index_is_rejected(self):
        """Same file, same count, but the source was edited and the functions
        shifted — index 0 no longer holds what the checkpoint recorded."""
        with TemporaryDirectory() as tmp:
            ck = RunCheckpoint(tmp)
            ck.start(_header(total=2))
            ck.append(0, _report("alpha"))

            shifted = [_Sample("beta", "app/x.js"), _Sample("alpha", "app/x.js")]

            with self.assertRaises(CheckpointMismatch):
                ck.load_completed(_header(total=2), samples=shifted)

    def test_matching_samples_are_accepted(self):
        with TemporaryDirectory() as tmp:
            ck = RunCheckpoint(tmp)
            ck.start(_header(total=2))
            ck.append(0, _report("alpha"))

            unchanged = [_Sample("alpha", "app/x.js"), _Sample("beta", "app/x.js")]
            loaded = ck.load_completed(_header(total=2), samples=unchanged)

            self.assertEqual(list(loaded), [0])

    def test_headerless_file_is_rejected(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "checkpoint.jsonl"
            p.write_text("not json at all\n", encoding="utf-8")

            with self.assertRaises(CheckpointMismatch):
                RunCheckpoint(tmp).load_completed(_header())


class TestCheckpointSurvivesInterruption(unittest.TestCase):

    def test_half_written_last_line_is_dropped_not_fatal(self):
        """A process killed mid-write leaves a truncated final line. That one
        function gets re-analysed; the rest must still load."""
        with TemporaryDirectory() as tmp:
            ck = RunCheckpoint(tmp)
            ck.start(_header())
            ck.append(0, _report("alpha"))
            ck.append(1, _report("beta"))

            with open(ck.path, "a", encoding="utf-8") as f:
                f.write('{"kind": "report", "index": 2, "function_na')

            loaded = ck.load_completed(_header())

            self.assertEqual(sorted(loaded), [0, 1])

    def test_resumed_reports_sort_back_into_function_order(self):
        """A resumed run fills gaps out of completion order; findings must come
        out ordered by function index, which is what the CLI relies on."""
        with TemporaryDirectory() as tmp:
            ck = RunCheckpoint(tmp)
            ck.start(_header(total=3))
            ck.append(2, _report("gamma"))
            ck.append(0, _report("alpha"))
            ck.append(1, _report("beta"))

            loaded = ck.load_completed(_header(total=3))
            names = [loaded[k].function_name for k in sorted(loaded)]

            self.assertEqual(names, ["alpha", "beta", "gamma"])


class TestOfflineEdgeResolution(unittest.TestCase):
    """`analyze --dry-run` is documented as making no LLM calls. It builds the
    call graph first, so edge resolution has to be the thing that stays home."""

    def _resolver(self, offline: bool):
        from src.context.llm_edge_resolver import LLMEdgeResolver
        with TemporaryDirectory() as tmp:
            r = LLMEdgeResolver(
                api_key="sk-test",
                cache_path=str(Path(tmp) / "edge_cache.json"),
                offline=offline,
            )
            r.client = MagicMock()
            r.client.resolve_edge.return_value = {"target": "doWork", "confidence": 0.9}
            yield r

    def test_offline_miss_never_calls_the_api(self):
        for r in self._resolver(offline=True):
            result = r.resolve(caller="a::b", raw_call="doWork",
                               caller_code="doWork()", candidates=["doWork", "doOther"])

            r.client.resolve_edge.assert_not_called()
            self.assertIsNone(result["target"])
            self.assertEqual(result["resolved_by"], "offline_skip")
            self.assertEqual(r.offline_misses, 1)

    def test_online_miss_does_call_the_api(self):
        """The guard must be specific to offline mode, not a blanket disable."""
        for r in self._resolver(offline=False):
            result = r.resolve(caller="a::b", raw_call="doWork",
                               caller_code="doWork()", candidates=["doWork", "doOther"])

            r.client.resolve_edge.assert_called_once()
            self.assertEqual(result["target"], "doWork")
            self.assertEqual(r.offline_misses, 0)

    def test_offline_still_serves_cache_hits(self):
        """Cache hits are free, so a dry run should still benefit from them —
        that is the difference between a useful preview graph and an empty one."""
        from src.context.llm_edge_resolver import LLMEdgeResolver
        with TemporaryDirectory() as tmp:
            cache_path = str(Path(tmp) / "edge_cache.json")

            warm = LLMEdgeResolver(api_key="sk-test", cache_path=cache_path)
            warm.client = MagicMock()
            warm.client.resolve_edge.return_value = {"target": "doWork", "confidence": 0.9}
            warm.resolve(caller="a::b", raw_call="doWork",
                         caller_code="doWork()", candidates=["doWork", "doOther"])

            cold = LLMEdgeResolver(api_key="sk-test", cache_path=cache_path, offline=True)
            cold.client = MagicMock()
            result = cold.resolve(caller="a::b", raw_call="doWork",
                                  caller_code="doWork()", candidates=["doWork", "doOther"])

            cold.client.resolve_edge.assert_not_called()
            self.assertEqual(result["target"], "doWork")
            self.assertEqual(result["resolved_by"], "cache")
            self.assertEqual(cold.offline_misses, 0)

    def test_builder_passes_offline_through(self):
        from src.context.call_graph import CallGraphBuilder

        builder = CallGraphBuilder(api_key="sk-test", offline_edges=True)

        self.assertIsNotNone(builder.llm_resolver)
        self.assertTrue(builder.llm_resolver.offline)
        self.assertEqual(builder.get_offline_misses(), 0)


if __name__ == "__main__":
    unittest.main()
