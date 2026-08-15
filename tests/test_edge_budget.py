"""
Tests for the spending ceiling on call-graph edge resolution.

The regression these exist for: `--budget-usd 5.0` was checked only between
functions in the analysis loop, and edge resolution runs *before* that loop. A
Juice Shop run therefore billed $31 against a $5 ceiling while never reaching
the code that enforces it — it was still resolving edges four days after it
started, resuming every time the machine woke.

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_edge_budget.py -v
"""
import sys
from pathlib import Path

import pytest

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.context.llm_edge_resolver import LLMEdgeResolver
from src.llm.pricing import TokenUsage

MODEL = "o4-mini"
CANDIDATES = ["registerUser", "loginUser", "deleteUser"]


class FakeClient:
    """Stands in for OpenAIResolver: counts calls and reports rising usage.

    Cost is what the ceiling is measured in, so the usage has to grow with each
    call or nothing would ever trip it.
    """

    def __init__(self, tokens_per_call: int = 200_000):
        self.calls = 0
        self.tokens_per_call = tokens_per_call

    def resolve_edge(self, payload: dict) -> dict:
        self.calls += 1
        return {"target": CANDIDATES[0], "confidence": 0.9, "reasoning": "fake"}

    def get_usage(self) -> TokenUsage:
        return TokenUsage(
            prompt_tokens=self.calls * self.tokens_per_call,
            completion_tokens=0,
            total_tokens=self.calls * self.tokens_per_call,
        )


@pytest.fixture()
def resolver(tmp_path):
    def build(budget_usd=None, model=MODEL, tokens_per_call=200_000):
        r = LLMEdgeResolver(
            api_key="sk-test",
            model=model,
            cache_path=str(tmp_path / "edge_cache.json"),
            budget_usd=budget_usd,
        )
        r.client = FakeClient(tokens_per_call=tokens_per_call)
        return r
    return build


def _resolve_many(r, n: int) -> None:
    """n distinct edges, so the cache never serves them and each costs money."""
    for i in range(n):
        r.resolve(f"caller{i}", f"someCall{i}", "code", CANDIDATES)


def test_resolution_stops_once_the_ceiling_is_reached(resolver):
    """The whole point: an unbounded phase cannot outspend the ceiling."""
    r = resolver(budget_usd=1.0)
    _resolve_many(r, 40)

    assert r.budget_exhausted is True
    assert r.spend_usd() <= 1.0 + _one_call_cost(r)
    assert r.budget_skipped > 0
    # It stopped buying; it did not stop being asked.
    assert r.client.calls < 40


def test_without_a_ceiling_nothing_is_capped(resolver):
    """The default is unchanged — a ceiling is opt-in."""
    r = resolver(budget_usd=None)
    _resolve_many(r, 20)

    assert r.budget_exhausted is False
    assert r.budget_skipped == 0
    assert r.client.calls == 20


def test_a_skipped_edge_degrades_it_does_not_raise(resolver):
    """Edges already bought are real and the graph they form is worth keeping,
    so hitting the ceiling has to look like an unresolved edge, not a crash."""
    r = resolver(budget_usd=0.5)
    _resolve_many(r, 30)

    verdict = r.resolve("callerX", "someCallX", "code", CANDIDATES)
    assert verdict["target"] is None
    assert verdict["resolved_by"] == "budget_skip"
    assert verdict["confidence"] == 0.0


def test_the_ceiling_never_blocks_a_free_cache_hit(resolver):
    """A cache hit costs nothing, so refusing to serve it once the ceiling is
    reached would degrade the graph for no saving at all."""
    r = resolver(budget_usd=0.5)
    first = r.resolve("caller", "theCall", "code", CANDIDATES)
    assert first["resolved_by"] == "llm"

    _resolve_many(r, 40)
    assert r.budget_exhausted is True

    again = r.resolve("caller", "theCall", "code", CANDIDATES)
    assert again["resolved_by"] == "cache"
    assert again["target"] == CANDIDATES[0]


def test_an_unpriced_model_says_so_rather_than_pretending_to_be_capped(resolver):
    """Treating unknown cost as $0 would silently uncap a run that looks capped.

    The run continues — the same trade the analysis loop makes — but
    `budget_enforceable` goes false so the CLI can say the ceiling is not real.
    """
    r = resolver(budget_usd=0.01, model="not-a-real-model")
    _resolve_many(r, 5)

    assert r.spend_usd() is None
    assert r.budget_enforceable is False
    assert r.budget_exhausted is False
    assert r.client.calls == 5


def test_a_priced_model_reports_the_ceiling_as_enforceable(resolver):
    r = resolver(budget_usd=1.0)
    _resolve_many(r, 3)
    assert r.budget_enforceable is True


def test_the_builder_exposes_the_stop_to_the_cli(tmp_path):
    """The CLI has to be able to say "no functions were analysed and why", which
    it can only do if the stop survives the builder boundary."""
    from src.context.call_graph import CallGraphBuilder

    builder = CallGraphBuilder(api_key="sk-test", model=MODEL, budget_usd=0.5)
    builder.llm_resolver.cache.cache_file = tmp_path / "edge_cache.json"
    builder.llm_resolver.client = FakeClient()

    assert builder.budget_exhausted is False
    _resolve_many(builder.llm_resolver, 40)

    assert builder.budget_exhausted is True
    assert builder.budget_skipped > 0


def test_a_builder_with_no_key_reports_no_budget_state():
    """No api_key means no resolver at all — the properties must not explode."""
    from src.context.call_graph import CallGraphBuilder

    builder = CallGraphBuilder(api_key=None, budget_usd=1.0)
    assert builder.budget_exhausted is False
    assert builder.budget_skipped == 0
    assert builder.budget_enforceable is True


def _one_call_cost(r) -> float:
    """Overshoot allowance: the ceiling is checked *before* a call, so the call
    in flight when it is reached still completes."""
    from src.llm.pricing import estimate_cost

    return estimate_cost(r.model, TokenUsage(
        prompt_tokens=r.client.tokens_per_call,
        completion_tokens=0,
        total_tokens=r.client.tokens_per_call,
    )) or 0.0
