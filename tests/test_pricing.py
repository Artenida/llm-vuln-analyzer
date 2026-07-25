"""
Tests for Sprint 7 — token usage capture & cost tracking.

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_pricing.py -v
"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.agent.react_loop import ReActAgent
from src.config import LLMConfig
from src.context.llm_edge_resolver import LLMEdgeResolver
from src.llm.client import LLMClient, ReActStep, VulnerabilityReport
from src.llm.openai_client import OpenAIResolver
from src.llm.pricing import TokenUsage, estimate_cost, extract_usage
from src.models import CodeSample, Language


# ── TokenUsage / estimate_cost / extract_usage ──────────────────────────────

def test_token_usage_add_sums_all_fields():
    a = TokenUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)
    b = TokenUsage(prompt_tokens=3, completion_tokens=2, total_tokens=5)
    c = a + b
    assert c.prompt_tokens == 13
    assert c.completion_tokens == 7
    assert c.total_tokens == 20


def test_estimate_cost_known_model():
    usage = TokenUsage(prompt_tokens=1_000_000, completion_tokens=1_000_000, total_tokens=2_000_000)
    cost = estimate_cost("o4-mini", usage)
    assert cost == pytest.approx(1.10 + 4.40)


def test_estimate_cost_unknown_model_is_none():
    usage = TokenUsage(prompt_tokens=1000, completion_tokens=1000, total_tokens=2000)
    assert estimate_cost("some-future-model", usage) is None


def test_extract_usage_missing_usage_field_returns_zero():
    response = MagicMock()
    response.usage = None
    usage = extract_usage(response)
    assert usage == TokenUsage()


def test_extract_usage_reads_prompt_completion_total():
    response = MagicMock()
    response.usage = MagicMock(prompt_tokens=40, completion_tokens=10, total_tokens=50)
    usage = extract_usage(response)
    assert usage.prompt_tokens == 40
    assert usage.completion_tokens == 10
    assert usage.total_tokens == 50


# ── LLMClient.analyze() / reason() ───────────────────────────────────────────

def _sample() -> CodeSample:
    return CodeSample(
        function_name="getUser",
        file_path="app.py",
        code="def getUser(id):\n    return db.execute('SELECT * FROM users WHERE id=' + id)\n",
        language=Language.PYTHON,
        start_line=1,
        end_line=2,
    )


def _make_llm_client(monkeypatch, model="o4-mini") -> LLMClient:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    return LLMClient(LLMConfig(model=model))


def _mock_completion(content: str, prompt_tokens: int, completion_tokens: int, total_tokens: int):
    response = MagicMock()
    response.choices = [MagicMock(message=MagicMock(content=content))]
    response.usage = MagicMock(
        prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, total_tokens=total_tokens
    )
    return response


_REPORT_JSON = json.dumps({
    "vulnerability_found": True,
    "cwe_id": "CWE-89",
    "affected_lines": [2],
    "severity": "high",
    "explanation": "SQL built via string concatenation",
    "patch_suggestion": "use parameterized query",
    "confidence": 0.9,
    "hallucination_flag": False,
})


def test_analyze_captures_usage_and_cost(monkeypatch):
    client = _make_llm_client(monkeypatch)
    client.client.chat.completions.create = MagicMock(
        return_value=_mock_completion(_REPORT_JSON, 100, 50, 150)
    )

    report = client.analyze(_sample(), context_prompt="analyze this")

    assert report.token_usage.prompt_tokens == 100
    assert report.token_usage.completion_tokens == 50
    assert report.token_usage.total_tokens == 150
    assert report.cost_usd == pytest.approx((100 * 1.10 + 50 * 4.40) / 1_000_000)


def test_analyze_unknown_model_captures_tokens_but_cost_is_none(monkeypatch):
    client = _make_llm_client(monkeypatch, model="some-future-model")
    client.client.chat.completions.create = MagicMock(
        return_value=_mock_completion(_REPORT_JSON, 100, 50, 150)
    )

    report = client.analyze(_sample(), context_prompt="analyze this")

    assert report.token_usage.total_tokens == 150
    assert report.cost_usd is None


def test_analyze_without_context_prompt_still_sends_the_code(monkeypatch):
    """The ReAct loop's single-pass fallback calls analyze() with no context
    prompt — the request must still contain the target function and the
    response schema, not an empty user message."""
    client = _make_llm_client(monkeypatch)
    create = MagicMock(return_value=_mock_completion(_REPORT_JSON, 10, 5, 15))
    client.client.chat.completions.create = create

    client.analyze(_sample(), phase="react_loop_fallback")

    user_message = create.call_args.kwargs["messages"][1]["content"]
    assert user_message.strip(), "user message must not be empty"
    assert "getUser" in user_message
    assert "SELECT * FROM users" in user_message
    assert "vulnerability_found" in user_message


def test_reason_captures_usage_for_a_tool_call_step(monkeypatch):
    client = _make_llm_client(monkeypatch)
    tool_call_json = json.dumps({
        "action": "tool", "tool": "get_callees",
        "args": {"function_name": "getUser"}, "thought": "need callees",
    })
    client.client.chat.completions.create = MagicMock(
        return_value=_mock_completion(tool_call_json, 20, 5, 25)
    )

    step = client.reason(sample=_sample(), tool_history=[])

    assert step.is_final is False
    assert step.token_usage.total_tokens == 25


# ── ReActAgent — usage summed across steps, not just the final one ──────────

class _FakeLLMClient:
    """Stand-in for LLMClient — same interface react_loop.py depends on
    (.config.model, .reason()), no real API calls."""

    def __init__(self, model: str, steps: list[ReActStep]):
        self.config = SimpleNamespace(model=model)
        self._steps = iter(steps)

    def reason(self, **kwargs) -> ReActStep:
        return next(self._steps)


def test_react_loop_sums_token_usage_across_all_steps(monkeypatch):
    tool_step = ReActStep(
        is_final=False, tool_name="get_callees",
        tool_args={"function_name": "getUser"}, reasoning="need callees",
    )
    tool_step.token_usage = TokenUsage(prompt_tokens=10, completion_tokens=5, total_tokens=15)

    final_report = VulnerabilityReport(
        function_name="getUser", file_path="app.py", language="python",
        vulnerability_found=True, cwe_id="CWE-89", affected_lines=[2],
        severity="high", explanation="SQL injection", patch_suggestion="parameterize",
        confidence=0.9, hallucination_flag=False,
    )
    final_step = ReActStep(is_final=True, report=final_report, reasoning="done")
    final_step.token_usage = TokenUsage(prompt_tokens=20, completion_tokens=10, total_tokens=30)

    fake_llm = _FakeLLMClient(model="o4-mini", steps=[tool_step, final_step])
    agent = ReActAgent(llm=fake_llm, tools=None, max_steps=5)

    result = agent.run(_sample(), graph={})

    # summed across BOTH steps, not just the final one
    assert result.token_usage.prompt_tokens == 30
    assert result.token_usage.completion_tokens == 15
    assert result.token_usage.total_tokens == 45
    assert result.cost_usd == pytest.approx(estimate_cost("o4-mini", result.token_usage))


# ── Edge resolution — cache hits must never add spend ────────────────────────

def test_edge_resolver_cache_hit_does_not_add_usage(tmp_path):
    cache_path = tmp_path / "edge_cache.json"
    resolver = LLMEdgeResolver(api_key="test-key", model="o4-mini", cache_path=str(cache_path))

    call_count = {"n": 0}

    def fake_resolve_edge(payload):
        call_count["n"] += 1
        resolver.client.usage_total = resolver.client.usage_total + TokenUsage(
            prompt_tokens=50, completion_tokens=20, total_tokens=70
        )
        return {"target": "bar", "confidence": 0.9, "reasoning": "matched"}

    resolver.client.resolve_edge = fake_resolve_edge

    first = resolver.resolve(caller="foo", raw_call="bar()", caller_code="code", candidates=["bar", "baz"])
    assert first["target"] == "bar"
    assert call_count["n"] == 1
    assert resolver.get_usage().total_tokens == 70

    # second call for the identical (caller, raw_call, candidates) key is a cache hit
    second = resolver.resolve(caller="foo", raw_call="bar()", caller_code="code", candidates=["bar", "baz"])
    assert second["target"] == "bar"
    assert call_count["n"] == 1, "cache hit must not re-invoke the LLM"
    assert resolver.get_usage().total_tokens == 70, "cache hit must not add to spend"


def test_openai_resolver_captures_usage_on_real_call():
    resolver = OpenAIResolver(api_key="test-key", model="o4-mini")
    response = MagicMock()
    response.choices = [MagicMock(message=MagicMock(
        content=json.dumps({"target": "bar", "confidence": 0.9, "reasoning": "match"})
    ))]
    response.usage = MagicMock(prompt_tokens=40, completion_tokens=10, total_tokens=50)
    resolver.client.chat.completions.create = MagicMock(return_value=response)

    result = resolver.resolve_edge({
        "caller": "a", "raw_call": "b()", "caller_code": "code", "candidates": ["bar"],
    })

    assert result["target"] == "bar"
    assert resolver.get_usage().prompt_tokens == 40
    assert resolver.get_usage().completion_tokens == 10
    assert resolver.get_usage().total_tokens == 50
