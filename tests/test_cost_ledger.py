"""
Tests for the persistent cost ledger (SQLite) and multi-API-key attribution.

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_cost_ledger.py -v
"""
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.config import AppConfig
from src.llm.client import LLMClient
from src.llm.cost_ledger import CostLedger
from src.llm.pricing import TokenUsage
from src.models import CodeSample, Language


def _sample() -> CodeSample:
    return CodeSample(
        function_name="getUser",
        file_path="app.py",
        code="def getUser(id):\n    return db.execute('SELECT * FROM users WHERE id=' + id)\n",
        language=Language.PYTHON,
        start_line=1,
        end_line=2,
    )


# ── CostLedger — basic record/query ──────────────────────────────────────────

def test_record_and_total(tmp_path):
    ledger = CostLedger(db_path=str(tmp_path / "ledger.db"))
    ledger.record(
        provider="openai", api_key_alias="default", model="o4-mini", phase="analysis",
        usage=TokenUsage(100, 50, 150), cost_usd=0.0005, run_id="run1",
    )
    ledger.record(
        provider="openai", api_key_alias="default", model="o4-mini", phase="analysis",
        usage=TokenUsage(50, 25, 75), cost_usd=0.00025, run_id="run1",
    )

    total = ledger.total()
    assert total.calls == 2
    assert total.total_tokens == 225
    assert total.cost_usd == pytest.approx(0.00075)


def test_total_scoped_to_run_id(tmp_path):
    ledger = CostLedger(db_path=str(tmp_path / "ledger.db"))
    ledger.record(
        provider="openai", api_key_alias="default", model="o4-mini", phase="analysis",
        usage=TokenUsage(100, 50, 150), cost_usd=0.0005, run_id="run1",
    )
    ledger.record(
        provider="openai", api_key_alias="default", model="o4-mini", phase="analysis",
        usage=TokenUsage(999, 999, 1998), cost_usd=1.0, run_id="run2",
    )

    total_run1 = ledger.total(run_id="run1")
    assert total_run1.calls == 1
    assert total_run1.total_tokens == 150
    assert total_run1.cost_usd == pytest.approx(0.0005)


def test_by_phase_breaks_down_correctly(tmp_path):
    ledger = CostLedger(db_path=str(tmp_path / "ledger.db"))
    ledger.record(
        provider="openai", api_key_alias="default", model="o4-mini", phase="edge_resolution",
        usage=TokenUsage(40, 10, 50), cost_usd=0.0001, run_id="run1",
    )
    ledger.record(
        provider="openai", api_key_alias="default", model="o4-mini", phase="react_loop",
        usage=TokenUsage(200, 100, 300), cost_usd=0.001, run_id="run1",
    )
    ledger.record(
        provider="openai", api_key_alias="default", model="o4-mini", phase="react_loop",
        usage=TokenUsage(50, 25, 75), cost_usd=0.00025, run_id="run1",
    )

    rows = {r.group_key: r for r in ledger.by_phase(run_id="run1")}
    assert rows["edge_resolution"].calls == 1
    assert rows["react_loop"].calls == 2
    assert rows["react_loop"].total_tokens == 375
    assert rows["react_loop"].cost_usd == pytest.approx(0.00125)


def test_by_phase_group_cost_is_none_if_any_event_unknown(tmp_path):
    ledger = CostLedger(db_path=str(tmp_path / "ledger.db"))
    ledger.record(
        provider="openai", api_key_alias="default", model="o4-mini", phase="patch_generation",
        usage=TokenUsage(100, 50, 150), cost_usd=0.0005, run_id="run1",
    )
    ledger.record(
        provider="openai", api_key_alias="default", model="some-unpriced-model", phase="patch_generation",
        usage=TokenUsage(100, 50, 150), cost_usd=None, run_id="run1",
    )

    rows = ledger.by_phase(run_id="run1")
    assert len(rows) == 1
    assert rows[0].calls == 2
    assert rows[0].cost_usd is None, "one unknown-cost event must make the whole group unknown, not silently $0"


# ── Multi-API-key attribution ────────────────────────────────────────────────

def test_by_run_orders_by_recency_not_run_id(tmp_path):
    """run_id embeds the model name before the timestamp, so alphabetical
    ordering groups by model rather than by time. The older run here sorts
    LAST alphabetically but must still come out second."""
    ledger = CostLedger(db_path=str(tmp_path / "ledger.db"))
    ledger.record(  # recorded first => older
        provider="openai", api_key_alias="default", model="o4-mini", phase="analysis",
        usage=TokenUsage(10, 5, 15), cost_usd=0.0001, run_id="analysis_o4_mini_20260101_000000",
    )
    ledger.record(  # recorded second => newer, but sorts EARLIER alphabetically
        provider="openai", api_key_alias="default", model="gpt-4o-mini", phase="analysis",
        usage=TokenUsage(20, 10, 30), cost_usd=0.0002, run_id="analysis_gpt_4o_mini_20260202_000000",
    )

    rows = ledger.by_run()
    assert [r.group_key for r in rows] == [
        "analysis_gpt_4o_mini_20260202_000000",
        "analysis_o4_mini_20260101_000000",
    ]


def test_by_run_limit_keeps_the_most_recent(tmp_path):
    ledger = CostLedger(db_path=str(tmp_path / "ledger.db"))
    for i in range(5):
        ledger.record(
            provider="openai", api_key_alias="default", model="o4-mini", phase="analysis",
            usage=TokenUsage(10, 5, 15), cost_usd=0.0001, run_id=f"run{i}",
        )

    rows = ledger.by_run(limit=2)
    assert len(rows) == 2
    assert rows[0].group_key == "run4", "newest run must come first"


def test_by_api_key_attributes_spend_to_the_correct_key(tmp_path):
    ledger = CostLedger(db_path=str(tmp_path / "ledger.db"))
    ledger.record(
        provider="openai", api_key_alias="default", model="o4-mini", phase="analysis",
        usage=TokenUsage(100, 50, 150), cost_usd=0.0005, run_id="run1",
    )
    ledger.record(
        provider="openai", api_key_alias="team2", model="o4-mini", phase="analysis",
        usage=TokenUsage(400, 200, 600), cost_usd=0.002, run_id="run2",
    )

    rows = {r.group_key: r for r in ledger.by_api_key()}
    assert rows["default"].total_tokens == 150
    assert rows["team2"].total_tokens == 600
    assert rows["team2"].cost_usd == pytest.approx(0.002)


def test_config_resolve_api_key_default(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-default-key")
    config = AppConfig()
    key, alias = config.resolve_api_key(None)
    assert key == "sk-default-key"
    assert alias == "default"


def test_config_resolve_api_key_named_alias(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-default-key")
    monkeypatch.setenv("OPENAI_API_KEY_TEAM2", "sk-team2-key")
    config = AppConfig()
    key, alias = config.resolve_api_key("team2")
    assert key == "sk-team2-key"
    assert alias == "team2"


def test_config_resolve_api_key_missing_alias_raises(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY_GHOST", raising=False)
    config = AppConfig()
    with pytest.raises(EnvironmentError):
        config.resolve_api_key("ghost")


# ── LLMClient actually writes to the ledger it's given ───────────────────────

def test_llm_client_writes_to_provided_ledger(tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    ledger = CostLedger(db_path=str(tmp_path / "ledger.db"))
    from src.config import LLMConfig
    client = LLMClient(
        LLMConfig(model="o4-mini"), api_key_alias="team2",
        cost_ledger=ledger, run_id="run-xyz", dataset="demo",
    )

    response = MagicMock()
    content = json.dumps({
        "vulnerability_found": True, "cwe_id": "CWE-89", "affected_lines": [1],
        "severity": "high", "explanation": "sqli", "patch_suggestion": "params",
        "confidence": 0.9, "hallucination_flag": False,
    })
    response.choices = [MagicMock(message=MagicMock(content=content))]
    response.usage = MagicMock(prompt_tokens=100, completion_tokens=50, total_tokens=150)
    client.client.chat.completions.create = MagicMock(return_value=response)

    client.analyze(_sample(), context_prompt="analyze this", phase="call_graph_context")

    rows = ledger.by_phase(run_id="run-xyz")
    assert len(rows) == 1
    assert rows[0].group_key == "call_graph_context"
    assert rows[0].total_tokens == 150

    key_rows = {r.group_key: r for r in ledger.by_api_key(run_id="run-xyz")}
    assert "team2" in key_rows
    assert key_rows["team2"].total_tokens == 150


def test_llm_client_without_ledger_does_not_crash(monkeypatch):
    """cost_ledger is optional — omitting it must not change analyze() behavior."""
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    from src.config import LLMConfig
    client = LLMClient(LLMConfig(model="o4-mini"))  # no cost_ledger passed

    response = MagicMock()
    content = json.dumps({
        "vulnerability_found": False, "cwe_id": None, "affected_lines": [],
        "severity": None, "explanation": "", "patch_suggestion": "",
        "confidence": 0.1, "hallucination_flag": False,
    })
    response.choices = [MagicMock(message=MagicMock(content=content))]
    response.usage = MagicMock(prompt_tokens=10, completion_tokens=5, total_tokens=15)
    client.client.chat.completions.create = MagicMock(return_value=response)

    report = client.analyze(_sample(), context_prompt="analyze this")
    assert report.token_usage.total_tokens == 15
