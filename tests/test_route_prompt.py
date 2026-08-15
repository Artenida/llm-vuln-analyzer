"""The route context block must actually reach both prompts.

The graph can carry perfect route data and change nothing if the prompt never
renders it - which was the situation before Stage 1: `RouteExtractor` ran on
every file and its output went into entry-point flags only, never into a prompt.
These tests pin the wiring, not the data.

Run with:
    python -m pytest tests/test_route_prompt.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.agent.tools import ToolSet
from src.context.call_graph import CallGraphBuilder, nodes_to_dict
from src.context.route_context import format_route_block
from src.llm.client import _REACT_STATE_TEMPLATE, _REACT_SYSTEM
from src.models import CodeSample, Language
from src.models.code_sample import RouteDefinition


GUARDED = [{
    "method": "GET",
    "path": "/api/Addresss",
    "source_file": "server.ts",
    "source_line": 449,
    "handlers": ["security.appendUserId()", "utils.asyncHandler(address.getAddress())"],
    "guards_before": ["security.appendUserId()"],
    "prefix_guards": [],
}]


class TestFormatRouteBlock:

    def test_guard_chain_is_rendered_in_order(self):
        text = format_route_block(GUARDED, "getAddress")
        assert "GET /api/Addresss" in text
        assert "security.appendUserId()" in text
        assert "server.ts:449" in text

    def test_absent_registration_says_unknown_not_unguarded(self):
        """The distinction that caused ten false IDOR reports: with no route
        table at all, every handler looked unguarded rather than unestablished."""
        text = format_route_block([], "getAddress")
        assert "No HTTP route registration was found" in text
        assert "Do NOT conclude" in text

    def test_empty_chain_is_stated_explicitly(self):
        """A handler that really is first in the chain must say so - silence here
        is indistinguishable from missing data."""
        reg = [dict(GUARDED[0], guards_before=[])]
        text = format_route_block(reg, "getMemories")
        assert "nothing" in text

    def test_prefix_guards_are_rendered(self):
        reg = [dict(GUARDED[0], prefix_guards=[{
            "path": "/rest/basket",
            "handlers": ["security.isAuthorized()"],
            "source_file": "server.ts",
            "source_line": 356,
        }])]
        text = format_route_block(reg, "applyCoupon")
        assert "path prefix '/rest/basket'" in text
        assert "security.isAuthorized()" in text

    def test_long_registration_lists_are_capped_and_counted(self):
        many = [dict(GUARDED[0], path=f"/r{i}") for i in range(10)]
        text = format_route_block(many, "handler", max_routes=3)
        assert "/r0" in text and "/r9" not in text
        assert "7 further registration(s)" in text

    def test_block_warns_that_guard_names_can_mislead(self):
        """Handing over a guard list invites the opposite error - trusting a name.
        isAuthorized checks authentication, not ownership."""
        text = format_route_block(GUARDED, "getAddress")
        assert "get_source" in text


class TestReActPrompt:

    def test_state_template_has_a_route_context_slot(self):
        assert "{route_context}" in _REACT_STATE_TEMPLATE

    def test_state_renders_with_the_block(self):
        rendered = _REACT_STATE_TEMPLATE.format(
            function_name="getAddress",
            file_path="routes/address.ts",
            start_line=1,
            end_line=9,
            language="typescript",
            code="function getAddress () {}",
            route_context=format_route_block(GUARDED, "getAddress"),
            tool_history="(none yet)",
        )
        assert "=== ROUTE CONTEXT ===" in rendered
        assert "security.appendUserId()" in rendered
        # Ordering matters: the model should meet the context before the task.
        assert rendered.index("ROUTE CONTEXT") < rendered.index("TOOL HISTORY")

    def test_system_prompt_documents_the_tool_and_the_rule(self):
        assert "get_route_context" in _REACT_SYSTEM
        assert "unknown, NOT unguarded" in _REACT_SYSTEM


class TestSinglePassPrompt:

    def test_context_prompt_includes_the_block(self):
        """Both modes must see the same context, or a measured difference between
        them stops being a fact about the modes."""
        from src.cli import _build_context_prompt

        sample = CodeSample(
            function_name="getAddress",
            file_path="routes/address.ts",
            code="function getAddress () {}",
            language=Language.TYPESCRIPT,
            start_line=1,
            end_line=9,
        )
        routes = [RouteDefinition(
            method="GET", path="/api/Addresss",
            handlers=["security.appendUserId()", "utils.asyncHandler(address.getAddress())"],
            handler_names=["appendUserId", "asyncHandler", "getAddress"],
            handler_name_index=[0, 1, 1],
            source_file="server.ts", source_line=449,
        )]
        graph, name_index = CallGraphBuilder().build([sample], routes=routes)
        tools = ToolSet(graph, name_index)

        prompt = _build_context_prompt(
            sample, {"callers": [], "callees": []}, tools, [sample]
        )

        assert "=== ROUTE CONTEXT ===" in prompt
        assert "security.appendUserId()" in prompt


class TestToolSetAccess:

    def test_get_route_context_reads_plain_dict_graphs(self):
        """ToolSet is handed live CallGraphNode objects during a run and plain
        dicts when a saved graph is reloaded. Both must work."""
        sample = CodeSample(
            function_name="getAddress", file_path="routes/address.ts",
            code="function getAddress () {}", language=Language.TYPESCRIPT,
            start_line=1, end_line=9,
        )
        routes = [RouteDefinition(
            method="GET", path="/api/Addresss",
            handlers=["security.appendUserId()", "address.getAddress()"],
            handler_names=["appendUserId", "getAddress"],
            handler_name_index=[0, 1],
            source_file="server.ts", source_line=449,
        )]
        graph, name_index = CallGraphBuilder().build([sample], routes=routes)

        live = ToolSet(graph, name_index).get_route_context("getAddress")
        reloaded = ToolSet(nodes_to_dict(graph), name_index).get_route_context("getAddress")

        assert live[0]["guards_before"] == ["security.appendUserId()"]
        assert reloaded == live

    def test_unknown_function_returns_empty(self):
        assert ToolSet({}, {}).get_route_context("nope") == []
