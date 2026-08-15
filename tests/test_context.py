"""Tests for the call-graph context layer — route registrations and guard chains.

Background: juice-shop wires all 171 of its routes inside `server.ts::configureApp`,
a 514-line function that exceeds `max_function_lines` and is therefore skipped.
That left 103 route handlers with no callers in the graph, so the analyzer could
not see the middleware guarding them and reported ten protected handlers as IDOR.
These tests pin the behaviour that fixes it: registrations reach the handler node
even when the registering function was never extracted.

Run with:
    python -m pytest tests/test_context.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.context.call_graph import CallGraphBuilder, nodes_to_dict
from src.models import CodeSample, Language
from src.models.code_sample import RouteDefinition


def _sample(name: str, file_path: str, code: str = "function f () { return 1 }") -> CodeSample:
    return CodeSample(
        function_name=name,
        file_path=file_path,
        code=code,
        language=Language.TYPESCRIPT,
        start_line=1,
        end_line=3,
    )


def _route(method, path, handlers, names, name_index, line, file="server.ts") -> RouteDefinition:
    return RouteDefinition(
        method=method,
        path=path,
        handlers=handlers,
        handler_names=names,
        handler_name_index=name_index,
        source_file=file,
        source_line=line,
    )


# ── RouteDefinition itself ────────────────────────────────────────────────────

class TestGuardChain:

    def setup_method(self):
        self.route = _route(
            "GET", "/api/Addresss",
            ["security.appendUserId()", "utils.asyncHandler(address.getAddress())"],
            ["appendUserId", "asyncHandler", "getAddress"],
            [0, 1, 1],
            449,
        )

    def test_position_of_wrapped_handler(self):
        assert self.route.position_of("appendUserId") == 0
        assert self.route.position_of("getAddress") == 1
        assert self.route.position_of("nothing") is None

    def test_guards_before_the_handler(self):
        assert self.route.guards_before("getAddress") == ["security.appendUserId()"]

    def test_guard_has_nothing_before_it(self):
        assert self.route.guards_before("appendUserId") == []

    def test_unknown_name_claims_no_guards(self):
        """Returning the whole chain for an unmatched name would tell the model a
        function is protected by guards that do not apply to it."""
        assert self.route.guards_before("unrelated") == []


# ── graph attachment ──────────────────────────────────────────────────────────

class TestRouteRegistrations:

    def setup_method(self):
        self.samples = [
            _sample("getAddress", "routes/address.ts"),
            _sample("appendUserId", "lib/insecurity.ts"),
            _sample("isAuthorized", "lib/insecurity.ts"),
            _sample("applyCoupon", "routes/coupon.ts"),
            _sample("retrieveBasket", "routes/basket.ts"),
        ]
        self.routes = [
            _route("USE", "/rest/basket", ["security.isAuthorized()"],
                   ["isAuthorized"], [0], 356),
            _route("GET", "/api/Addresss",
                   ["security.appendUserId()", "utils.asyncHandler(address.getAddress())"],
                   ["appendUserId", "asyncHandler", "getAddress"], [0, 1, 1], 449),
            _route("GET", "/rest/basket/:id",
                   ["utils.asyncHandler(retrieveBasket())"],
                   ["asyncHandler", "retrieveBasket"], [0, 0], 601),
        ]
        builder = CallGraphBuilder()
        self.graph, _ = builder.build(self.samples, routes=self.routes)

    def _node(self, name, file):
        return self.graph[f"{file}::{name}"]

    def test_handler_receives_its_registration(self):
        regs = self._node("getAddress", "routes/address.ts").route_registrations
        assert len(regs) == 1
        assert regs[0]["method"] == "GET"
        assert regs[0]["path"] == "/api/Addresss"
        assert regs[0]["source_line"] == 449

    def test_handler_sees_the_guard_that_runs_before_it(self):
        """This is the fix for the ten IDOR false positives: appendUserId
        overwrites req.body.UserId from the verified JWT before the handler runs."""
        regs = self._node("getAddress", "routes/address.ts").route_registrations
        assert regs[0]["guards_before"] == ["security.appendUserId()"]

    def test_middleware_is_also_an_entry_point_with_its_own_registration(self):
        node = self._node("appendUserId", "lib/insecurity.ts")
        assert node.is_entry_point
        assert node.route_registrations[0]["path"] == "/api/Addresss"
        assert node.route_registrations[0]["guards_before"] == []

    def test_prefix_guard_is_folded_into_a_route_beneath_it(self):
        regs = self._node("retrieveBasket", "routes/basket.ts").route_registrations
        guards = regs[0]["prefix_guards"]
        assert len(guards) == 1
        assert guards[0]["path"] == "/rest/basket"
        assert guards[0]["handlers"] == ["security.isAuthorized()"]

    def test_unrelated_route_gets_no_prefix_guard(self):
        regs = self._node("getAddress", "routes/address.ts").route_registrations
        assert regs[0]["prefix_guards"] == []

    def test_registrations_are_serialized(self):
        plain = nodes_to_dict(self.graph)
        node = plain["routes/address.ts::getAddress"]
        assert node["route_registrations"][0]["guards_before"] == ["security.appendUserId()"]

    def test_wrapped_handler_is_matched_at_all(self):
        """`utils.asyncHandler(address.getAddress())` — the old code looked at the
        raw handler text, whose last dotted segment is `asyncHandler(address.getAddress())`,
        and matched nothing."""
        assert self._node("getAddress", "routes/address.ts").is_entry_point


class TestPrefixGuardOrdering:

    def test_guard_registered_after_a_route_does_not_protect_it(self):
        """Express applies middleware in registration order. Folding in a later
        guard would invent authorization that does not exist."""
        samples = [_sample("retrieveBasket", "routes/basket.ts")]
        routes = [
            _route("GET", "/rest/basket/:id", ["retrieveBasket"],
                   ["retrieveBasket"], [0], 300),
            _route("USE", "/rest/basket", ["security.isAuthorized()"],
                   ["isAuthorized"], [0], 900),   # registered later
        ]
        graph, _ = CallGraphBuilder().build(samples, routes=routes)
        regs = graph["routes/basket.ts::retrieveBasket"].route_registrations
        assert regs[0]["prefix_guards"] == []

    def test_prefix_match_respects_segment_boundaries(self):
        assert CallGraphBuilder._path_covers("/rest/basket", "/rest/basket/:id")
        assert CallGraphBuilder._path_covers("/rest/basket", "/rest/basket")
        assert not CallGraphBuilder._path_covers("/api/Card", "/api/Cards")
        assert not CallGraphBuilder._path_covers("", "/api/Cards")

    def test_global_middleware_is_not_a_prefix_guard(self):
        """`app.use(compression())` has no mount path. Treating it as covering
        everything would bury every prompt in parser and logger middleware."""
        glob = _route("USE", "", ["compression()"], ["compression"], [0], 179)
        assert not glob.is_prefix_guard


class TestNoRoutes:

    def test_function_with_no_registration_has_none(self):
        samples = [_sample("helper", "lib/util.ts")]
        graph, _ = CallGraphBuilder().build(samples, routes=[])
        assert graph["lib/util.ts::helper"].route_registrations == []
