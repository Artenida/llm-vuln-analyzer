"""Express-style route registration extraction.

Why this is AST-based
---------------------
The previous regex matched `router.(get|post|put|delete)` only, and split the
argument list on every comma. On juice-shop that found essentially nothing: the
app registers 171 routes as `app.*`, and its handlers are wrapped
(`utils.asyncHandler(payment.getPaymentMethods())`) so a naive comma split
produces fragments rather than handlers.

The cost of that miss was not cosmetic. All of juice-shop's route wiring lives
in `server.ts::configureApp`, which is 514 lines and therefore over
`max_function_lines` - so it is the one function the extractor skips. With no
route table either, 103 route handlers ended up with no callers in the call
graph and the analyzer could not see the guards protecting them, which
manufactured 12 false positives on its own.

Route extraction runs on raw file *content*, before any function-size filtering,
so the table is recoverable whether or not the enclosing function is analysable.
That is what makes this fix independent of chunking oversized functions.
"""
from __future__ import annotations

import logging
from typing import List, Optional

from src.ingestion.parser import TreeSitterParser, node_text
from src.models.code_sample import RouteDefinition

logger = logging.getLogger(__name__)

# Objects that register routes. `server` and `api` are common aliases for an
# Express app; including them costs nothing and misses less.
_ROUTER_OBJECTS = {"app", "router", "server", "api"}

_ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "all", "use"}

# Languages this can parse. Express is a JS/TS framework; asking for routes in a
# C file is not an error, it just has none.
_SUPPORTED = {"javascript", "typescript", "tsx"}


def _string_literal(node) -> bool:
    return node.type in ("string", "template_string")


def _strip_quotes(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] in "\"'`" and text[-1] == text[0]:
        return text[1:-1]
    return text


def _callee_name(fn_node, source_bytes: bytes) -> Optional[str]:
    """The name being called: the property for `a.b()`, the identifier for `b()`."""
    if fn_node.type == "member_expression":
        prop = fn_node.child_by_field_name("property")
        return node_text(prop, source_bytes) if prop is not None else None
    if fn_node.type == "identifier":
        return node_text(fn_node, source_bytes)
    return None


def _callable_names(node, source_bytes: bytes, out: List[str]) -> None:
    """Collect callable names inside a handler argument, outermost call first.

    `utils.asyncHandler(payment.getPaymentMethods())` yields
    ["asyncHandler", "getPaymentMethods"] - the wrapper and the function that
    actually handles the request. Both are kept because either may be the name
    the call graph knows the function by, and the caller decides which to use.

    Recursion deliberately follows a call's *arguments* and not its callee: the
    receiver in `payment.getPaymentMethods()` is the module object `payment`,
    which is not a handler and only adds noise to the matching candidates.
    """
    if node.type == "call_expression":
        fn = node.child_by_field_name("function")
        if fn is not None:
            name = _callee_name(fn, source_bytes)
            if name:
                out.append(name)
        args = node.child_by_field_name("arguments")
        if args is not None:
            for child in args.children:
                if child.is_named:
                    _callable_names(child, source_bytes, out)
        return

    if node.type == "member_expression":
        # A bare handler reference: `app.use('/x', middlewares.checkAuth)`
        prop = node.child_by_field_name("property")
        if prop is not None:
            out.append(node_text(prop, source_bytes))
        return

    if node.type == "identifier":
        # A bare handler reference: `app.post('/x', ensureFileIsPassed, ...)`
        out.append(node_text(node, source_bytes))
        return

    for child in node.children:
        if child.is_named:
            _callable_names(child, source_bytes, out)


class RouteExtractor:

    def __init__(self, parser: Optional[TreeSitterParser] = None):
        # Shared with the caller where possible - grammars are cached globally,
        # but the parser object is cheap and stateless enough to make its own.
        self.parser = parser or TreeSitterParser()

    def extract(self, content: str, language: str = "javascript") -> List[RouteDefinition]:
        if language not in _SUPPORTED:
            return []

        tree = self.parser.parse(content, language)
        if tree is None:
            return []

        source_bytes = content.encode("utf-8")
        routes: List[RouteDefinition] = []

        def walk(node) -> None:
            if node.type == "call_expression":
                route = self._as_route(node, source_bytes)
                if route is not None:
                    routes.append(route)
            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return routes

    def _as_route(self, node, source_bytes: bytes) -> Optional[RouteDefinition]:
        fn = node.child_by_field_name("function")
        if fn is None or fn.type != "member_expression":
            return None

        obj = fn.child_by_field_name("object")
        prop = fn.child_by_field_name("property")
        if obj is None or prop is None:
            return None

        # Only a bare identifier object counts. `swaggerUi.serve` and
        # `helmet.frameguard()` are not route registrations, and neither is
        # `foo.bar.use(...)` on some unrelated object.
        if obj.type != "identifier":
            return None
        if node_text(obj, source_bytes) not in _ROUTER_OBJECTS:
            return None

        method = node_text(prop, source_bytes)
        if method not in _ROUTE_METHODS:
            return None

        args_node = node.child_by_field_name("arguments")
        if args_node is None:
            return None

        args = [c for c in args_node.children if c.is_named]
        if not args:
            return None

        # A leading string literal is the mount path. Without one the
        # registration is global middleware (`app.use(compression())`) - still
        # recorded, with an empty path, because "this runs for everything" is
        # true and occasionally relevant.
        path = ""
        handler_nodes = args
        if _string_literal(args[0]):
            path = _strip_quotes(node_text(args[0], source_bytes))
            handler_nodes = args[1:]
        elif args[0].type == "array":
            # `app.get(['/.well-known/security.txt', '/security.txt'], ...)`
            paths = [
                _strip_quotes(node_text(c, source_bytes))
                for c in args[0].children
                if _string_literal(c)
            ]
            path = ", ".join(paths)
            handler_nodes = args[1:]

        if not handler_nodes:
            return None

        handlers: List[str] = []
        handler_names: List[str] = []
        handler_name_index: List[int] = []
        for i, h in enumerate(handler_nodes):
            raw = node_text(h, source_bytes)
            # Inline arrow/function middleware is real but unnameable; keep it
            # in the chain so positions stay honest, collapsed so it cannot
            # dominate a prompt.
            if h.type in ("arrow_function", "function_expression"):
                raw = "<inline middleware>"
            handlers.append(" ".join(raw.split()))
            names: List[str] = []
            _callable_names(h, source_bytes, names)
            handler_names.extend(names)
            # One handler can contribute several names (a wrapper and what it
            # wraps). Keeping the index lets a matched function find its own
            # position in the chain, and therefore what ran before it.
            handler_name_index.extend([i] * len(names))

        return RouteDefinition(
            method=method.upper(),
            path=path,
            handlers=handlers,
            handler_names=handler_names,
            handler_name_index=handler_name_index,
            source_line=node.start_point[0] + 1,
        )
