from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, List, Optional
from src.models.models import Language


@dataclass
class ImportReference:
    alias: str
    source: str
    imported_name: Optional[str] = None


@dataclass
class RouteDefinition:
    """One `app.get(...)` / `router.use(...)` style registration.

    `handlers` holds the raw source text of each handler argument, in the order
    Express will run them. Order is the whole point: everything registered
    before a function has already run by the time that function sees the
    request, so a guard earlier in the chain has already enforced whatever it
    enforces. Losing the order (or merging the guards into the handler) is what
    left the analyzer unable to see that `security.appendUserId()` overwrites
    `req.body.UserId` before the handler it guards.

    `handler_names` is the flattened list of callable names appearing in those
    arguments, in the same order, so wrapped handlers
    (`utils.asyncHandler(payment.getPaymentMethods())`) can still be matched to
    the function they actually invoke.
    """
    method: str
    path: str
    handlers: List[str]
    handler_names: List[str] = field(default_factory=list)
    # Parallel to handler_names: the index into `handlers` each name came from,
    # so a matched function can locate its own position in the chain.
    handler_name_index: List[int] = field(default_factory=list)
    source_file: str = ""
    source_line: Optional[int] = None

    def position_of(self, name: str) -> Optional[int]:
        """Index into `handlers` of the first handler contributing `name`."""
        for candidate, idx in zip(self.handler_names, self.handler_name_index):
            if candidate == name:
                return idx
        return None

    def guards_before(self, name: str) -> List[str]:
        """Handlers that Express runs before `name` in this registration.

        These have already executed by the time `name` sees the request, so a
        check performed by one of them is a check the target does not have to
        repeat.
        """
        pos = self.position_of(name)
        if pos is None:
            return []
        return list(self.handlers[:pos])

    @property
    def is_prefix_guard(self) -> bool:
        """A path-mounted `use(...)` registration: every handler in it runs for
        any route beneath that path, rather than for one endpoint."""
        return self.method == "USE" and bool(self.path)

    @property
    def middleware(self) -> List[str]:
        """Every handler but the last. For a `use(...)` mount there is no
        terminal handler, so all of them are middleware."""
        if self.method == "USE":
            return list(self.handlers)
        return list(self.handlers[:-1])


@dataclass
class CodeSample:
    function_name: str
    file_path: str
    code: str                            # was "content" in the old flat models.py
    language: Language
    start_line: int
    end_line: int
    imports: List[ImportReference] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    routes: List[RouteDefinition] = field(default_factory=list)
    class_name: Optional[str] = None
    is_async: bool = False
    ast_node: Optional[Any] = None       # populated by TreeSitterParser
    raw_content: Optional[str] = None    # full file text, needed for call graph
    # Set when this sample is a slice of a function too long to analyse whole.
    # A chunk is a prompt unit, not a semantic function: it gets no call-graph
    # node, because asserting that `configureApp#2` calls everything it registers
    # would be an edge the source does not have.
    chunk_of: Optional[str] = None
    chunk_index: int = 0
    chunk_total: int = 0

    @property
    def is_chunk(self) -> bool:
        return self.chunk_of is not None