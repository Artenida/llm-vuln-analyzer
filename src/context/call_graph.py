import difflib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from src.models import CodeSample
from src.context.symbol_resolver import SymbolResolver
from src.context.llm_edge_resolver import LLMEdgeResolver
from src.ingestion.parser import TreeSitterParser
from src.llm.cost_ledger import CostLedger
from src.llm.pricing import TokenUsage

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# NODE
# ─────────────────────────────────────────────


@dataclass
class CallGraphNode:
    id: str
    function_name: str
    file_path: str

    callers: Set[str] = field(default_factory=set)
    callees: Set[str] = field(default_factory=set)

    is_entry_point: bool = False
    is_infrastructure: bool = False
    is_external: bool = False
    is_taint_source: bool = False   # receives untrusted user input (e.g. HTTP handlers)
    is_taint_sink: bool = False     # passes data to dangerous operations

    # HTTP registrations that reach this function, each with the guard chain
    # that runs before it. Without this, a handler whose only caller is an
    # oversized (and therefore skipped) route-wiring function looks like an
    # unreachable, unguarded orphan — which is how ten protected juice-shop
    # handlers were reported as IDOR.
    route_registrations: List[dict] = field(default_factory=list)


ENTRY_POINT_PATTERNS = ["handler", "route", "endpoint", "controller", "main"]

INFRASTRUCTURE_PATTERNS = ["execute", "query", "connect", "disconnect"]

# External calls that mark a node as a taint sink
_SINK_EXTERNAL_PATTERNS = [
    "execute", "query", "eval", "exec", "system", "popen",
    "spawn", "shell", "run_command", "subprocess",
    "write_file", "write", "send_response",
]

# Function-name patterns that are always sinks regardless of callees
_SINK_NAME_PATTERNS = [
    "execute", "exec_query", "run_query", "run_command",
    "eval", "shell_exec",
]


class CallGraphBuilder:

    def __init__(
        self,
        api_key: str = None,
        model: str = "o4-mini",
        api_key_alias: str = "default",
        cost_ledger: Optional[CostLedger] = None,
        run_id: Optional[str] = None,
        dataset: Optional[str] = None,
        offline_edges: bool = False,
        budget_usd: Optional[float] = None,
    ):
        self.parser = TreeSitterParser()
        self.symbol_resolver = SymbolResolver()
        self.llm_resolver = LLMEdgeResolver(
            api_key, model=model, api_key_alias=api_key_alias,
            cost_ledger=cost_ledger, run_id=run_id, dataset=dataset,
            offline=offline_edges, budget_usd=budget_usd,
        ) if api_key else None

    # How many names one unresolved call may be asked about. A list this long
    # is already generous: the answer is either a near-miss of the called name
    # or something the caller imported, and neither produces twenty options.
    MAX_LLM_CANDIDATES = 20

    def _llm_candidates(
        self,
        sample: CodeSample,
        raw_call: str,
        known: Set[str],
        names_by_file: Dict[str, Set[str]],
    ) -> List[str]:
        """The names worth paying to choose between, for one unresolved call.

        Every call used to be sent `list(known)` — the whole project's function
        names. On Juice Shop that is 1728 names, ~10k tokens, 88% of the prompt,
        repeated on every call, while the caller's own code was capped at 1500
        characters. It was also mostly pointless: this path is only reached once
        static resolution has established that no name matches the call, so the
        honest answer was usually "external", and 4096 of 4513 cached verdicts
        were exactly that.

        An empty result means "nothing here could plausibly be the target" —
        the caller should record an external node rather than buy that answer.
        """
        simple = raw_call.split(".")[-1] if "." in raw_call else raw_call
        obj = raw_call.split(".")[0] if "." in raw_call else ""

        candidates: Set[str] = set()

        # What the alias actually refers to. SymbolResolver has already tried
        # the exact `alias.method` match; this is the wider net for the case it
        # misses — a re-exported or renamed function in the imported module.
        if obj:
            for imp in sample.imports or []:
                if imp.alias != obj:
                    continue
                stem = Path(imp.source).stem
                if not stem:
                    continue
                for file_path, names in names_by_file.items():
                    if stem in file_path:
                        candidates |= names

        # `this.helper()` / `self.helper()`: the target is a sibling in the same
        # file. Restricted to those receivers — pulling in every same-file name
        # for an arbitrary `foo.bar()` would just re-inflate the prompt.
        if obj in ("this", "self"):
            candidates |= names_by_file.get(sample.file_path or "", set())

        # Near-misses. A renamed import or a one-character difference is the
        # case static matching cannot settle and a model genuinely can.
        candidates |= set(difflib.get_close_matches(simple, known, n=5, cutoff=0.8))

        # A function is not its own callee via an alias.
        candidates.discard(sample.function_name)

        return sorted(candidates)[: self.MAX_LLM_CANDIDATES]

    def get_offline_misses(self) -> int:
        """Edges left unresolved because edge resolution was offline (dry run).
        Always 0 on a normal run."""
        return self.llm_resolver.offline_misses if self.llm_resolver else 0

    @property
    def budget_exhausted(self) -> bool:
        """Whether the run's ceiling was reached while resolving edges.

        This phase precedes the analysis loop, so hitting the ceiling here means
        there is nothing left to analyse with — the caller has to say so rather
        than proceed as though the graph were complete.
        """
        return self.llm_resolver.budget_exhausted if self.llm_resolver else False

    @property
    def budget_skipped(self) -> int:
        """Edges left unresolved because the ceiling had been reached."""
        return self.llm_resolver.budget_skipped if self.llm_resolver else 0

    @property
    def budget_enforceable(self) -> bool:
        return self.llm_resolver.budget_enforceable if self.llm_resolver else True

    def get_edge_resolution_usage(self) -> Optional[TokenUsage]:
        """Cumulative token usage spent resolving call graph edges via the LLM
        fallback, or None if no LLM resolver was configured (no api_key)."""
        return self.llm_resolver.get_usage() if self.llm_resolver else None

    def _make_id(self, file_path: str, function_name: str) -> str:
        return f"{file_path}::{function_name}"

    def _is_entry_point(
        self,
        function_name: str,
        file_path: str,
    ) -> bool:

        path = file_path.lower()

        if any(
            x in path
            for x in [
                "controller",
                "route",
                "middleware",
                "api",
            ]
        ):
            return True

        return any(p in function_name.lower() for p in ENTRY_POINT_PATTERNS)

    @staticmethod
    def _path_covers(guard_path: str, route_path: str) -> bool:
        """Whether a `use(<guard_path>, ...)` mount runs for `route_path`.

        Express mounts on a path prefix, so `/rest/basket` guards
        `/rest/basket/:id/order`. The match is made at a segment boundary —
        `/api/Card` must not be treated as guarding `/api/Cards`.
        """
        if not guard_path or not route_path:
            return False
        g = guard_path.rstrip("/")
        r = route_path.rstrip("/")
        return r == g or r.startswith(g + "/")

    def _prefix_guards_for(self, route, prefix_guards: List) -> List[dict]:
        """Path-mounted middleware that runs before `route`.

        Only guards registered *earlier in the same file* count: Express applies
        middleware in registration order, so a `use(...)` declared after a route
        does not protect it. Getting this backwards would invent authorization
        that does not exist, which is a worse failure than missing it.
        """
        out = []
        for g in prefix_guards:
            if g is route or not self._path_covers(g.path, route.path):
                continue
            if g.source_file and route.source_file and g.source_file != route.source_file:
                continue
            if (
                g.source_line is not None
                and route.source_line is not None
                and g.source_line >= route.source_line
            ):
                continue
            out.append({
                "path": g.path,
                "handlers": list(g.handlers),
                "source_file": g.source_file,
                "source_line": g.source_line,
            })
        return out

    def _apply_route_entry_points(
        self,
        graph: Dict[str, "CallGraphNode"],
        route_defs: List,
    ) -> None:
        name_to_nodes: Dict[str, List[str]] = {}
        for node_id, node in graph.items():
            if node.is_external:
                continue
            name_to_nodes.setdefault(node.function_name, []).append(node_id)

        prefix_guards = [r for r in route_defs if getattr(r, "is_prefix_guard", False)]

        for route in route_defs:
            # `handler_names` resolves wrapped handlers — the function actually
            # invoked by `utils.asyncHandler(payment.getPaymentMethods())` is
            # getPaymentMethods, which the raw handler text does not yield.
            # Older RouteDefinitions carry only `handlers`, so fall back to it.
            lookup_names = list(getattr(route, "handler_names", None) or route.handlers)
            covering = self._prefix_guards_for(route, prefix_guards)

            for raw_name in lookup_names:
                name = raw_name.strip()
                if not name:
                    continue
                # handlers referenced as `object.method` (e.g. billingController.payInvoice)
                # never carry the object prefix on the extracted function itself
                lookup_name = name.split(".")[-1] if "." in name else name
                candidates = name_to_nodes.get(lookup_name, [])

                target: Optional[str] = None
                if len(candidates) == 1:
                    target = candidates[0]
                elif len(candidates) > 1:
                    preferred = [
                        nid for nid in candidates
                        if any(
                            x in graph[nid].file_path.lower()
                            for x in ("controller", "route", "middleware", "api")
                        )
                    ]
                    if len(preferred) == 1:
                        target = preferred[0]
                    # else: ambiguous with no clear winner — leave as-is rather
                    # than risk flagging the wrong (e.g. service-layer) function

                if target is None:
                    continue

                graph[target].is_entry_point = True
                self._attach_registration(graph[target], route, lookup_name, covering)

    @staticmethod
    def _attach_registration(node, route, name: str, covering: List[dict]) -> None:
        entry = {
            "method": route.method,
            "path": route.path,
            "source_file": getattr(route, "source_file", ""),
            "source_line": getattr(route, "source_line", None),
            "handlers": list(route.handlers),
            # What Express ran before this function on this route. This is the
            # field the analyzer needs: a check performed here has already
            # happened by the time the target sees the request.
            "guards_before": (
                route.guards_before(name)
                if hasattr(route, "guards_before")
                else list(route.handlers[:-1])
            ),
            "prefix_guards": covering,
        }
        if entry not in node.route_registrations:
            node.route_registrations.append(entry)

    def build(
        self,
        samples: List[CodeSample],
        routes: Optional[List] = None,
    ) -> Tuple[Dict[str, "CallGraphNode"], Dict[str, Set[str]]]:
        """
        routes: project-wide RouteDefinition list (e.g. CodeExtractor.all_routes).
        Route files (Express `router.get(...)` wiring) typically have no function
        bodies of their own, so this can't be recovered from `sample.routes` alone
        — falls back to scanning samples for callers that don't pass it explicitly.
        """

        graph: Dict[str, CallGraphNode] = {}
        name_index: Dict[str, Set[str]] = {}

        known: Set[str] = set()
        # file_path -> names defined in it, for narrowing LLM candidates to the
        # module an alias actually points at.
        names_by_file: Dict[str, Set[str]] = {}

        # ─────────────────────────────────────────────
        # 1. NODE CREATION
        # ─────────────────────────────────────────────
        for s in samples:

            if not s.function_name:
                continue

            # A chunk of an oversized function is a prompt unit, not a semantic
            # function. Giving it a node would assert that `configureApp#2`
            # calls every handler it registers — an edge the source does not
            # have, and one that would silently change the caller counts of
            # every handler in the graph.
            if getattr(s, "chunk_of", None):
                continue

            node_id = self._make_id(s.file_path or "", s.function_name)

            known.add(s.function_name)
            names_by_file.setdefault(s.file_path or "", set()).add(s.function_name)

            graph[node_id] = CallGraphNode(
                id=node_id,
                function_name=s.function_name,
                file_path=s.file_path or "",
                is_entry_point=self._is_entry_point(
                    s.function_name,
                    s.file_path or "",
                ),
                is_infrastructure=any(
                    p in s.function_name.lower() for p in INFRASTRUCTURE_PATTERNS
                ),
                is_external=False,
            )

            name_index.setdefault(s.function_name, set()).add(node_id)

        # Function names directly registered as Express route handlers — a more
        # precise entry-point signal than name/path guessing, applied once nodes
        # (and therefore name collisions across files) are known. A route name
        # that matches more than one function (e.g. a controller and the service
        # it delegates to sharing a name) is only resolved if exactly one
        # candidate also matches the existing path heuristic — otherwise it's
        # left alone rather than risk marking the wrong one.
        route_defs = routes if routes is not None else [
            r for s in samples for r in s.routes
        ]
        self._apply_route_entry_points(graph, route_defs)

        # ─────────────────────────────────────────────
        # 2. EDGE CREATION
        # ─────────────────────────────────────────────
        for s in samples:

            if not s.function_name or not s.ast_node:
                if s.function_name:
                    logger.debug(
                        "Skipping edge extraction for %s — no AST node",
                        s.function_name,
                    )
                continue

            src_id = self._make_id(s.file_path or "", s.function_name)

            src_node = graph.get(src_id)

            if not src_node:
                continue

            src_bytes = (s.raw_content or s.code).encode("utf-8")

            calls = self.parser.extract_call_names(
                s.ast_node,
                s.language.value,
                src_bytes,
            )

            for c in calls:

                # ─────────────────────────────────────
                # Static resolution
                # authService.registerUser -> registerUser
                # fakeDb.execute -> execute
                # ─────────────────────────────────────
                simple_target = c.split(".")[-1] if "." in c else c
                target = c

                resolved_name = None

                if target in known:
                    resolved_name = target

                elif simple_target in known:
                    resolved_name = simple_target

                # ─────────────────────────────────────
                # Import-aware resolution via SymbolResolver
                # Handles: authService.registerUser when imports exist
                # ─────────────────────────────────────
                if resolved_name is None and "." in c and s.imports:
                    sr_candidates = self.symbol_resolver.resolve_candidates(
                        s, c, samples
                    )
                    for tgt_id in sr_candidates:
                        if tgt_id in graph:
                            src_node.callees.add(tgt_id)
                            graph[tgt_id].callers.add(src_id)
                    if sr_candidates:
                        continue  # wired directly; skip LLM fallback

                # ─────────────────────────────────────
                # HYBRID: AI fallback when static fails
                # ─────────────────────────────────────
                if resolved_name is None and self.llm_resolver and known:
                    # Narrowed to what could actually be the target. No
                    # plausible candidate means the call leaves the codebase —
                    # recorded as external without paying to be told so.
                    llm_candidates = self._llm_candidates(
                        s, c, known, names_by_file
                    )
                    try:
                        result = (
                            self.llm_resolver.resolve(
                                caller=src_id,
                                raw_call=c,
                                caller_code=s.code,
                                candidates=llm_candidates,
                            )
                            if llm_candidates
                            else {"target": None}
                        )
                        ai_target = result.get("target")
                        if ai_target and ai_target in known:
                            resolved_name = ai_target
                            logger.debug(
                                "AI resolved %r -> %r (caller: %s)",
                                c,
                                ai_target,
                                src_id,
                            )
                    except Exception as e:
                        logger.debug("AI edge resolution failed for %r: %s", c, e)

                # ─────────────────────────────────────
                # External node — truly unresolved
                # ─────────────────────────────────────
                if resolved_name is None:

                    ext_id = f"external::{target}"

                    if ext_id not in graph:

                        graph[ext_id] = CallGraphNode(
                            id=ext_id,
                            function_name=target,
                            file_path="external",
                            is_external=True,
                        )

                    src_node.callees.add(ext_id)
                    graph[ext_id].callers.add(src_id)
                    continue

                # ─────────────────────────────────────
                # Internal function — wire the edge
                # ─────────────────────────────────────
                targets = name_index.get(resolved_name, set())

                for tgt_id in targets:

                    if tgt_id == src_id:
                        continue

                    src_node.callees.add(tgt_id)
                    graph[tgt_id].callers.add(src_id)

        # ─────────────────────────────────────────────
        # 3. TAINT PROPAGATION
        # ─────────────────────────────────────────────
        for node_id, node in graph.items():
            if node.is_external:
                continue

            # entry points receive user-controlled data → taint sources
            if node.is_entry_point:
                node.is_taint_source = True

            # function-name based sink detection
            if any(p in node.function_name.lower() for p in _SINK_NAME_PATTERNS):
                node.is_taint_sink = True

            # sink detection via external callees: e.g. fakeDb.execute(...)
            for callee_id in node.callees:
                if callee_id.startswith("external::"):
                    raw_name = callee_id.replace("external::", "")
                    leaf = raw_name.split(".")[-1].lower()
                    if any(p in leaf for p in _SINK_EXTERNAL_PATTERNS):
                        node.is_taint_sink = True
                        break

        # ─────────────────────────────────────────────
        # 4. JSON SERIALIZATION FIX
        # ─────────────────────────────────────────────
        for node in graph.values():

            node.callers = sorted(list(node.callers))
            node.callees = sorted(list(node.callees))

        name_index_final = {k: sorted(list(v)) for k, v in name_index.items()}

        return graph, name_index_final


def nodes_to_dict(graph: Dict[str, "CallGraphNode"]) -> Dict[str, dict]:
    """
    Converts the Dict[str, CallGraphNode] returned by CallGraphBuilder.build()
    into the plain Dict[str, dict] format consumed by export_dot / export_html.
    """
    result = {}
    for node_id, node in graph.items():
        result[node_id] = {
            "function_name":     node.function_name,
            "file_path":         node.file_path,
            "callers":           list(node.callers),
            "callees":           list(node.callees),
            "is_entry_point":    node.is_entry_point,
            "is_infrastructure": node.is_infrastructure,
            "is_external":       node.is_external,
            "is_taint_source":   node.is_taint_source,
            "is_taint_sink":     node.is_taint_sink,
            "route_registrations": list(node.route_registrations),
        }
    return result
