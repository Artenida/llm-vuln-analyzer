"""
LLM-based call graph edge resolver.

Wraps OpenAIResolver with a persistent cache so each unique
(caller, raw_call, candidates) combination is only sent to the
LLM once across runs.

Cache is stored under experiments/results/context/edge_cache.json
(not in the project root).
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

from src.context.edge_cache import EdgeCache
from src.llm.cost_ledger import CostLedger
from src.llm.openai_client import OpenAIResolver
from src.llm.pricing import TokenUsage, estimate_cost

logger = logging.getLogger(__name__)

# Put cache inside experiments folder, not project root
_DEFAULT_CACHE_PATH = os.path.join(
    Path(__file__).parent.parent.parent,
    "experiments", "results", "context", "edge_cache.json",
)


def _is_usable_cache_entry(entry: dict) -> bool:
    """Whether a cache hit can be served instead of paying for a fresh call.

    Anything with a real verdict qualifies, including target=None ("this call
    resolves to nothing internal") — that is an answer, not a gap.

    Failures do not qualify. Current failures are tagged `error`; entries
    written before that tag existed are recognised by the "error: ..." string
    the old code put in `reasoning`. Both are re-queried rather than believed.
    """
    if entry.get("error"):
        return False
    reasoning = entry.get("reasoning")
    if isinstance(reasoning, str) and reasoning.startswith("error:"):
        return False
    return True


class LLMEdgeResolver:

    def __init__(
        self,
        api_key: str,
        model: str = "o4-mini",
        cache_path: str = None,
        api_key_alias: str = "default",
        cost_ledger: Optional[CostLedger] = None,
        run_id: Optional[str] = None,
        dataset: Optional[str] = None,
        offline: bool = False,
        budget_usd: Optional[float] = None,
    ):
        self.client = OpenAIResolver(
            api_key, model=model, api_key_alias=api_key_alias,
            cost_ledger=cost_ledger, run_id=run_id, dataset=dataset,
        )
        self.model = model
        self.cache = EdgeCache(
            cache_path or _DEFAULT_CACHE_PATH
        )
        # Spending ceiling for the whole run, enforced here as well as in the
        # analysis loop. Edge resolution runs *before* that loop, so a ceiling
        # checked only between functions does not bound it at all: on a large
        # codebase this phase can be the entire cost of a run and never reach
        # the code that would stop it. A Juice Shop run billed $31 against a $5
        # ceiling exactly this way — it was still resolving edges four days in.
        self.budget_usd = budget_usd
        self._budget_exhausted = False
        self._budget_enforceable = True
        self._budget_skipped = 0
        # Offline: serve from cache, never call the API. Used by `analyze
        # --dry-run`, which is documented as making no LLM calls — building the
        # graph through the normal path would bill edge resolution before the
        # dry-run check was ever reached. Cache hits stay available because
        # they are free; a miss resolves to "unknown" instead of to a purchase.
        self.offline = offline
        # Edges left unresolved purely because we were offline. Reported so a
        # dry-run graph is never mistaken for a complete one.
        self._offline_misses = 0
        # Cached "resolves to nothing" answers served without an API call.
        # Reported so the saving is visible rather than assumed.
        self._negative_cache_hits = 0

    @property
    def negative_cache_hits(self) -> int:
        """Cached negative verdicts served instead of re-bought."""
        return self._negative_cache_hits

    @property
    def offline_misses(self) -> int:
        """Edges an offline run declined to resolve. Zero on a normal run."""
        return self._offline_misses

    @property
    def budget_exhausted(self) -> bool:
        """Whether the ceiling stopped edge resolution before it finished."""
        return self._budget_exhausted

    @property
    def budget_skipped(self) -> int:
        """Edges left unresolved because the ceiling had been reached."""
        return self._budget_skipped

    @property
    def budget_enforceable(self) -> bool:
        """False once a ceiling was asked for but the model has no pricing."""
        return self._budget_enforceable

    def spend_usd(self) -> Optional[float]:
        """What edge resolution has cost so far, or None if the model is not
        priced. Only real calls count — cache hits never reach the client."""
        return estimate_cost(self.model, self.client.get_usage())

    def _over_budget(self) -> bool:
        """Whether the ceiling has been reached. Checked before *every* paid call.

        Per-call rather than per-function: this phase has no functions to sit
        between, and one unbounded phase is all it takes to blow a ceiling by 6x.
        """
        if self.budget_usd is None or self._budget_exhausted:
            return self._budget_exhausted

        spent = self.spend_usd()
        if spent is None:
            # Unknown pricing. Enforcing nothing is bad; treating unknown cost as
            # $0 would be worse, because it silently uncaps the run while looking
            # capped. Report it once and continue — the same trade the analysis
            # loop makes with the same problem.
            if self._budget_enforceable:
                self._budget_enforceable = False
                logger.warning(
                    "--budget-usd cannot be enforced during edge resolution: %s is not "
                    "in the pricing table, so spend is unknown.", self.model,
                )
            return False

        if spent >= self.budget_usd:
            self._budget_exhausted = True
            logger.warning(
                "Budget ceiling reached during edge resolution: $%.4f of $%.4f.",
                spent, self.budget_usd,
            )
            return True
        return False

    def get_usage(self) -> TokenUsage:
        """Cumulative token usage from real LLM calls only — cache hits in
        resolve() return before ever reaching OpenAIResolver, so they never
        count here."""
        return self.client.get_usage()

    def resolve(
        self,
        caller: str,
        raw_call: str,
        caller_code: str,
        candidates: list,
    ) -> dict:
        """
        Resolves a call graph edge using the LLM.

        Returns a dict with keys:
            target       - function name from candidates, or None
            confidence   - float 0.0–1.0
            resolved_by  - "cache" | "llm" | "static"
            reasoning    - short explanation string
        """
        # ── fast path: single candidate, no LLM needed ────────────────────────
        if len(candidates) == 1:
            return {
                "target": candidates[0],
                "confidence": 1.0,
                "resolved_by": "static",
                "reasoning": "Only one candidate.",
            }

        # ── filter candidates: skip obviously external calls ──────────────────
        # Member expressions like res.json, jwt.sign are external — don't waste
        # tokens asking the LLM about them.
        simple = raw_call.split(".")[-1] if "." in raw_call else raw_call
        obj = raw_call.split(".")[0] if "." in raw_call else ""

        _EXTERNAL_OBJECTS = {
            "res", "req", "console", "fs", "jwt", "bcrypt",
            "process", "Math", "JSON", "Date", "Object", "Array",
        }
        if obj in _EXTERNAL_OBJECTS:
            return {
                "target": None,
                "confidence": 1.0,
                "resolved_by": "static",
                "reasoning": f"{obj} is an external/runtime object.",
            }

        # ── cache lookup ──────────────────────────────────────────────────────
        # Sort candidates so key is stable regardless of insertion order
        cache_key = json.dumps(
            {
                "caller": caller,
                "raw_call": raw_call,
                "candidates": sorted(candidates),
            },
            sort_keys=True,
        )

        cached = self.cache.get(cache_key)
        if cached:
            # Normalise old cache entries that used different key names
            cached = self._normalise(cached, candidates)
            if _is_usable_cache_entry(cached):
                # A cached "resolves to nothing" is a real answer and is served
                # like any other. This used to fall through to a fresh LLM call:
                # the write path cached negatives ("to avoid re-querying the
                # same dead ends") but the read path ignored them, so on a repo
                # where most calls are to built-ins — 1077 of 1176 cached
                # entries on Juice Shop — nearly the whole graph was re-bought
                # on every single run.
                cached["resolved_by"] = "cache"
                self._negative_cache_hits += 0 if cached.get("target") else 1
                return cached

        # ── offline: a cache miss is as far as we go ──────────────────────────
        if self.offline:
            self._offline_misses += 1
            return {"target": None, "confidence": 0.0, "resolved_by": "offline_skip"}

        # ── budget ceiling ────────────────────────────────────────────────────
        # Degrades exactly like offline mode rather than raising: the edges
        # resolved so far are real and the graph they form is worth keeping.
        if self._over_budget():
            self._budget_skipped += 1
            return {"target": None, "confidence": 0.0, "resolved_by": "budget_skip"}

        # ── LLM call ──────────────────────────────────────────────────────────
        payload = {
            "caller": caller,
            "raw_call": raw_call,
            "caller_code": caller_code,
            "candidates": candidates,
        }

        result = self.client.resolve_edge(payload)
        result["resolved_by"] = "llm"

        if result.get("error"):
            # Never cache a failure. It would be indistinguishable from a real
            # "no match" on the next run and would suppress the edge forever.
            logger.debug("Not caching failed edge resolution for %r: %s",
                         raw_call, result.get("error"))
            return result

        if result.get("target"):
            logger.debug(
                "LLM resolved %r -> %r (conf %.2f) for caller %s",
                raw_call,
                result["target"],
                result.get("confidence", 0.0),
                caller,
            )

        # cache even None results to avoid re-querying the same dead ends
        self.cache.set(cache_key, result)

        return result

    # ── helpers ───────────────────────────────────────────────────────────────

    def _normalise(self, entry: dict, candidates: list) -> dict:
        """
        Migrate old cache entries that used inconsistent key names
        (resolved_callee, callee, call, resolved_call, etc.) to the
        canonical "target" key.
        """
        if "target" in entry:
            return entry

        for alt in (
            "resolved_callee", "callee", "resolved_call",
            "resolved_to", "call",
        ):
            val = entry.get(alt)
            if isinstance(val, str) and val in candidates:
                entry["target"] = val
                return entry

        # check nested structures like {"resolved_edges": [{"callee": ...}]}
        for nested_key in ("resolved_edges", "edges", "call_edges"):
            nested = entry.get(nested_key)
            if isinstance(nested, list) and nested:
                first = nested[0]
                if isinstance(first, dict):
                    for alt in ("callee", "target", "resolved_callee"):
                        val = first.get(alt)
                        if isinstance(val, str) and val in candidates:
                            entry["target"] = val
                            return entry

        entry["target"] = None
        return entry