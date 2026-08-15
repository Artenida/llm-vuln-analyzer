"""Grouping functions into workflows for the flow-level analysis pass.

Why a second pass exists at all
-------------------------------
All six execution-proven vulnerabilities in the juice-shop ground truth sit in
the NEITHER bucket - missed by the LLM agent and by Semgrep. The shape is
consistent:

    generateCoupon      mints a token with a reversible, unkeyed encoding
    discountFromCoupon  accepts it after a month-format regex and no MAC

The analyzer examined both functions and called both clean, and at function
scope it was right both times. Neither one is wrong on its own; the pair is. No
amount of prompt work on a single-function pass reaches that, because the
evidence is split across two functions that are individually defensible.

So this module builds groups, and the flow pass asks a different question of
each: not "is this function wrong" but "do these functions disagree".

Three strategies, cheapest first
--------------------------------
  producer/consumer  one function mints a value, another validates it. This is
                     the coupon case, and the Hashids continue-code case.
  route cluster      a route's handler plus what it calls, so an ordering or
                     ownership rule spanning handler and helper is visible.
  model writers      a persistence model's setters plus the routes that write
                     through them.

Groups are capped and de-duplicated: this pass costs money per group, and a
group larger than the cap stops being a workflow and becomes a file dump.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

MAX_GROUP_FUNCTIONS = 6
MAX_GROUP_LINES = 800

# A value is *minted* by one of these and *checked* by one of those. Matching is
# on the verb, and the remainder of the name has to agree - `generateCoupon` and
# `discountFromCoupon` pair on "coupon", `generateToken` and `checkPassword` do
# not pair at all.
_PRODUCER_VERBS = ("generate", "create", "make", "mint", "sign", "encode", "issue", "build")
_CONSUMER_VERBS = ("verify", "validate", "check", "decode", "parse", "apply", "redeem", "from")


@dataclass
class FlowGroup:
    """A set of functions to analyse together, with why they were grouped."""
    kind: str                      # "producer_consumer" | "route_cluster" | "model_writers"
    label: str                     # human-readable, e.g. "coupon: generateCoupon -> discountFromCoupon"
    node_ids: List[str] = field(default_factory=list)
    rationale: str = ""

    @property
    def key(self) -> tuple:
        return tuple(sorted(self.node_ids))


def _subject(name: str, verbs: tuple) -> Optional[str]:
    """The noun a producer/consumer verb acts on, lowercased.

    `generateCoupon` -> "coupon", `discountFromCoupon` -> "discountcoupon",
    `verifyImageCaptcha` -> "imagecaptcha". Returns None when no verb appears.

    Every matching verb is stripped, not just the first. The subjects two names
    reduce to are then compared by containment rather than equality — see
    `_subjects_match`. `generateCoupon` and `discountFromCoupon` are the pair
    this whole strategy exists to catch, and they reduce to "coupon" and
    "discountcoupon": equality would miss them.
    """
    lowered = name.lower()
    if not any(verb in lowered for verb in verbs):
        return None
    remainder = lowered
    for verb in verbs:
        remainder = re.sub(verb, "", remainder)
    remainder = remainder.strip("_-")
    return remainder if len(remainder) >= 3 else None


# Containment is looser than equality, so require a real noun before allowing it.
# Below this, "id" or "key" fragments would pair unrelated functions.
_MIN_CONTAINMENT_LEN = 5


def _subjects_match(a: str, b: str) -> bool:
    if a == b:
        return True
    shorter, longer = (a, b) if len(a) <= len(b) else (b, a)
    return len(shorter) >= _MIN_CONTAINMENT_LEN and shorter in longer


def _lines(sample) -> int:
    return max(0, (sample.end_line or 0) - (sample.start_line or 0) + 1)


def _within_budget(samples: List) -> bool:
    return (
        len(samples) <= MAX_GROUP_FUNCTIONS
        and sum(_lines(s) for s in samples) <= MAX_GROUP_LINES
    )


def _node_id(sample) -> str:
    return f"{sample.file_path}::{sample.function_name}"


def build_producer_consumer_groups(samples: List) -> List[FlowGroup]:
    """Pair a function that mints a value with one that accepts it.

    This is the strategy that reaches the coupon forgery: `generateCoupon`
    z85-encodes a discount and `discountFromCoupon` accepts it on a regex, and
    each is individually defensible.
    """
    producers: Dict[str, List] = {}
    consumers: Dict[str, List] = {}

    for s in samples:
        if getattr(s, "chunk_of", None):
            continue
        subject = _subject(s.function_name, _PRODUCER_VERBS)
        if subject:
            producers.setdefault(subject, []).append(s)
        subject = _subject(s.function_name, _CONSUMER_VERBS)
        if subject:
            consumers.setdefault(subject, []).append(s)

    groups: List[FlowGroup] = []
    for subject, produced in producers.items():
        # Every consumer whose own subject overlaps this one, so a producer is
        # grouped with all the ways its value is later accepted rather than only
        # the one that happens to be named identically.
        consumed = [
            s
            for other, members in consumers.items()
            if _subjects_match(subject, other)
            for s in members
        ]
        if not consumed:
            continue
        members = list({_node_id(s): s for s in produced + consumed}.values())
        if len(members) < 2 or not _within_budget(members):
            continue
        groups.append(FlowGroup(
            kind="producer_consumer",
            label=f"{subject}: " + " + ".join(sorted(s.function_name for s in members)),
            node_ids=[_node_id(s) for s in members],
            rationale=(
                f"One of these produces a '{subject}' value and another consumes it. "
                "Check whether what is produced can be forged or replayed by anyone "
                "who can read this code, and whether the consumer would notice."
            ),
        ))
    return groups


def build_route_cluster_groups(samples: List, graph: Dict) -> List[FlowGroup]:
    """A route handler plus the internal functions it calls, depth <= 2.

    Needs the route registrations Stage 1 attaches, so a cluster is anchored on
    something actually reachable over HTTP rather than on any function that
    happens to have callees.
    """
    by_id = {_node_id(s): s for s in samples if not getattr(s, "chunk_of", None)}
    groups: List[FlowGroup] = []

    for node_id, node in graph.items():
        regs = _attr(node, "route_registrations") or []
        if not regs:
            continue
        if node_id not in by_id:
            continue

        members = [node_id]
        frontier = [node_id]
        for _ in range(2):
            nxt = []
            for current in frontier:
                for callee in _attr(graph.get(current), "callees") or []:
                    if callee.startswith("external::") or callee in members:
                        continue
                    if callee not in by_id:
                        continue
                    members.append(callee)
                    nxt.append(callee)
            frontier = nxt

        member_samples = [by_id[m] for m in members if m in by_id]
        if len(member_samples) < 2 or not _within_budget(member_samples):
            continue

        reg = regs[0]
        groups.append(FlowGroup(
            kind="route_cluster",
            label=f"{reg.get('method', '?')} {reg.get('path', '?')}",
            node_ids=[_node_id(s) for s in member_samples],
            rationale=(
                "These run to serve one HTTP request. Check for a rule that spans "
                "them — an ownership or ordering requirement that each function "
                "leaves to the other, so neither enforces it."
            ),
        ))
    return groups


def build_model_writer_groups(samples: List, graph: Dict) -> List[FlowGroup]:
    """A persistence model's setters plus their callers.

    Two of the baseline's attribution disputes live here: the defect is in a
    setter, the ground truth labels the caller, or the reverse.
    """
    by_id = {_node_id(s): s for s in samples if not getattr(s, "chunk_of", None)}
    by_file: Dict[str, List] = {}
    for s in by_id.values():
        if "/models/" in (s.file_path or "").replace("\\", "/").lower():
            by_file.setdefault(s.file_path, []).append(s)

    groups: List[FlowGroup] = []
    for file_path, setters in by_file.items():
        members = {_node_id(s): s for s in setters}
        for s in setters:
            for caller in _attr(graph.get(_node_id(s)), "callers") or []:
                if caller in by_id:
                    members[caller] = by_id[caller]
        member_samples = list(members.values())
        if len(member_samples) < 2 or not _within_budget(member_samples):
            continue
        short = file_path.replace("\\", "/").split("/")[-1]
        groups.append(FlowGroup(
            kind="model_writers",
            label=f"{short} and its writers",
            node_ids=[_node_id(s) for s in member_samples],
            rationale=(
                "A stored model and the code that writes through it. Check whether "
                "validation or sanitisation is assumed by one side and performed by "
                "neither."
            ),
        ))
    return groups


def _attr(node, name: str):
    if node is None:
        return None
    if hasattr(node, name):
        return getattr(node, name)
    if isinstance(node, dict):
        return node.get(name)
    return None


def build_flow_groups(
    samples: List,
    graph: Dict,
    max_groups: Optional[int] = None,
) -> List[FlowGroup]:
    """Every group worth a flow-pass call, de-duplicated and capped.

    A group that is a subset of another is dropped: analysing both pays twice for
    the same question. Producer/consumer pairs are kept first because they are
    the smallest and the only strategy with a demonstrated miss behind it.
    """
    groups = (
        build_producer_consumer_groups(samples)
        + build_route_cluster_groups(samples, graph)
        + build_model_writer_groups(samples, graph)
    )

    kept: List[FlowGroup] = []
    seen: set = set()
    for group in groups:
        key = group.key
        if key in seen:
            continue
        member_set = set(key)
        if any(member_set <= set(k.key) for k in kept):
            continue
        kept = [k for k in kept if not set(k.key) < member_set]
        seen.add(key)
        kept.append(group)

    if max_groups is not None and len(kept) > max_groups:
        logger.info(
            "Flow pass: %d groups built, analysing the first %d", len(kept), max_groups
        )
        kept = kept[:max_groups]
    return kept
