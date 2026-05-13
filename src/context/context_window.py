"""
Phase 2 placeholder.
Will assemble multi-function context windows later.
"""

from dataclasses import dataclass, field

from src.models import CodeSample


@dataclass
class ContextualSample:
    target: CodeSample

    callers: list[CodeSample] = field(default_factory=list)

    callees: list[CodeSample] = field(default_factory=list)

    taint_summary: str = ""

    call_chain_summary: str = ""

    cross_function_flow_detected: bool = False

    total_tokens_estimate: int = 0