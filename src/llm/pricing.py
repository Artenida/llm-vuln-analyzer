"""
Token usage tracking + static per-model pricing for cost estimation.

Owns the two pieces needed to turn an OpenAI response's `usage` field into a
dollar figure: an accumulator type (`TokenUsage`) and a pricing table
(`estimate_cost`). A model missing from PRICING means "cost unknown" —
`estimate_cost` returns None rather than guessing.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

# $ per 1,000,000 tokens, as (input_rate, output_rate).
# Only models this project actually runs against. Add a row before running
# a new model if you want its cost tracked — an unlisted model degrades to
# "unknown" rather than silently reporting $0 or a wrong number.
PRICING: dict[str, tuple[float, float]] = {
    "o4-mini": (1.10, 4.40),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
}


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
        )


def extract_usage(response) -> TokenUsage:
    """Pulls prompt/completion/total tokens off an OpenAI chat completion
    response. Returns a zeroed TokenUsage if `usage` is absent (e.g. a mocked
    response in tests) rather than raising."""
    usage = getattr(response, "usage", None)
    if usage is None:
        return TokenUsage()
    return TokenUsage(
        prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
        completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
        total_tokens=getattr(usage, "total_tokens", 0) or 0,
    )


def estimate_cost(model: str, usage: TokenUsage) -> Optional[float]:
    """Returns the $ cost of `usage` under `model`'s pricing, or None if the
    model isn't in PRICING — never fabricates a number for an unknown model."""
    rates = PRICING.get(model)
    if rates is None:
        return None
    input_rate, output_rate = rates
    return (
        usage.prompt_tokens * input_rate + usage.completion_tokens * output_rate
    ) / 1_000_000
