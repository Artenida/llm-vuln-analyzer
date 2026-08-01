"""
Web UI backend.

A thin read-only adapter over the artifacts the CLI already writes to
`experiments/`. It deliberately re-implements none of the analysis: metrics come
from `src.evaluation.evaluator`, cost from `src.llm.cost_ledger`. See
`docs/frontend-plan.md`.
"""
