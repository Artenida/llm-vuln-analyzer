# Cost & Token Tracking (Sprint 7)

## Why

Sprint 6 names "cost ceilings" as a scaling constraint with no number behind
it, and the thesis needs a real answer to: is the ReAct agent's accuracy gain
worth its extra API cost compared to single-pass or call-graph-context mode?
That question is unanswerable unless token usage and $ cost are measured per
mode, per phase, and accumulated across runs.

Cost is tracked at two levels:

- **Per run** — each run's own `analysis.json`/`patches.json` carries its
  token/cost totals and per-item breakdown. Self-contained and disposable,
  matching how run files have always worked.
- **Across runs** — a local SQLite ledger accumulates one row per real LLM
  call, from every phase and every API key, so spend can be totalled by
  phase, by run, or by key without re-reading every run file.

## Capture (`src/llm/pricing.py`)

- `TokenUsage(prompt_tokens, completion_tokens, total_tokens)` — a small
  accumulator with `__add__` so usage from multiple LLM calls can be summed.
- `extract_usage(response)` — pulls `response.usage` off an OpenAI chat
  completion response; returns a zeroed `TokenUsage` if `usage` is absent
  (e.g. a mocked response in tests) rather than raising.
- `estimate_cost(model, usage)` — converts a `TokenUsage` to a dollar figure
  using a static `PRICING` table (`$/1M` input/output tokens for `o4-mini`,
  `gpt-4o-mini`, `gpt-4o`). **A model missing from the table returns `None`,
  never a guessed number** — this is the one rule every other layer respects:
  `cost_usd`/`total_cost_usd` being `None` always means "unknown," not "$0."

Every phase that calls the LLM goes through this same capture path:
call-graph edge resolution (`OpenAIResolver.resolve_edge`), vulnerability
analysis in any mode (`LLMClient.analyze`/`reason`), and patch generation
(`PatchGenerator.generate`).

## Persistent cross-run ledger (`src/llm/cost_ledger.py`)

**Why a database, and why SQLite:** "total spend this month" or "total spend
on patch generation across every run" is not a question one run file can
answer, and hand-aggregating dozens of JSON files is the same kind of manual
counting Sprint 5 replaced for precision/recall. SQLite beats a second JSON
ledger here because those cross-run aggregates are a `GROUP BY` rather than
custom accumulation code, and this is a local, single-user, file-based
project (same posture as `edge_cache.json`) — no server, no migration
framework, and concurrent-write handling comes free.

- **Location:** `experiments/cost_ledger.db` (gitignored, like the rest of
  `experiments/` — never committed).
- **Schema:** one append-only table, `cost_events`. One row per *real* LLM
  API call — not per finding, not per run — with `timestamp`, `provider`,
  `api_key_alias`, `model`, `phase`, `run_id`, `dataset`, `function_name`,
  `prompt_tokens`, `completion_tokens`, `total_tokens`, `cost_usd`. Rows are
  inserted, never updated or deleted, and a write failure (disk full, locked
  file) is logged and swallowed — **cost tracking must never be the reason
  an analysis run fails.**
- **`phase` values:** `edge_resolution`, `call_graph_context`, `react_loop`,
  `react_loop_fallback`, `patch_generation`. The three analysis phases are
  exactly the `VulnerabilityReport.analysis_mode` values — no separate
  taxonomy.
- **Queries:** `CostLedger.total()`, `.by_phase()`, `.by_api_key()` accept an
  optional `run_id` filter; `.by_run()` lists runs newest-first, ordered by
  each run's latest event timestamp (not by `run_id`, which embeds the model
  name before the timestamp and would therefore group by model, not time).
  All share one rule: if *any* event folded into a group has
  `cost_usd IS NULL` (unpriced model), the whole group's cost is `None`, not
  a partial sum — a partial number would understate spend while looking like
  a real one. A phase that made no API call at all (e.g. a patch skipped
  because its source couldn't be re-extracted) records `$0`, not unknown.

### Multi-API-key attribution

Every constructor that talks to the LLM (`LLMClient`, `OpenAIResolver` via
`LLMEdgeResolver`/`CallGraphBuilder`, `PatchGenerator`) accepts an
`api_key_alias: str = "default"` alongside the actual key value, and stamps
every ledger row it writes with that alias. **The raw key value itself is
never written to the ledger** — only the alias.

Resolving which key to use for a given alias is `AppConfig.resolve_api_key()`
(`src/config.py`): the default key is `OPENAI_API_KEY`; a named key
`"team2"` is read from `OPENAI_API_KEY_TEAM2` (alias uppercased). A missing
aliased env var raises immediately rather than silently falling back to the
default key under a different label. `analyze`, `graph`, and `patch` all
expose `--api-key-alias` on the CLI.

This is attribution, **not** key rotation, round-robin dispatch, or
rate-limit failover — those are request-dispatch concerns (closer to Sprint
6.1's rate-limit/backoff scope), not cost accounting. Run different
invocations under different aliases (one budget per team member, or per
experiment) and the ledger keeps their spend distinguishable instead of
merging it into one undifferentiated total. Rotation/failover would compose
on top without a ledger schema change — an invocation would just pick its
alias per call instead of once at startup.

### CLI

- `analyze` prints the per-run token/cost summary plus a **cost by phase**
  breakdown for that run, queried live from the ledger.
- `patch` prints total patch-generation tokens/cost.
- `cost` command — read-only view over the ledger:
  - `cost` — grand total + breakdown by phase, all-time, across every run.
  - `cost --run-id <id>` — same breakdown scoped to one run.
  - `cost --by-run [--limit N]` — totals per run_id, most recent first.
  - By-API-key breakdown is shown automatically whenever more than one
    alias has spent anything, so a single-key setup doesn't get a
    meaningless one-row table by default.

## Per-run capture (source of truth for one run's own numbers)

- `VulnerabilityReport` carries `token_usage: TokenUsage` and
  `cost_usd: Optional[float]`; `ReActStep` carries `token_usage` for its own
  step. **ReAct's cost is the sum of every step, not just the final one** —
  `ReActAgent.run()` (`src/agent/react_loop.py`) accumulates usage across
  every `reason()` call in the loop (tool-call steps, the final step, and
  the max-steps-reached forced final call) before writing the cumulative
  total onto the returned report. A 3-tool-call verdict's `cost_usd`
  reflects 4 LLM calls, not 1.
- Call-graph edge resolution is tracked as a separate cost stream from
  per-finding analysis, since a graph is built once and cached, then reused
  across many later `analyze` runs — folding it into each run's per-finding
  total would double-count it every time the cached graph backs a new run.
  `LLMEdgeResolver.resolve()` returns early on a cache hit — that return
  path never reaches `OpenAIResolver`, so **a cache hit can never add to
  spend**, by construction rather than a special-cased check.
- `save_run()`'s `summary` carries `total_prompt_tokens`,
  `total_completion_tokens`, `total_tokens`, `total_cost_usd` (recomputed
  from the summed `TokenUsage`, not by summing each report's `cost_usd`, to
  avoid float drift and to correctly stay `None` if the model is unpriced).
  Each finding also carries its own `prompt_tokens`/`completion_tokens`/
  `cost_usd`. Edge-resolution cost is passed via `save_run()`'s `extra_meta`
  (`meta.edge_resolution_cost_usd`/`..._prompt_tokens`/`..._completion_tokens`),
  kept structurally separate from per-finding cost for the reason above.
  `save_patches()` carries the equivalent summary fields for patch generation.
- `EvaluationReport` (`src/evaluation/evaluator.py`) reads `total_cost_usd`/
  `total_tokens` from the run JSON's `summary` and adds `cost_per_tp()`;
  `comparison_table()` has `Cost (USD)`/`Cost/TP` columns. **A run whose
  summary carries no cost renders as `n/a`, never `$0.00`** — an untracked
  run must never be misread as free.

## What this does not do

- **No key rotation/failover/round-robin.** See "Multi-API-key attribution"
  above — deliberately scoped to attribution, not dispatch.
- ~~**No budget enforcement.**~~ Shipped: `analyze --budget-usd` caps a run at
  both phases that spend — before every call during call-graph edge resolution,
  and between functions in the analysis loop. See
  [`pipeline.md` § Capping spend](pipeline.md#capping-spend). Enforcing it in
  only one of the two is what let a run bill $31 against a $5 ceiling.
- **No retroactive cost for old runs.** Runs saved before token capture
  existed have no `token_usage` in their JSON and no rows in the ledger —
  unrecoverable after the fact.
- **No pricing-table auto-sync.** `PRICING` in `src/llm/pricing.py` is a
  static table for the models this project actually runs — add a row before
  running a new model if you want its cost tracked.
- **The ledger is supplementary, not authoritative for a single run.** A
  run's own `analysis.json`/`patches.json` is the source of truth for that
  run's numbers, keeping run files self-contained; the ledger exists for the
  cross-run/cross-phase/cross-key questions those files can't answer alone.

## Files

| File | Purpose |
|------|---------|
| `src/llm/pricing.py` | `TokenUsage`, `extract_usage()`, `PRICING` table, `estimate_cost()` |
| `src/llm/cost_ledger.py` | `CostLedger` — persistent SQLite cost ledger; `record()` + `total()`/`by_phase()`/`by_api_key()`/`by_run()` queries |
| `src/config.py` | `AppConfig.resolve_api_key(alias)` — multi-key resolution via `OPENAI_API_KEY`/`OPENAI_API_KEY_<ALIAS>` |
| `src/llm/client.py` | `LLMClient` takes `api_key`/`api_key_alias`/`cost_ledger`/`run_id`/`dataset`; `analyze()`/`reason()` take `phase` and log to the ledger |
| `src/agent/react_loop.py` | Sums `TokenUsage` across every ReAct step; labels fallback calls `react_loop_fallback` |
| `src/llm/openai_client.py` | `OpenAIResolver` logs to the ledger only on a real edge-resolution API call |
| `src/context/llm_edge_resolver.py` / `src/context/call_graph.py` | Thread `api_key_alias`/`cost_ledger`/`run_id`/`dataset` down to the resolver |
| `src/results/patch_generator.py` | `PatchGenerator` now captures usage/cost and logs to the ledger (`phase="patch_generation"`) |
| `src/results/run_saver.py` | `make_run_id()` (public, so callers can generate one before saving); run-level + per-finding/per-patch token/cost fields |
| `src/evaluation/evaluator.py` | `EvaluationReport.total_cost_usd`/`total_tokens`/`cost_per_tp()`; cost columns in `comparison_table()` |
| `src/cli.py` | `--api-key-alias` on `analyze`/`graph`/`patch`; per-run phase breakdown on `analyze`; new `cost` command |
| `tests/test_pricing.py` | Per-call/per-run capture: mocked LLM, multi-step summation, unknown-model fallback, cache-hit exclusion (12 tests) |
| `tests/test_cost_ledger.py` | Ledger record/query correctness, multi-key attribution, unknown-cost group handling, `LLMClient` writing to a provided ledger (10 tests) |
