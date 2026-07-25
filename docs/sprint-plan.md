# Sprint Plan

## Product Goal

Build a production-grade LLM-powered security analysis tool that can scan a real codebase, produce accurate vulnerability reports with low false-positive rates, and be evaluated against a ground-truth dataset.

---

## Sprint 1 — Foundation (DONE)

**Status:** Complete

**Deliverables:**
- [x] Tree-sitter based function extractor (Python, JS, C, C++)
- [x] Static + AI hybrid call graph builder
- [x] LLM-based edge resolver with persistent cache
- [x] Single-pass vulnerability analysis
- [x] ReAct agent loop (reason → act → observe)
- [x] CLI with `analyze` and `show` commands
- [x] Result persistence (extraction, call graph, analysis JSON)
- [x] Experiment runs on reference `auth-service` (24 functions, 14 runs)
- [x] Bug fixes: callee-bleed prevention, CWE normalization, affected_lines clamping

**Known issues going into Sprint 2:**
- `graph_models.py` has unused legacy types

---

## Sprint 2 — Call Graph Context, Taint Tracking & Visualization (DONE)

**Status:** Complete

**Deliverables:**
- `CallGraphNode` gained `is_taint_source` / `is_taint_sink` fields; `CallGraphBuilder.build()` sets these via pattern matching + external-callee inspection
- `CallGraphBuilder` wires `SymbolResolver` for import-based edge resolution before falling back to the LLM edge resolver
- `export_graph.py`: `export_html()` — interactive pyvis HTML with color-coded legend, dark theme, hover tooltips (entry point / taint source / taint sink / vulnerable-by-severity / infrastructure / default); `export_dot()` updated to match
- `tools.py`: `get_taint_path()` (BFS source→sink, up to 3 paths), `get_graph_summary()`, plus helpers that work with both `CallGraphNode` objects and plain dicts; wired into `react_loop.py` and the ReAct tool list in `client.py`
- CLI: `analyze --visualize/-v`; new `graph` command (`--path`, `--graph-file`, `--results`, `--html`, `--dot`, `--output-dir`)

---

## Sprint 3 — Patch Generation (DONE)

**Status:** Complete — see `docs/patching.md` for full design.

**Deliverables:**
- `src/results/patch_generator.py` — `PatchGenerator`: calls the LLM with `(original_code, explanation, cwe_id)` → returns a unified diff (`PatchResult`)
- `src/results/patch_validator.py` — `PatchValidator`: applies the diff to an in-memory copy of the function's source only (never touches the original file on disk), locating hunk context via exact match falling back to `difflib.SequenceMatcher` fuzzy matching, then re-parses with tree-sitter for a syntax check (`PatchValidationResult`)
- `VulnerabilityReport` gained `unified_diff: str`, `patch_valid: Optional[bool]`, `patch_error: Optional[str]`
- CLI `patch` command — takes a completed run JSON (`--results`), re-extracts flagged functions' source, generates + validates patches, saves to `experiments/results/patches/<run_id>_patches.json` by default (source project untouched)
- `--apply` flag on `patch` writes validated patches into the actual source files — opt-in only, requires confirmation (`--yes` to skip for non-interactive use)
- `tests/test_patching.py` — unit coverage for validator hunk-matching/syntax-check paths and generator fence-stripping/error handling (mocked LLM client)

**Not yet done:** measuring patch-apply success rate against the reference `auth-service` dataset with a real API key (exit criterion 3 below).

**Exit criteria:**
- [x] Running `patch` never modifies the analyzed project unless `--apply` is explicitly passed
- [x] Validated patches pass a tree-sitter syntax check
- [ ] Patches apply cleanly (validated in-memory) to a majority of flagged functions in the reference dataset

---

## Sprint 4 — Business Logic & Authorization Analysis (DONE)

**Goal:** Detect vulnerabilities that are invisible to syntactic/CWE-pattern
analysis because the code is syntactically fine but violates an
application-level invariant — who is allowed to touch which resource, in
what order, with what data. This is the reason the ReAct loop and call
graph exist: these bugs can only be caught by tracing a request across
functions, not by reading one function in isolation.

**Explicitly out of scope: the semantic single-pass mode
(`call_graph_context`).** Business-logic bugs need the agent to actively
check callers/callees/authorization state before making a call — a one-shot
prompt has no way to verify that, so it would just add false positives
without the ability to check them. This sprint only touches the agentic
(`--react`) path.

### Tasks

#### 4.1 Business-logic CWE taxonomy + prompt rules
Extend `_REACT_SYSTEM` in `src/llm/client.py` only — no new system prompt,
no new response schema:
- Add to the existing CWE assignment table: `CWE-639` (IDOR / broken object-level
  authorization), `CWE-862` (missing function-level authorization), `CWE-841`
  (improper enforcement of a behavioral workflow / step-ordering bypass),
  `CWE-915` (mass assignment — client body merged directly into a model/update),
  `CWE-362` (race condition on business state, e.g. double-redeem)
- Add matching entries to the existing severity table
- Add a short "business logic checklist" instructing the agent: for entry
  points or state-mutating functions, check whether a resource/user
  identifier used in a lookup or update is compared against the
  authenticated caller (not merely present), whether a role/privilege value
  is taken directly from client input, and whether a multi-step workflow's
  ordering is enforced by checking callers

#### 4.2 Reuse existing tools — no new ToolSet methods (by default)
`get_callers`, `get_callees`, `get_source`, `get_node_info`, and
`get_taint_path` already give the agent everything it needs to trace an
identifier from a request into a data access or state change. Do not add a
new tool up front — see 4.5 for the one case where it might be justified.

#### 4.3 Business-logic ground truth
A second small reference app (toy e-commerce or social-API style) with
intentionally planted IDOR, mass-assignment, and workflow-bypass bugs,
under `experiments/test_apps/`, with its own `ground_truth.json` —
mirroring how `auth-service` grounds the injection-class CWEs. A separate
dataset is needed because business-logic bugs are inherently more ambiguous
(the "correct" behavior depends on domain intent, not just syntax), so
false-positive rate has to be measured independently of the Sprint 1 results.

#### 4.4 Evaluation run
Run `--react` against the new app, compare against ground truth, and tune
the 4.1 prompt rules based on the false positives/negatives observed —
same process Sprint 1 used for the injection-class CWEs on `auth-service`.

#### 4.5 Stretch — `get_authz_checks(function_name)` tool
Only build this if 4.4 shows the agent can't reliably ground its answers
(e.g. asserting "no ownership check" without evidence). It would be a
deterministic regex scan (no LLM call) over a function's source for
conditionals referencing user/owner/role/session identity comparisons,
returned as evidence lines. Deferred by default to keep the sprint minimal.

**Exit criteria:**
- [x] `--react` flags IDOR / mass-assignment / workflow-bypass bugs in the new
      reference app at a precision comparable to Sprint 1's injection-class results
- [x] Semantic (`call_graph_context`) mode and `VulnerabilityReport` schema
      are unchanged — all changes confined to `_REACT_SYSTEM`
- [x] `docs/business-logic.md` written documenting the taxonomy, checklist,
      and evaluation results

**Status:** Complete — see `docs/business-logic.md` for the full taxonomy,
attribution rule, and 3-round evaluation writeup against the new
`orders-service` ground truth (5/5 recall, one documented residual
false-positive pattern).

---

## Sprint 5 — Automated Evaluation Framework (DONE)

**Status:** Complete — see `docs/evaluation.md` for full design.

**Goal:** Sprints 1, 3, and 4 all measured precision/recall by hand — counting
matches between a run's `findings[]` and a ground truth dataset in prose (see
`docs/business-logic.md`'s "3 Rounds" section). That doesn't scale past a
couple of dozen functions and isn't reproducible. Replace it with a
deterministic, offline scoring step over already-completed `analyze` runs —
no LLM calls, no changes to the ground truth schema or `VulnerabilityReport`.

### Tasks

#### 5.1 Ground truth loader
- `src/evaluation/ground_truth.py` — `GroundTruthEntry` / `GroundTruthDataset` /
  `load_ground_truth()`, matching the existing `experiments/ground_truth/*.json`
  schema unchanged

#### 5.2 Matching + scoring
- `src/evaluation/evaluator.py` — matches each ground truth row to a finding by
  `function_name`, disambiguating by `file_path` suffix when a name repeats
  across files (e.g. `auth-service`'s duplicated `rateLimiter` bug); rows that
  can't be disambiguated are reported separately rather than guessed
- TP/FP/FN/TN confusion matrix + precision/recall/F1 at the instance level
- CWE-exactness accuracy computed independently of detection accuracy
- Deduplicated (`duplicate_of`-aware) unique-vulnerability recall — the
  "N/N recall" style number used in `docs/business-logic.md`
- Per-CWE breakdown (planted / detected / correct-CWE)
- Hallucination rate restricted to flagged (TP+FP) findings

#### 5.3 CLI `evaluate` command
- `--results` (repeatable — pass more than once to compare modes/models side
  by side), `--ground-truth`, `--output-dir`
- Saves `experiments/results/evaluations/eval_<run_id>.json` per run; prints a
  markdown comparison table across runs when more than one `--results` is given
- Purely read-only: never touches the run file, ground truth file, or analyzed project

#### 5.4 Tests
- `tests/test_evaluation.py` — synthetic ground truth + synthetic run JSON,
  no LLM calls: TP/FP/FN scoring, duplicate-name file disambiguation, dedup
  recall, unmatched-finding exclusion, hallucination rate, JSON round-trip,
  comparison table formatting

**Exit criteria:**
- [x] `evaluate` reproduces the `auth-service` Sprint 1 numbers (11/11 detection
      instances correct, 10/10 deduplicated recall) with no manual counting
- [x] Running the same ground truth against two archived runs
      (`gpt-4o-mini` vs `o4-mini`) reproduces the known qualitative Sprint 1
      finding as a concrete number (precision 0.79 vs 1.00 at equal recall)
- [x] `evaluate` never writes to the analyzed project, the run file, or the
      ground truth file
- [x] `docs/evaluation.md` written documenting the matching rules and metrics

---

## Sprint 6 — Real-World Repository Evaluation

**Goal:** Defend the results against the most predictable examiner criticism —
*"you evaluated on small apps you wrote yourself, with bugs you planted
yourself."* Three of the four current datasets are exactly that
(auth-service 25 functions, billing-service 22, orders-service 27); only
NodeGoat (56) is third-party. Running against a real open-source repository
with vulnerabilities **someone else** chose is what makes the precision/recall
numbers externally valid.

Scale work is in scope only where it blocks that goal. This sprint is
deliberately *not* about making the tool a product.

### Tasks

#### 6.1 Honest coverage reporting (DONE)
Functions over `max_function_lines` (200) were dropped with no log, no counter,
no warning — on a real repo that silently shrinks the denominator behind every
recall and coverage number, with nothing in the output disclosing it. Now
`TreeSitterParser.last_skipped` / `CodeExtractor.skipped_functions` record every
oversized function; `analyze` prints a skip count with an explicit coverage
percentage, and `extraction.json` carries `functions_skipped_oversized`,
`coverage`, and a per-function `skipped_oversized[]` list.

This was a validity fix, not a scale feature — worth doing regardless of
whether a large repo is ever analysed.

#### 6.2 Select and prepare a real-world dataset
Pick one open-source repository in a supported language (Python / JavaScript /
C / C++) with **externally documented** vulnerabilities — CVE-linked fixing
commits, or a recognised third-party benchmark app. Check out the *vulnerable*
commit, derive ground truth from the fix diff (or the project's own documented
issue list), and record it in the existing `experiments/datasets/<name>/`
layout. Size target: a few hundred functions — large enough to be credible,
small enough to afford.

Whole repositories only. Function-level vulnerability corpora (BigVul, Devign,
DiverseVul, PrimeVul) ship *detached* functions with no surrounding project, so
no call graph can be built from them — they structurally cannot exercise the
inter-procedural context that is this tool's central claim. Worth stating
explicitly in the thesis as the reason those standard benchmarks were not used.

#### 6.3 Estimate before committing
Use the Sprint 7 cost ledger to project the run before paying for it: take
measured per-function cost from a small dataset, multiply by the target repo's
function count, per mode. A ReAct run over several hundred functions may simply
be unaffordable — better to know beforehand and scope the dataset accordingly.

#### 6.4 Throughput — only if the sequential run proves intolerable
The analysis loop is sequential. For a thesis "finishes overnight" is
acceptable, so concurrency is a convenience, not a blocker. If a run does prove
impractical: bounded parallel batches, exponential backoff on 429s, and
checkpoint/resume so an interrupted run isn't lost. Do not build this
speculatively.

#### 6.5 TypeScript — only if the chosen repo needs it
`.ts` already maps to the JavaScript grammar and parses; only type annotations
are lost. Purely a consequence of the 6.2 dataset choice — zero work if that
repo is plain JS. Decide after 6.2, not before.

**Explicitly out of scope** (considered and dropped, not deferred):
- **Incremental / cached analysis** (hash-and-skip re-analysis). Beyond being
  unrequested, it works against the evaluation method: LLM output is
  non-deterministic and Sprint 4 already relied on comparing repeated rounds.
  Serving cached verdicts would mask exactly the run-to-run variance that may
  need measuring.
- **SARIF export / GitHub Code Scanning integration.** An IDE- and
  CI-integration feature with no bearing on any thesis claim.
- **Large-function chunking** (overlapping windows + merged results). 6.1 makes
  the skips visible; chunking is only worth building if the reported count on a
  real repo turns out to be material, and it carries real result-merging
  complexity.

**Exit criteria:**
- [x] No function is dropped from a run without being counted and reported;
      every run states its own coverage
- [ ] One real-world third-party repository analysed end to end, with ground
      truth derived from external evidence (CVE fix commits or a documented
      vulnerability list) rather than self-planted bugs
- [ ] `evaluate` produces precision/recall/F1 **and** cost per true positive on
      that repo, for at least two analysis modes
- [ ] Reported coverage on that repo is stated in the thesis alongside the
      accuracy numbers, so recall is never quoted over an unstated denominator

---

## Sprint 7 — Cost & Token Tracking (DONE)

**Status:** Complete — see `docs/cost-tracking.md` for the full design.

**Goal:** Right now no run reports what it cost. `response.usage` (prompt/completion
tokens) comes back from every OpenAI call in `src/llm/client.py` and
`src/llm/openai_client.py` and is discarded — `docs/evaluation.md` explicitly notes
"no API key or cost involved" because there is nothing to show. This is a gap, not
just a nice-to-have: Sprint 6 already names "cost ceilings" as a scaling constraint
without any number behind it, and the thesis needs a real answer to "is ReAct's
accuracy gain worth its extra API cost compared to single-pass/call-graph mode" —
that's an empty question until token usage and $ cost are actually measured per mode.

### Tasks

#### 7.1 Token usage capture
Capture `response.usage` (prompt_tokens, completion_tokens, total_tokens) at every
`chat.completions.create` call site:
- `LLMClient.analyze()` and `LLMClient.reason()` in `src/llm/client.py`
- `OpenAIResolver.resolve_edge()` in `src/llm/openai_client.py` — **only on an actual
  API call**, not a cache hit (`edge_cache.json` already avoids repeat LLM calls for
  edge resolution; counting a cache hit as spend would over-report cost every time
  the same graph is reused across runs)
- A small `TokenUsage` dataclass threaded onto `VulnerabilityReport` and `ReActStep`.
  For the ReAct loop, `react_loop.py` must sum usage across **every step** of a
  function's loop, not just the final step — a verdict after 3 tool calls costs 4x
  what a single-pass verdict costs, and only the sum reflects that.

#### 7.2 Pricing table
`src/llm/pricing.py` — a static $/1M-input-token and $/1M-output-token table for the
models this project actually runs (`o4-mini`, `gpt-4o-mini`), converting a
`TokenUsage` into a dollar figure. A model missing from the table must report cost
as `None` ("unknown"), never a silently wrong guessed number.

#### 7.3 Run-level aggregation
- `run_saver.save_run()`: add `total_prompt_tokens` / `total_completion_tokens` /
  `total_cost_usd` to the run `summary`, plus per-finding `token_usage`/`cost_usd`
  (same pattern Sprint 3 used to add `unified_diff`/`patch_valid` per finding)
- Report call-graph edge-resolution cost separately from per-finding analysis cost —
  the graph is built once and cached, then reused across many `analyze` runs, so
  folding its cost into each run's per-finding total would double-count it every
  time the same cached graph backs a new run

#### 7.4 `evaluate` cost-effectiveness columns
Extend `comparison_table()` in `src/evaluation/evaluator.py` to show `cost_usd` and
`cost_per_TP` alongside precision/recall/F1 when every compared run carries usage
data — this is what turns Sprint 6's "cost ceilings" concern into the same kind of
concrete number Sprint 5 produced for accuracy (e.g. "precision 0.79 vs 1.00").
Archived pre-Sprint-7 runs have no usage data — show `n/a`, not `$0.00`, so an old
run is never misread as free.

#### 7.5 CLI surfacing
- `analyze` prints a one-line token/cost summary at the end of a run, next to the
  existing found/clean/error counts
- Stretch: `--budget-usd` ceiling on `analyze` — stop starting new function analyses
  once running spend crosses it, warn, and save the partial run as-is. Only worth
  doing if it falls out naturally alongside Sprint 6.1's checkpoint/resume work;
  don't build it standalone.

#### 7.6 Tests
Mocked `response.usage` covering: correct capture in `analyze()`/`reason()`;
correct multi-step summation in the ReAct loop; unknown model → `cost_usd is None`
not a crash; edge-resolver cache hits contribute zero tokens.

#### 7.7 Persistent cross-run ledger + multi-API-key attribution (added after initial
7.1–7.6 landed, once real usage surfaced two gaps: patch generation was the one
AI-calling phase left untracked, and cost only existed inside one run's own JSON
with no way to total spend across runs)
- `src/llm/cost_ledger.py` — `CostLedger`: a SQLite-backed, append-only
  `cost_events` table (one row per real LLM call, tagged with `phase`,
  `run_id`, `dataset`, `api_key_alias`, `model`, tokens, `cost_usd`) at
  `experiments/cost_ledger.db` (gitignored, like the rest of `experiments/`).
  Query methods (`total()`, `by_phase()`, `by_api_key()`, `by_run()`) all
  degrade a group's cost to `None` if any event in it has unknown pricing,
  never a partial sum. A ledger write failure is logged and swallowed —
  cost tracking must never fail an analysis run.
- `PatchGenerator.generate()` now captures usage/cost and logs
  `phase="patch_generation"` — closes the one AI-calling phase Sprint 7.1–7.3
  didn't cover.
- `AppConfig.resolve_api_key(alias)` (`src/config.py`) — multi-key support:
  default key from `OPENAI_API_KEY`, a named key `"team2"` from
  `OPENAI_API_KEY_TEAM2`. Every LLM-calling constructor (`LLMClient`,
  `OpenAIResolver`, `PatchGenerator`) takes `api_key_alias` and stamps every
  ledger row with it — the raw key value itself is never written to the
  ledger. Deliberately attribution-only, not rotation/failover/round-robin
  dispatch across keys (that's a request-dispatch concern, arguably Sprint
  6.1's rate-limit scope, not a cost-accounting one).
- CLI: `--api-key-alias` on `analyze`/`graph`/`patch`; `analyze` prints a
  per-run phase breakdown pulled live from the ledger; new `cost` command
  (`cost`, `cost --run-id <id>`, `cost --by-run`) for cross-run/cross-phase/
  cross-key totals.
- `tests/test_cost_ledger.py` — 10 tests: record/query correctness, `run_id`
  scoping, unknown-cost group handling, multi-key attribution, `AppConfig`
  key resolution (default/named/missing), `LLMClient` actually writing to a
  provided ledger, and that omitting the ledger doesn't change behavior.

**Exit criteria:**
- [x] Every `analyze` run (single-pass, call-graph, ReAct) reports total tokens + $
      cost in its saved JSON, with ReAct's cost correctly summed across all steps
- [ ] `evaluate` shows cost alongside precision/recall/F1 for at least two archived
      runs of different modes — **not yet done**: this needs a fresh live-API-key
      `analyze` run (all runs archived under `experiments/datasets/` predate Sprint 7
      and have no `total_cost_usd` in their summary, so `evaluate` correctly reports
      them as `n/a` rather than fabricating a number; a real cost-vs-accuracy
      comparison table needs at least one post-Sprint-7 run to compare against)
- [x] Call-graph edge-resolution cache hits are never counted as new spend
- [x] A run against a model missing from the pricing table degrades to "cost
      unknown" rather than a fabricated number
- [x] Every AI-calling phase (edge resolution, analysis, patch generation) is
      tracked, not just analysis
- [x] Cost persists across runs in a queryable form (`cost_ledger.db`), and
      spend from more than one API key is attributed by alias, not merged
- [x] `docs/cost-tracking.md` written documenting the pricing table, the
      per-step ReAct summation, the ledger schema, multi-key attribution, and
      what still needs a live run to demonstrate

---

## Backlog (Unscheduled)

| Item | Notes |
|------|-------|
| VSCode extension | Real-time inline vulnerability highlighting |
| Semgrep rule export | Convert LLM findings to reusable Semgrep rules |
| False-positive feedback loop | Allow users to mark findings as FP; fine-tune prompts |
| Go / Rust / Java support | Add tree-sitter grammars |
| Inter-procedural analysis | Analyze chains of 3+ functions together |
| `get_authz_checks` tool | Sprint 4.5 stretch goal — only if prompt-only approach can't ground its answers |

---

## Documentation Plan (per Sprint)

| Sprint | Doc |
|--------|-----|
| 1 | `docs/project-overview.md`, `docs/architecture.md`, `docs/sprint-plan.md` |
| 2 | *(covered by updates to `docs/project-overview.md` — call graph visualization, taint tracking)* |
| 3 | `docs/patching.md` — patch generation & validation approach |
| 4 | `docs/business-logic.md` — business-logic CWE taxonomy, checklist, evaluation results |
| 5 | `docs/evaluation.md` — automated precision/recall/F1 harness, matching rules |
| 6 | `docs/real-world-evaluation.md` — dataset selection & ground-truth derivation, coverage reporting, results |
| 7 | `docs/cost-tracking.md` — pricing table, per-step ReAct cost summation, cost-vs-accuracy comparison |
