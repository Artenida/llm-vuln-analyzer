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

## Sprint 6 — Scale & Multi-Language

**Goal:** Analyze real-world open-source repositories (hundreds to thousands of functions) without hitting API rate limits or cost ceilings.

### Tasks

#### 6.1 Batch Analysis
- Process functions in parallel batches (configurable concurrency)
- Rate-limit aware: exponential backoff on 429s
- Resume from last checkpoint if interrupted

#### 6.2 Incremental / Cached Analysis
- Hash each function's code; skip re-analysis if hash matches a cached result
- Only re-analyze functions that changed since last run (git-diff integration)

#### 6.3 TypeScript Support
- TypeScript is currently mapped to the JavaScript grammar — good for syntax but misses type annotations
- Add `tree-sitter-typescript` grammar for richer type-aware context in prompts

#### 6.4 Large-Function Handling
- Functions over `max_function_lines` (currently 200) are silently skipped
- Instead: chunk them into overlapping windows and analyze each window; merge results

#### 6.5 Filtering & Triage UI
- `show` command enhancements: filter by severity, CWE, file, function name
- Export to SARIF format for GitHub Code Scanning / VS Code integration

**Exit criteria:**
- Successfully analyze a 500-function real-world repo in < 30 minutes
- SARIF export validated by GitHub Advanced Security

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
| 6 | `docs/scaling.md` — batch processing, caching, incremental analysis |
| 6 | `docs/sarif-integration.md` — GitHub Code Scanning setup |
