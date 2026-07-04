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

## Sprint 3 — Patch Generation (NEXT)

**Goal:** Given a confirmed vulnerability finding, generate and validate a concrete code fix — as a proposal the user reviews, not a change applied to their project automatically.

### Tasks
1. `src/results/patch_generator.py` — `PatchGenerator`: calls the LLM with `(original_code, explanation, cwe_id)` → returns a unified diff
2. `src/results/patch_validator.py` — `PatchValidator`: applies the diff via `difflib` to an in-memory copy of the function's source only (never touches the original file on disk), then re-parses with tree-sitter for a syntax check
3. `VulnerabilityReport` gains `unified_diff: str`, `patch_valid: bool`, `patch_error: Optional[str]`
4. New CLI command `patch` — takes a completed run JSON, generates + validates patches for all flagged functions, and by default only writes results to `experiments/results/patches/<run_id>_patches.json` (diffs + validity, source project untouched)
5. Optional `--apply` flag on `patch` (or a separate `patch apply` subcommand) lets the user write validated patches into the actual source files. This is opt-in only — never the default — and should require an explicit target confirmation before writing

**Exit criteria:**
- Running `patch` never modifies the analyzed project unless `--apply` is explicitly passed
- Patches apply cleanly (validated in-memory) to a majority of flagged functions in the reference dataset
- Validated patches pass a tree-sitter syntax check

---

## Sprint 4 — Scale & Multi-Language

**Goal:** Analyze real-world open-source repositories (hundreds to thousands of functions) without hitting API rate limits or cost ceilings.

### Tasks

#### 4.1 Batch Analysis
- Process functions in parallel batches (configurable concurrency)
- Rate-limit aware: exponential backoff on 429s
- Resume from last checkpoint if interrupted

#### 4.2 Incremental / Cached Analysis
- Hash each function's code; skip re-analysis if hash matches a cached result
- Only re-analyze functions that changed since last run (git-diff integration)

#### 4.3 TypeScript Support
- TypeScript is currently mapped to the JavaScript grammar — good for syntax but misses type annotations
- Add `tree-sitter-typescript` grammar for richer type-aware context in prompts

#### 4.4 Large-Function Handling
- Functions over `max_function_lines` (currently 200) are silently skipped
- Instead: chunk them into overlapping windows and analyze each window; merge results

#### 4.5 Filtering & Triage UI
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

---

## Documentation Plan (per Sprint)

| Sprint | Doc |
|--------|-----|
| 1 | `docs/project-overview.md`, `docs/architecture.md`, `docs/sprint-plan.md` |
| 2 | *(covered by updates to `docs/project-overview.md` — call graph visualization, taint tracking)* |
| 3 | `docs/patching.md` — patch generation & validation approach |
| 4 | `docs/scaling.md` — batch processing, caching, incremental analysis |
| 4 | `docs/sarif-integration.md` — GitHub Code Scanning setup |
