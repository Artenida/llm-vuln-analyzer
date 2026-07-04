# Sprint Plan

## Product Goal

Build a production-grade LLM-powered security analysis tool that can scan a real codebase, produce accurate vulnerability reports with low false-positive rates, and be evaluated against a ground-truth dataset.

---

## Sprint 1 — Foundation (DONE)

**Status:** Complete (experiments done, code stabilized)

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
- `ImportExtractor`/`RouteExtractor` not wired into extraction pipeline
- `SymbolResolver` always returns empty (depends on `imports`)
- No evaluation framework — accuracy measured informally
- `agent/memory.py` is an empty stub
- `graph_models.py` has unused legacy types

---

## Sprint 2 — Accuracy & Evaluation

**Goal:** Measure and improve analysis accuracy with a proper ground-truth dataset and fix the remaining static resolution gap.

### Tasks

#### 2.1 Wire Import and Route Extraction
- Call `ImportExtractor.extract(content)` inside `CodeExtractor._extract_samples()` and populate `CodeSample.imports`
- Call `RouteExtractor.extract(content)` to populate `CodeSample.routes`
- This enables `SymbolResolver` to resolve member-expression calls (e.g., `authService.registerUser`) via import aliasing rather than falling through to the LLM every time

#### 2.2 Ground-Truth Evaluation Dataset
- Create `test_apps/` with 3–5 small reference applications across Python and JavaScript:
  - Auth service with deliberate SQL injection, IDOR, JWT misuse
  - File upload handler with path traversal
  - API service with command injection
- Label each function as `vulnerable: true/false` with the correct CWE
- Store labels in `test_apps/<app>/ground_truth.json`

#### 2.3 Evaluation Runner
- New command: `python -m src.cli evaluate --path <app> --ground-truth <gt.json>`
- Outputs: precision, recall, F1 per severity, confusion matrix
- Saves to `experiments/results/evaluation/`

#### 2.4 Prompt Tuning
- Run evaluation across `gpt-4o-mini`, `o4-mini`, and `gpt-4o` on the ground-truth dataset
- Document precision/recall tradeoffs per model in `docs/model-comparison.md`

#### 2.5 Agent Memory (`agent/memory.py`)
- Implement cross-function memory: if the agent sees that `execute()` receives unsanitized input from `findByUsername()`, it can carry that context when analyzing `findByUsername`
- Scoped to one analysis run (not persistent across runs)

**Exit criteria:**
- F1 ≥ 0.80 on ground-truth dataset with `o4-mini` + ReAct
- `SymbolResolver` resolves ≥ 50% of import-based call edges without LLM fallback

---

## Sprint 3 — Scale & Multi-Language

**Goal:** Analyze real-world open-source repositories (hundreds to thousands of functions) without hitting API rate limits or cost ceilings.

### Tasks

#### 3.1 Batch Analysis
- Process functions in parallel batches (configurable concurrency)
- Rate-limit aware: exponential backoff on 429s
- Resume from last checkpoint if interrupted

#### 3.2 Incremental / Cached Analysis
- Hash each function's code; skip re-analysis if hash matches a cached result
- Only re-analyze functions that changed since last run (git-diff integration)

#### 3.3 TypeScript Support
- TypeScript is currently mapped to the JavaScript grammar — good for syntax but misses type annotations
- Add `tree-sitter-typescript` grammar for richer type-aware context in prompts

#### 3.4 Large-Function Handling
- Functions over `max_function_lines` (currently 200) are silently skipped
- Instead: chunk them into overlapping windows and analyze each window; merge results

#### 3.5 Filtering & Triage UI
- `show` command enhancements: filter by severity, CWE, file, function name
- Export to SARIF format for GitHub Code Scanning / VS Code integration

**Exit criteria:**
- Successfully analyze a 500-function real-world repo in < 30 minutes
- SARIF export validated by GitHub Advanced Security

---

## Sprint 4 — Multi-Provider & Reporting

**Goal:** Support Anthropic models and produce professional-grade security reports.

### Tasks

#### 4.1 Anthropic Provider
- Implement `src/llm/anthropic_client.py` using the Anthropic Python SDK
- Abstract `LLMClient` into a provider interface (`BaseAnalyzer`)
- Config: `llm.provider: anthropic`, `llm.model: claude-opus-4-7`

#### 4.2 Model Routing
- Use a cheap model (Haiku / `gpt-4o-mini`) for initial screening
- Escalate to a stronger model (Opus / `o4-mini`) only for high-confidence findings
- Document cost savings in experiments

#### 4.3 HTML / PDF Report Generation
- `python -m src.cli report --run <run_id> --format html`
- Per-function finding cards with severity badges, code snippets, patch suggestions
- Executive summary: severity breakdown pie chart, OWASP Top 10 coverage

#### 4.4 CI/CD Integration
- GitHub Actions example workflow: scan PR diff, comment findings inline
- Exit code 1 if any `critical` or `high` severity findings (configurable threshold)
- `.llm-vuln-analyzer.yml` config file at repo root for CI settings

**Exit criteria:**
- Anthropic + OpenAI produce comparable results on evaluation dataset
- CI integration demonstrated on a sample open-source repo PR

---

## Backlog (Unscheduled)

| Item | Notes |
|------|-------|
| VSCode extension | Real-time inline vulnerability highlighting |
| Semgrep rule export | Convert LLM findings to reusable Semgrep rules |
| False-positive feedback loop | Allow users to mark findings as FP; fine-tune prompts |
| Go / Rust / Java support | Add tree-sitter grammars |
| Taint tracking | Track user-controlled data flow across call boundaries |
| Inter-procedural analysis | Analyze chains of 3+ functions together |

---

## Documentation Plan (per Sprint)

| Sprint | Doc |
|--------|-----|
| 1 (now) | `docs/project-overview.md`, `docs/architecture.md`, `docs/sprint-plan.md` |
| 2 | `docs/evaluation.md` — methodology, dataset, results |
| 2 | `docs/model-comparison.md` — precision/recall table per model |
| 3 | `docs/scaling.md` — batch processing, caching, incremental analysis |
| 3 | `docs/sarif-integration.md` — GitHub Code Scanning setup |
| 4 | `docs/providers.md` — adding new LLM providers |
| 4 | `docs/ci-integration.md` — GitHub Actions workflow |
