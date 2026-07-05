# Architecture

> **Current state: Sprint 3 complete.** Sprint 4 (Scale & Multi-Language) is next.

---

## System Overview

```
┌────────────────────────────────────────────────────────────────────────────────────┐
│  CLI   src/cli.py   —   commands: analyze | graph | show | patch                    │
└───────────┬──────────────────┬──────────────────────┬──────────────────┬───────────┘
            │                  │                      │                  │
    ┌───────▼──────┐   ┌───────▼───────┐     ┌────────▼────────┐ ┌───────▼────────┐
    │  Ingestion   │   │  Call Graph   │     │  LLM / Agent    │ │  Patch          │
    │  Layer       │   │  Layer        │     │  Layer          │ │  Layer          │
    │ src/ingestion│   │ src/context   │     │ src/llm,        │ │ src/results/    │
    │              │   │               │     │ src/agent       │ │ patch_*.py      │
    └──────────────┘   └───────┬───────┘     └────────┬────────┘ └────────┬────────┘
                                │                      │                   │
                        ┌───────▼───────┐     ┌────────▼────────┐          │
                        │  Results &    │     │  ToolSet        │          │
                        │  Visualization│     │  (graph tools)  │          │
                        │  src/results  │     └─────────────────┘          │
                        └───────┬───────┘                                 │
                                └─────────────────────────────────────────┘
                              (patch command re-reads a saved analysis.json)
```

**Analysis pipeline (end-to-end):**
```
Source code (file / dir / snippet)
  │
  ▼  Ingestion Layer
  List[CodeSample]  (one per function, with AST node + imports + routes)
  │
  ▼  Call Graph Layer  (always built)
  Dict[str, CallGraphNode]  +  name_index
  │
  ▼  LLM / Agent Layer
  List[VulnerabilityReport]
  │
  ▼  Results Layer
  analysis.json  +  call_graph.html  +  call_graph.dot
  │
  ▼  Patch Layer  (separate `patch` command, run against a saved analysis.json)
  <run_id>_patches.json   (diffs + validity — source untouched unless --apply)
```

---

## Detailed Information Flow

The diagram below traces one function all the way from raw source text to a
validated patch proposal, showing exactly which module produces which piece
of data and where it is persisted.

```
 ┌─────────────────────┐
 │ source file / dir /  │
 │ inline snippet        │
 └──────────┬────────────┘
            │  CodeExtractor.from_path() / from_snippet()      [src/ingestion/extractor.py]
            ▼
 ┌───────────────────────────────────────────────────────────────┐
 │ TreeSitterParser.extract_functions()                          │  [src/ingestion/parser.py]
 │   → FunctionNode(name, body, start_line, end_line, ast_node)   │
 │ ImportExtractor.extract()  → List[ImportReference]             │  [import_extractor.py]
 │ RouteExtractor.extract()   → List[RouteDefinition]              │  [route_extractor.py]
 └──────────┬──────────────────────────────────────────────────────┘
            │  one CodeSample per function
            ▼
 ┌───────────────────────────────────────────────────────────────┐
 │ List[CodeSample]                                                │  → saved: extraction.json
 └──────────┬──────────────────────────────────────────────────────┘
            │  CallGraphBuilder.build(samples)                     [src/context/call_graph.py]
            │    1. create one CallGraphNode per sample
            │    2. resolve each call site to a callee node_id:
            │         exact name → SymbolResolver (import-aware)
            │         → LLMEdgeResolver (cached)  → external::<name>
            │    3. flag is_entry_point / is_infrastructure (pattern match)
            │    4. flag is_taint_source (= is_entry_point)
            │    5. flag is_taint_sink (external callee / name pattern match)
            ▼
 ┌───────────────────────────────────────────────────────────────┐
 │ Dict[node_id, CallGraphNode]  +  name_index                     │  → saved: call_graph.json
 └──────────┬──────────────────────────────────────────────────────┘
            │  ToolSet(graph, name_index)                          [src/agent/tools.py]
            │
            ├─────────────────────────────┬─────────────────────────────┐
            │  Semantic mode (default)     │  Agentic mode (--react)      │
            ▼                              ▼                              │
 ┌─────────────────────────┐   ┌─────────────────────────────────────┐    │
 │ tools.trace_one_hop()    │   │ ReActAgent.run(sample, graph)       │    │
 │  → callers + callees     │   │  [src/agent/react_loop.py]          │    │
 │ _build_context_prompt()  │   │  loop (max_steps):                  │    │
 │  [src/cli.py]            │   │    AgentMemory.get_context_for()    │    │
 │        │                  │   │      (prior findings on neighbours) │    │
 │        ▼                  │   │    llm.reason(sample, tool_history) │    │
 │ LLMClient.analyze()       │   │      → ReActStep (tool | final)     │    │
 │  [src/llm/client.py]      │   │    if tool:  ToolSet.execute(...)   │    │
 │        │                  │   │      get_callees / get_callers /    │    │
 │        │                  │   │      get_source / is_entry_point /  │    │
 │        │                  │   │      get_node_info / get_taint_path │    │
 │        │                  │   │      → append to tool_history       │    │
 │        │                  │   │    if final: → VulnerabilityReport  │    │
 │        ▼                  │   │  AgentMemory.record(finding)        │    │
 │ VulnerabilityReport       │   │        │                             │    │
 │ (analysis_mode=           │   │        ▼                             │    │
 │  call_graph_context)      │   │ VulnerabilityReport                  │    │
 │                            │   │ (analysis_mode=react_loop)           │    │
 └─────────────┬─────────────┘   └───────────────┬───────────────────────┘    │
               └───────────────┬──────────────────┘                            │
                                ▼                                              │
                    List[VulnerabilityReport]                                 │
                                │  save_run()                    [run_saver.py]│
                                ▼                                              │
                        analysis.json  ◄─────────────────────────────────────-┘
                         (findings: vulnerability_found, cwe_id, severity,
                          affected_lines, explanation, patch_suggestion,
                          confidence, hallucination_flag, analysis_mode)
                                │
                                │  export_html() / export_dot()   [export_graph.py]
                                ▼
                call_graph.html / call_graph_annotated.html / call_graph.dot
                                │
                                │  `python -m src.cli patch --results analysis.json`
                                ▼
 ┌───────────────────────────────────────────────────────────────┐
 │ patch command                                                  │  [src/cli.py]
 │  1. load analysis.json → findings where vulnerability_found    │
 │  2. re-extract source_path with CodeExtractor                  │
 │     → recover each flagged function's exact code/lines         │
 │  3. for each finding:                                           │
 │       PatchGenerator.generate(code, explanation, cwe_id)        │  [patch_generator.py]
 │         → LLM call → unified diff (PatchResult)                 │
 │       PatchValidator.validate(code, diff, language)              │  [patch_validator.py]
 │         → apply hunks to an IN-MEMORY copy only                 │
 │           (exact match, else difflib.SequenceMatcher fuzzy match)│
 │         → tree-sitter re-parse → has_error check                │
 │         → PatchValidationResult(valid, patched_code, error)     │
 └──────────┬──────────────────────────────────────────────────────┘
            │  save_patches()                                      [run_saver.py]
            ▼
   experiments/results/patches/<run_id>_patches.json
   (unified_diff, patch_valid, patch_error, patched_code — per finding)
            │
            │  source project is UNTOUCHED up to this point
            │
            │  only if --apply is passed AND user confirms (or --yes):
            ▼
   original source file's [start_line, end_line] replaced with patched_code
   (src/cli.py::_write_patch_to_file)
```

Key invariant carried through the whole pipeline: **nothing writes to the
analyzed project except the final, explicitly-confirmed `--apply` step.**
Every other stage (extraction, call graph, analysis, patch generation,
patch validation) only ever produces new files under `experiments/`.

---

## Layer 1 — Ingestion  (`src/ingestion/`)

Converts source files into `CodeSample` objects — one per function.

| File | Role |
|------|------|
| `extractor.py` | Entry point: file, directory, or inline snippet; walks directory tree |
| `parser.py` | Wraps tree-sitter; extracts function bodies and AST nodes |
| `import_extractor.py` | Regex extraction of `require()` / `import from` statements → `ImportReference` list |
| `route_extractor.py` | Regex extraction of Express route declarations → `RouteDefinition` list |

**`CodeSample` fields populated at this stage:**

| Field | Source |
|-------|--------|
| `function_name`, `code`, `language` | tree-sitter |
| `file_path`, `start_line`, `end_line` | tree-sitter |
| `ast_node`, `raw_content` | tree-sitter |
| `imports` | `ImportExtractor.extract()` |
| `routes` | `RouteExtractor.extract()` |

`start_line`/`end_line` are the same 1-indexed, inclusive line range used
later by the `patch --apply` step to splice patched code back into a file,
so they must stay accurate — this is the reason patch generation re-runs
extraction rather than trusting cached line numbers from an old run.

---

## Layer 2 — Call Graph  (`src/context/`)

Builds a static + AI hybrid call graph from the `CodeSample` list.

| File | Role |
|------|------|
| `call_graph.py` | Core builder: creates nodes, resolves edges, runs taint analysis |
| `symbol_resolver.py` | Import-aware static resolution (`alias.method → file::function`) |
| `llm_edge_resolver.py` | AI fallback for edges that static resolution cannot resolve; uses cache |
| `edge_cache.py` | Persistent JSON cache — avoids re-calling the LLM for the same edge |
| `graph_traversal.py` | BFS downstream traversal (subgraph extraction) |
| `context_builder.py` | Builds a `FunctionContext` (target + 1-hop callers/callees) |

### `CallGraphNode` structure

```python
@dataclass
class CallGraphNode:
    id: str              # "path/to/file.py::function_name"
    function_name: str
    file_path: str
    callers: Set[str]        # node_ids that call this function
    callees: Set[str]        # node_ids this function calls
    is_entry_point: bool     # HTTP handlers, controllers, route files
    is_infrastructure: bool  # DB execute/query/connect layer
    is_external: bool        # unresolved library calls (e.g. jwt.sign)
    is_taint_source: bool    # receives untrusted user input (entry points)
    is_taint_sink: bool      # passes data to dangerous ops (SQL, shell, eval)
```

### Edge resolution order

```
raw_call  (e.g. "authService.registerUser")
  1. Exact name match in known function set
  2. Strip member prefix  →  "registerUser"
  3. SymbolResolver: match alias to import file  →  "auth_service.js::registerUser"
  4. LLM resolver with persistent cache
  5. External node  →  "external::authService.registerUser"
```

### Taint detection (automatic, no LLM)

| Role | Detection rule |
|------|----------------|
| `is_taint_source` | `is_entry_point == True` (HTTP handlers receive user input) |
| `is_taint_sink` | External callee name matches: `execute`, `query`, `eval`, `exec`, `system`, `popen`, `spawn` … |
| `is_taint_sink` | Function name matches: `execute_query`, `exec_query`, `run_command`, `eval` … |

The `get_taint_path()` tool runs a BFS through the call graph to find source→function→sink paths for the agent.

---

## Layer 3 — LLM / Agent  (`src/llm/`, `src/agent/`)

### Two analysis modes

| CLI flags | Mode name | `analysis_mode` tag | How it works |
|-----------|-----------|---------------------|--------------|
| _(none)_ | **Semantic** | `call_graph_context` | Call graph always built; callers + callees injected into prompt |
| `--react` | **Agentic** | `react_loop` (or `react_loop_fallback`) | Agent queries the graph iteratively before verdict |

### `LLMClient`  (`src/llm/client.py`)

| Method | Used by | Returns |
|--------|---------|---------|
| `analyze(sample, context_prompt)` | Semantic mode, and as a fallback when ReAct returns an empty verdict | `VulnerabilityReport` |
| `reason(sample, tool_history)` | Agentic mode (one step) | `ReActStep` |

### ReAct loop  (`src/agent/react_loop.py`)

```
state = AgentState(current_function=sample.function_name)
tool_history = [ prior findings from AgentMemory for this function's neighbours ]

for step in range(max_steps):
    react_step = llm.reason(sample, tool_history)
    if react_step.is_final:
        if _is_empty_output(react_step.report):        # confidence 0, no explanation, no error
            report = llm.analyze(sample)                # single-pass fallback retry
            report.analysis_mode = "react_loop_fallback"
        else:
            report.analysis_mode = "react_loop"
        AgentMemory.record(node_id, report)              # so later functions see this finding
        return report
    result = tools.execute(react_step.tool_name, react_step.tool_args)
    tool_history.append({tool, args, result})

# fallback: force final call if max_steps exhausted
react_step = llm.reason(sample, tool_history + ["max steps reached"])
return react_step.report or timeout_report
```

`AgentMemory` (`src/agent/memory.py`) is a per-run, in-memory-only store
(never persisted to disk) of findings keyed by `node_id`. Before analysing a
function, the agent asks memory for any findings already recorded on its
callers/callees this run — this lets later functions in the same run benefit
from earlier verdicts without re-deriving them. `AgentState`
(`src/agent/state.py`) holds the reasoning trace and tool-call history for
a single function's analysis (used for debugging/introspection, not
persisted).

### `ToolSet`  (`src/agent/tools.py`)

Tools available to the ReAct agent:

| Tool | What it returns |
|------|-----------------|
| `get_callees(fn)` | Functions `fn` calls — separates internal vs external |
| `get_callers(fn)` | Functions that call `fn` |
| `get_source(fn)` | Source code of `fn` |
| `is_entry_point(fn)` | True if `fn` is an HTTP handler / route |
| `get_node_info(fn)` | Full metadata: callers, callees, taint flags |
| `get_taint_path(fn)` | BFS source → `fn` → sink paths (up to 3); shows full data flow chain |
| `get_graph_summary()` | Aggregate stats (nodes, edges, entry points, taint sources/sinks) — used by the `graph` CLI command, not the agent loop |

### `VulnerabilityReport`  (`src/llm/client.py`)

```python
@dataclass
class VulnerabilityReport:
    function_name: str
    file_path: str
    language: str
    vulnerability_found: bool
    cwe_id: str | None          # normalized to "CWE-NNN"
    affected_lines: list[int]   # clamped to function line range
    severity: str | None        # low | medium | high | critical
    explanation: str
    patch_suggestion: str       # free-text suggestion (analyze-time, unstructured)
    confidence: float           # 0.0 – 1.0
    hallucination_flag: bool
    analysis_mode: str          # call_graph_context | react_loop | react_loop_fallback
    error: str | None
    unified_diff: str = ""              # populated by the `patch` command, not `analyze`
    patch_valid: bool | None = None     # populated by the `patch` command
    patch_error: str | None = None      # populated by the `patch` command
```

The three `patch_*` fields exist on the dataclass so a future run could fold
patch results back into `analysis.json`, but today's `patch` command keeps
them in a separate `<run_id>_patches.json` artifact instead (see Layer 4a) —
findings written by `analyze` always leave these at their defaults.

---

## Layer 4 — Results & Visualization  (`src/results/`)

| File | Role |
|------|------|
| `run_saver.py` | `save_run()`, `save_extraction_results()`, `save_call_graph()`, `save_patches()` — JSON persistence |
| `export_graph.py` | `export_html()` (pyvis interactive), `export_dot()` (Graphviz) |
| `save_graph.py` | `load_call_graph()`, `merge_call_graphs()`, `graph_stats()` |
| `patch_generator.py` | `PatchGenerator` — LLM call → unified diff (Layer 4a) |
| `patch_validator.py` | `PatchValidator` — in-memory patch application + syntax check (Layer 4a) |

### HTML graph color legend

| Color | Node role |
|-------|-----------|
| Steel blue | Entry point / HTTP handler |
| Teal | Taint source (entry point feeding user data into the graph) |
| Red | Taint sink (passes data to dangerous operation) |
| Amber | Infrastructure (DB / IO layer) |
| Orange → Red | Vulnerable (by severity: low→critical) |
| Grey | Regular internal function |

### Output files per run

| File | Description |
|------|-------------|
| `extraction.json` | All extracted functions with code and metadata |
| `call_graph.json` | Full call graph (nodes, edges, taint flags) |
| `call_graph.html` | Interactive visualization (open in browser) |
| `call_graph.dot` | Graphviz DOT source (render with `dot -Tpng`) |
| `call_graph_annotated.html` | HTML with vulnerable nodes highlighted |
| `analysis.json` | Full analysis run (findings, summary, metadata) |
| `<run_id>_patches.json` | Patch proposals for a completed run (see below) — only produced by the `patch` command, not `analyze` |

---

## Layer 4a — Patch Generation & Validation  (Sprint 3)

See [`docs/patching.md`](patching.md) for the full design write-up; summary here for architectural context.

The `patch` CLI command is deliberately **decoupled from `analyze`** — it
takes a completed `analysis.json` as input rather than running inline during
analysis, and re-extracts source (via `CodeExtractor`) rather than trusting
code embedded in the run JSON (the run JSON never stores function bodies).

| Component | Responsibility | Touches disk? |
|-----------|-----------------|----------------|
| `PatchGenerator.generate(code, explanation, cwe_id, ...)` | One LLM call → `PatchResult(unified_diff, error)` | No |
| `PatchValidator.validate(original_code, unified_diff, language)` | Parses diff hunks, applies them to an in-memory copy (exact match, falling back to `difflib.SequenceMatcher` fuzzy matching for line drift), re-parses with tree-sitter, checks `tree.root_node.has_error` | No — works on strings only |
| `save_patches()` | Writes `<run_id>_patches.json` | Yes — but only under `experiments/results/patches/`, never the analyzed project |
| `_write_patch_to_file()` (`src/cli.py`) | Splices `patched_code` into `[start_line, end_line]` of the original file | **Yes — only when `--apply` is passed and the user confirms** |

**Trust model:** `patch` without `--apply` is side-effect-free with respect
to the analyzed project, by construction — the only disk write in that path
is `save_patches()`, and it targets `experiments/results/patches/`. Writing
to the analyzed project requires both the explicit `--apply` flag and an
interactive confirmation (`--yes` opts out of the interactive prompt for
scripted use, but the flag itself is still required).

**Note on context:** an earlier iteration of `PatchGenerator` also accepted
call-graph-derived context (caller/callee source, imports) to try to reduce
hallucinated helper calls and placeholder secrets. It was tested against a
real analysis run and reverted — see `docs/patching.md` for what was tried
and why the evidence didn't support keeping it. `PatchGenerator` currently
takes only `(code, explanation, cwe_id, function_name, language,
patch_suggestion)`.

---

## Layer 5 — Models  (`src/models/`)

| File | Contents |
|------|----------|
| `models.py` | `Language` enum, `EXTENSION_MAP` |
| `code_sample.py` | `CodeSample`, `ImportReference`, `CallSite`, `RouteDefinition` |
| `route_models.py` | Route model types |

---

## Configuration  (`src/config.py`, `experiments/configs/`)

```
experiments/configs/default.yaml
  → load_config()
  → AppConfig {
      llm:       LLMConfig         (provider, model)
      ingestion: IngestionConfig   (max_function_lines, skip_dirs)
      output:    OutputConfig      (folder paths)
      agent:     AgentConfig       (react_mode, max_steps)
    }
```

Three provided configs:

| Config file | Purpose |
|-------------|---------|
| `default.yaml` | Standard runs with `o4-mini`, max_steps=5 |
| `fast_scan.yaml` | Cheap baseline with `gpt-4o-mini` for comparison |
| `react_agent.yaml` | Full ReAct with max_steps=8 for deep analysis |

`patch` reuses the same `AppConfig` (model + `openai_api_key`) via `--config`,
so it shares model choice with whatever config produced the run being patched
unless a different one is passed.

---

## Experiment Layout  (`experiments/`)

```
experiments/
├── configs/
│   ├── default.yaml          ← standard o4-mini config
│   ├── fast_scan.yaml        ← gpt-4o-mini baseline
│   └── react_agent.yaml      ← ReAct with max_steps=8
│
├── runs/                      ← named experiment output (--run-name)
│   └── <run-name>/
│       ├── extraction.json
│       ├── call_graph.json
│       ├── call_graph.html
│       ├── call_graph_annotated.html
│       └── analysis.json
│
├── results/
│   └── patches/               ← `patch` command output (Sprint 3)
│       └── <run_id>_patches.json   — diffs + validity, never applied to source unless --apply
│
├── test_apps/                 ← reference codebases for experiments
│   └── <app-name>/
│       ├── src/
│       └── ground_truth.json
│
├── scripts/                   ← PowerShell experiment runners
│   ├── run_semantic.ps1
│   ├── run_agentic.ps1
│   └── run_all_modes.ps1
└── archive/                   ← old timestamped result files (Sprint 1 runs)
```

---

## Key Design Decisions

**Why tree-sitter over regex?**
Language-aware AST extraction is robust against unusual formatting. Regex call extraction misses chained calls, nested expressions, and destructured assignments. It also gives `patch` a reliable syntax-validity oracle for free — the same parser that extracts functions is reused to check patched code.

**Why three-tier edge resolution (static → import-aware → LLM)?**
Each tier costs more but catches more edges. The persistent edge cache ensures LLM calls are only made once per unique `(caller, raw_call)` pair across all runs.

**Why separate taint source/sink flags instead of full taint propagation?**
Full inter-procedural taint tracking requires a dataflow engine (e.g. Joern). The flag-based approach gives the ReAct agent enough structural information to reason about injection paths without requiring a separate analysis pass.

**Why `o4-mini` over `gpt-4o-mini`?**
Sprint 1 experiments on the auth-service (24 functions) showed `o4-mini` produces ~40% fewer false positives on thin controllers and correctly attributes SQL injection to the query builder rather than the executor in all 14 runs. `gpt-4o-mini` is retained in `fast_scan.yaml` as a baseline for thesis comparison.

**Why `--run-name` instead of timestamped files?**
Named runs make thesis experiments reproducible and comparable. `experiments/runs/auth_agentic/analysis.json` is more meaningful than `analysis_o4_mini_20260518_180806.json`.

**Why is `patch` a separate command instead of a flag on `analyze`?**
Patch generation is a second, independent LLM pass with its own cost and failure modes; decoupling it means re-patching (e.g. after tuning the patch prompt) never requires re-running the full vulnerability analysis. It also keeps the write-boundary explicit: `analyze` never writes to the analyzed project under any flag, and only `patch --apply` can.

**Why hand-rolled diff application instead of a `patch`/`unidiff` dependency?**
The LLM's line numbers in generated diffs can drift slightly from the true source. Locating hunks by content (exact match, then `difflib.SequenceMatcher` fuzzy match) rather than by trusting `@@ -l,s +l,s @@` offsets tolerates that drift without adding a new dependency, and keeps validation entirely in-memory.

**Why was call-graph context tried for `patch`, then reverted?**
The idea (Sprint 2 already showed call graph context reduces false positives in `analyze`, so the same should ground patch generation) was reasonable, but a real test run showed no net improvement — the same valid/invalid count, one regression in the validator's hunk matching, and the two hallucination cases it was meant to fix (an invented import, a hardcoded JWT secret) were still wrong afterward, just differently wrong. Root cause: the hallucinated details lived in config/data files, not in anything reachable via call-graph edges, so the context never had the information needed. Kept out until a context source that actually covers that gap (e.g. full file content or config dumps) is worth the added complexity.

---

## Known Limitations (Sprint 3 state)

| Item | Status |
|------|--------|
| No evaluation framework — no ground-truth precision/recall metrics tying findings *and* patches together | Backlog (unscheduled) |
| Taint propagation is flag-based only — does not track individual variable flows | Backlog |
| No multi-provider support — only OpenAI implemented | Backlog (unscheduled) |
| Functions > `max_function_lines` (200) are silently skipped | Sprint 4 |
| `patch --apply` replaces by line range — stale if the source file changed since the analysis run | Known risk, mitigated by the confirmation prompt |
| Patch-apply success rate not yet measured against the reference dataset (needs a live-API run) | Sprint 3 follow-up, see `docs/patching.md` |
| `PatchGenerator` has no visibility into config/data files or project files outside the call graph — a known gap surfaced by the reverted context-injection experiment | Open; needs a different context source than the call graph |
