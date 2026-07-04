# Architecture

> **Current state: Sprint 2 complete.** Sprint 3 (patch generation) and Sprint 4 (metrics) are next.

---

## System Overview

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  CLI  src/cli.py  ─  commands: analyze | graph | show                        │
└────────────┬─────────────────┬─────────────────────────────┬─────────────────┘
             │                 │                             │
     ┌───────▼──────┐  ┌───────▼───────┐           ┌────────▼────────┐
     │  Ingestion   │  │  Call Graph   │           │  LLM / Agent    │
     │  Layer       │  │  Layer        │           │  Layer          │
     └──────────────┘  └───────┬───────┘           └────────┬────────┘
                               │                            │
                       ┌───────▼───────┐           ┌────────▼────────┐
                       │  Results &    │           │  ToolSet        │
                       │  Visualization│           │  (graph tools)  │
                       └───────────────┘           └─────────────────┘
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
```

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
    callers: List[str]       # node_ids that call this function
    callees: List[str]       # node_ids this function calls
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
| `--react` | **Agentic** | `react_loop` | Agent queries the graph iteratively before verdict |

### `LLMClient`  (`src/llm/client.py`)

| Method | Used by | Returns |
|--------|---------|---------|
| `analyze(sample, context_prompt)` | Semantic mode | `VulnerabilityReport` |
| `reason(sample, tool_history)` | Agentic mode (one step) | `ReActStep` |

### ReAct loop  (`src/agent/react_loop.py`)

```
for step in range(max_steps):
    react_step = llm.reason(sample, tool_history)
    if react_step.is_final:
        return react_step.report             # ← normal exit
    result = tools.execute(react_step.tool_name, react_step.tool_args)
    tool_history.append({tool, args, result})

# fallback: force final call if max_steps exhausted
react_step = llm.reason(sample, tool_history + ["max steps reached"])
return react_step.report or timeout_report
```

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

### `VulnerabilityReport`  (`src/llm/client.py`)

```python
@dataclass
class VulnerabilityReport:
    function_name: str
    file_path: str
    language: str
    vulnerability_found: bool
    cwe_id: str | None         # normalized to "CWE-NNN"
    affected_lines: list[int]  # clamped to function line range
    severity: str | None       # low | medium | high | critical
    explanation: str
    patch_suggestion: str      # free-text suggestion (Sprint 3: becomes unified diff)
    confidence: float          # 0.0 – 1.0
    hallucination_flag: bool
    analysis_mode: str         # call_graph_context | react_loop
    error: str | None
```

---

## Layer 4 — Results & Visualization  (`src/results/`)

| File | Role |
|------|------|
| `run_saver.py` | `save_run()`, `save_extraction_results()`, `save_call_graph()` — JSON persistence |
| `export_graph.py` | `export_html()` (pyvis interactive), `export_dot()` (Graphviz) |
| `save_graph.py` | `load_call_graph()`, `merge_call_graphs()`, `graph_stats()` |

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

---

## Experiment Layout  (`experiments/`)

```
experiments/
├── configs/
│   ├── default.yaml          ← standard o4-mini config
│   ├── fast_scan.yaml        ← gpt-4o-mini baseline
│   └── react_agent.yaml      ← ReAct with max_steps=8
│
├── runs/                     ← named experiment output (--run-name)
│   └── <run-name>/
│       ├── extraction.json
│       ├── call_graph.json
│       ├── call_graph.html
│       ├── call_graph_annotated.html
│       └── analysis.json
│
├── test_apps/                ← reference codebases for experiments
│   └── <app-name>/
│       ├── src/
│       └── ground_truth.json
│
├── ground_truth/             ← shared evaluation datasets (Sprint 4)
├── patches/                  ← generated patch files (Sprint 3)
├── scripts/                  ← PowerShell experiment runners
│   ├── run_semantic.ps1
│   ├── run_agentic.ps1
│   └── run_all_modes.ps1
└── archive/                  ← old timestamped result files (Sprint 1 runs)
```

---

## Key Design Decisions

**Why tree-sitter over regex?**
Language-aware AST extraction is robust against unusual formatting. Regex call extraction misses chained calls, nested expressions, and destructured assignments.

**Why three-tier edge resolution (static → import-aware → LLM)?**
Each tier costs more but catches more edges. The persistent edge cache ensures LLM calls are only made once per unique `(caller, raw_call)` pair across all runs.

**Why separate taint source/sink flags instead of full taint propagation?**
Full inter-procedural taint tracking requires a dataflow engine (e.g. Joern). The flag-based approach gives the ReAct agent enough structural information to reason about injection paths without requiring a separate analysis pass.

**Why `o4-mini` over `gpt-4o-mini`?**
Sprint 1 experiments on the auth-service (24 functions) showed `o4-mini` produces ~40% fewer false positives on thin controllers and correctly attributes SQL injection to the query builder rather than the executor in all 14 runs. `gpt-4o-mini` is retained in `fast_scan.yaml` as a baseline for thesis comparison.

**Why `--run-name` instead of timestamped files?**
Named runs make thesis experiments reproducible and comparable. `experiments/runs/auth_agentic/analysis.json` is more meaningful than `analysis_o4_mini_20260518_180806.json`.

---

## Known Limitations (Sprint 2 state)

| Item | Status |
|------|--------|
| `patch_suggestion` is free text — no structured diff or verification | Sprint 3 |
| No evaluation framework — no ground-truth dataset, no precision/recall metrics | Sprint 4 |
| `agent/memory.py` is a partial stub — cross-function memory is recorded but not deeply reused | Sprint 4 |
| Taint propagation is flag-based only — does not track individual variable flows | Backlog |
| No multi-provider support — only OpenAI implemented | Sprint 4 |
| Functions > `max_function_lines` (200) are silently skipped | Sprint 3 |
