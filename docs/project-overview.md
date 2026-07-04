# LLM-Vuln-Analyzer — Project Overview

## What It Is

A CLI research tool that uses the OpenAI API to detect security vulnerabilities in source code. Given a file, directory, or inline snippet, it extracts every function, builds a call graph with taint flow annotations, then sends each function to an LLM for security analysis. Built as an MSc project to compare two analysis modes (semantic and agentic) on a structured evaluation dataset.

## What Problems It Solves

Static analysis tools (Bandit, ESLint, Semgrep) find pattern matches but lack semantic understanding. LLMs can reason about data flow and intent — but naively asking "is this vulnerable?" per function causes **callee bleed** (flagging a thin controller because a service it calls is vulnerable). This project addresses that with a hybrid approach:

1. **Call graph context** — surround each function with its callers and callees before analysis.
2. **Taint tracking** — automatically detect taint sources (HTTP handlers) and sinks (SQL/shell/eval calls) and expose the full source→sink path to the agent.
3. **ReAct loop** — let the LLM actively query the graph before making a verdict, using tools like `get_taint_path` to trace injection flows.

## Supported Languages

| Language | Extensions |
|----------|-----------|
| Python | `.py` |
| JavaScript / TypeScript | `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs` |
| C | `.c`, `.h` |
| C++ | `.cpp`, `.hpp`, `.cc` |

## Two Analysis Modes (Thesis Taxonomy)

| Mode | CLI flags | `analysis_mode` tag | Description |
|------|-----------|---------------------|-------------|
| **Semantic** | _(none)_ | `call_graph_context` | Call graph always built; callers + callees + taint flags injected into prompt |
| **Agentic** | `--react` | `react_loop` | Agent queries graph iteratively using tools before verdict |

---

## Setup

```powershell
pip install -r requirements.txt

# Copy env file and add your OpenAI API key
copy .env.example .env
# Edit .env: OPENAI_API_KEY=sk-...
```

---

## Command Reference

### `analyze` — Run vulnerability analysis

```powershell
# ── Basic ──────────────────────────────────────────────────────────────────
# Semantic (call graph context injected into prompt — default)
python -m src.cli analyze --path path/to/project

# Agentic ReAct loop (most accurate)
python -m src.cli analyze --path path/to/project --react

# Inline snippet
python -m src.cli analyze --snippet "def login(u,p): db.execute('SELECT...' + u)" --language python

# ── Named experiments (saves to experiments/runs/<name>/) ──────────────────
python -m src.cli analyze --path path/to/app --run-name auth_semantic
python -m src.cli analyze --path path/to/app --react --run-name auth_agentic

# ── With visualization ─────────────────────────────────────────────────────
# Generates call_graph.html + call_graph_annotated.html (with findings overlaid)
python -m src.cli analyze --path path/to/app --react --visualize --run-name auth_agentic

# ── With custom config (model / steps / line limit) ────────────────────────
python -m src.cli analyze --path path/to/app --react --config experiments/configs/react_agent.yaml

# ── Dry run (build graph only, no LLM calls) ──────────────────────────────
python -m src.cli analyze --path path/to/app --build-context --dry-run
```

**Key flags:**

| Flag | Description |
|------|-------------|
| `--path / -p` | File or directory to analyse |
| `--snippet / -s` | Inline code string (requires `--language`) |
| `--language / -l` | Language for snippet: `python`, `javascript`, `c`, `cpp` |
| `--react` | Use ReAct agent loop instead of single-pass semantic |
| `--visualize / -v` | Export interactive HTML + DOT call graph |
| `--run-name / -n` | Named experiment → outputs go to `experiments/runs/<name>/` |
| `--config / -c` | Path to YAML config file |
| `--dry-run` | Build call graph only, skip LLM calls |

---

### `graph` — Build and visualize a call graph

```powershell
# Build graph from source and open HTML visualization
python -m src.cli graph --path path/to/project

# Also emit a Graphviz DOT file
python -m src.cli graph --path path/to/project --dot

# Visualize a previously saved call graph (no re-build)
python -m src.cli graph --graph-file experiments/runs/auth_agentic/call_graph.json

# Overlay vulnerability findings from an analysis run
python -m src.cli graph --graph-file experiments/runs/auth_agentic/call_graph.json \
                        --results    experiments/runs/auth_agentic/analysis.json

# Custom output directory
python -m src.cli graph --path path/to/project --output-dir experiments/runs/my_graph
```

---

### `show` — Pretty-print a saved analysis run

```powershell
# Full report
python -m src.cli show experiments/runs/auth_agentic/analysis.json

# Only show functions with vulnerabilities
python -m src.cli show experiments/runs/auth_agentic/analysis.json --vulns-only
```

---

## Viewing the Interactive Call Graph

After any run with `--visualize`, or after `graph`, the HTML file is a **self-contained interactive graph** — no server needed.

**Open it:**
```powershell
# Windows — opens in your default browser
Start-Process experiments/runs/auth_agentic/call_graph.html

# Or just double-click the file in Explorer
# Or drag it into any browser window
```

**What you can do in the browser:**
- **Drag nodes** to rearrange the layout
- **Scroll / pinch** to zoom in and out
- **Click a node** to highlight it and its direct connections
- **Hover over a node** to see: full file path, taint role badge (`[SOURCE]` / `[SINK]` / `[ENTRY]`), caller/callee counts
- Use the **navigation buttons** (top-left corner) to fit the graph to screen

**Color legend (also shown in the bottom-left of the page):**

| Color | Meaning |
|-------|---------|
| Steel blue | HTTP entry point / route handler |
| Teal | Taint source (entry point feeding user data into the graph) |
| Red | Taint sink (node that calls SQL/shell/eval) |
| Orange → Dark red | Vulnerable (colored by severity: low → critical) |
| Amber | Infrastructure (DB / IO layer) |
| Grey | Regular internal function |

---

## Output Files

For a named run `--run-name auth_agentic` all files land in `experiments/runs/auth_agentic/`:

| File | Description |
|------|-------------|
| `extraction.json` | All extracted functions (code, lines, language) |
| `call_graph.json` | Full call graph with taint flags |
| `call_graph.html` | Interactive visualization (open in browser) |
| `call_graph.dot` | Graphviz source — render with `dot -Tpng call_graph.dot -o graph.png` |
| `call_graph_annotated.html` | Same graph with vulnerable nodes highlighted by severity |
| `analysis.json` | Complete analysis run (see schema below) |

**`analysis.json` schema:**
```json
{
  "schema_version": "1.0",
  "run_id": "analysis_o4_mini_20260704_120000",
  "model": "o4-mini",
  "source_path": "...",
  "summary": {
    "total_functions": 24,
    "vulnerabilities_found": 8,
    "clean": 16,
    "errors": 0,
    "hallucinated": 1
  },
  "findings": [
    {
      "function_name": "findByUsername",
      "file_path": "services/authService.js",
      "vulnerability_found": true,
      "cwe_id": "CWE-89",
      "severity": "high",
      "affected_lines": [42, 43],
      "explanation": "...",
      "patch_suggestion": "...",
      "confidence": 0.95,
      "hallucination_flag": false,
      "analysis_mode": "react_loop",
      "error": null
    }
  ]
}
```

---

## Configuration

`experiments/configs/default.yaml` controls model, line limits, output paths, and agent settings.

| Config | Best for |
|--------|----------|
| `default.yaml` | Standard runs (`o4-mini`, max_steps=5) |
| `fast_scan.yaml` | Quick baseline comparison (`gpt-4o-mini`) |
| `react_agent.yaml` | Deep analysis (`o4-mini`, max_steps=8) |

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OPENAI_API_KEY` | Yes | Used for all LLM calls |

Copy `.env.example` to `.env` and fill in your key.

---

## Experiment History (Sprint 1)

14 analysis runs on a reference `auth-service` JavaScript app (24 functions), archived in `experiments/archive/`:

- `gpt-4o-mini` single-pass — high false-positive rate on thin controllers
- `o4-mini` + call graph context — significantly fewer false positives
- `o4-mini` + ReAct loop — best accuracy; correctly attributes SQL injection to `findByUsername` (the query builder) not `execute` (the runner)

All Sprint 2+ experiments use named runs under `experiments/runs/`.
