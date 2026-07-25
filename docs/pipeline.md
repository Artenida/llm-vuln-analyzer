# Full Pipeline Runbook

End-to-end reference for taking a repository from "never analysed" to
"precision/recall/F1 + cost, ready to defend". Every command is read-only with
respect to the analysed project unless explicitly stated.

## 0. Prerequisites

```bash
cd llm-vuln-analyzer
python -m pytest tests/ -q                 # expect: 83 passed, 7 skipped
```

The 7 skips are integration tests needing the sibling `app-test/` fixture apps;
they are expected to skip on a clean checkout.

API keys — the default key, plus optionally named keys for separate budgets:

```bash
# .env (gitignored) or your shell
OPENAI_API_KEY=sk-...
OPENAI_API_KEY_THESIS=sk-...       # used via --api-key-alias thesis
```

Cost is attributed per alias. `--api-key-alias` selects one; omit for the default.

---

## 1. Scaffold ground truth for a new dataset

`evaluate` only counts a **false positive** when a *clean* function has a ground
truth row — findings with no row are excluded from the confusion matrix
entirely. So precision is uncomputable unless every function is labelled, not
just the vulnerable ones. This command emits all of them.

### Case A — repo with CVE fixing commits (strongest evidence)

Check out the **vulnerable** state (the fix's parent), then point at the fix:

```bash
git -C /path/to/target log --oneline -- <file>       # find the fixing commit
git -C /path/to/target checkout <FIX_SHA>~1          # vulnerable state

python -m src.cli bootstrap-ground-truth \
    --path /path/to/target \
    --dataset my-dataset \
    --fix-commit <FIX_SHA> \
    --fix-commit <ANOTHER_FIX_SHA>
```

Functions overlapping a fix commit's **pre-image** lines are pre-marked
`vulnerable: true` with `REVIEW REQUIRED`. This is a starting point, not ground
truth: fix commits routinely bundle refactoring, tests and changelog edits.

### Case B — app with a documented vulnerability list (e.g. OWASP Juice Shop)

```bash
python -m src.cli bootstrap-ground-truth \
    --path /path/to/juice-shop \
    --dataset juice-shop \
    --description "OWASP Juice Shop — ground truth from the official challenge list"
```

Then mark vulnerable rows by hand from the project's own documentation.

**Output:** `experiments/datasets/<name>/ground_truth.json`. Re-running refuses
to overwrite — `--force` discards curated labels, so only pass it deliberately.

### Curate before evaluating (mandatory)

1. Confirm each `REVIEW REQUIRED` row is genuinely the vulnerability.
2. Set `cwe_id` + `severity` on every vulnerable row. Both are left `null`
   deliberately — guessing them would corrupt the CWE-accuracy metric.
3. Spot-check `UNREVIEWED` rows; any left mislabelled becomes a false positive
   charged against the analyzer.
4. Set `curation_status.reviewed = true`.

Until step 4, `evaluate` prints a loud warning that its numbers are invalid.

---

## 2. Dry run — extraction + call graph

```bash
python -m src.cli analyze --path /path/to/target --dry-run
```

A dry run makes **no LLM calls** — verified against the ledger, not just
intended. It used to: the call graph is built before the dry-run check, and
edge resolution would bill for it (a Juice Shop dry run reached 200 calls /
$0.89 before this was fixed). Edge resolution now runs *cache-only* under
`--dry-run`, so previously-resolved edges still come back for free and a miss
resolves to "unknown" instead of to a purchase.

The consequence to understand: a dry-run graph is a **preview**, not the graph
the real run will use. Ambiguous edges that have never been resolved stay
unresolved, and the run reports how many:

```
1393 ambiguous edge(s) left unresolved — resolving them needs the LLM, which a
dry run does not call. The real run will resolve them (and pay for the ones not
already cached).
```

That number is a useful cost signal before committing: it is the upper bound on
how many edge-resolution calls your first real run will pay for.

**Check the coverage line.** Functions over `max_function_lines` (200, in
`experiments/configs/default.yaml`) cannot be analysed:

```
Extraction summary
  Functions : 312
  Skipped   : 4 function(s) over 200 lines — NOT analysed (98.7% coverage)
```

Anything skipped is outside every metric. Quote that coverage next to any recall
figure, or recall is stated over an unspecified denominator.

---

## 3. Estimate cost before committing

ReAct issues multiple LLM calls per function; a few hundred functions can be an
order of magnitude more expensive than single-pass. Measure on something small
first, then extrapolate:

```bash
python -m src.cli analyze --path ../app-test/auth-service \
    --dataset auth-service --run-name cost-probe --react
python -m src.cli cost --by-run
```

Divide that run's cost by its function count, multiply by the target's count.

---

## 4. Analyse — one run per mode

The mode is the independent variable of the whole thesis, so run each one
separately against the same dataset.

```bash
# Mode B — semantic (call-graph context injected into a single-pass prompt)
python -m src.cli analyze \
    --path /path/to/target --dataset my-dataset --run-name semantic-v1 \
    --api-key-alias thesis

# Mode C — agentic (ReAct: reason → act → observe)
python -m src.cli analyze \
    --path /path/to/target --dataset my-dataset --run-name agentic-v1 \
    --react --api-key-alias thesis
```

Each writes `experiments/datasets/my-dataset/runs/<run-name>/` containing
`extraction.json`, `call_graph.json`, `analysis.json`.

Add `--visualize` for an interactive call graph (`call_graph_annotated.html`)
with findings overlaid — useful as a thesis figure. Forgot it? Don't re-run the
analysis: `graph --graph-file <run>/call_graph.json --results <run>/analysis.json
--output-dir <run>` rebuilds the same file offline, for free.

### Surviving an interrupted run

The analysis loop is sequential, and on a few-hundred-function repo it runs for
a long time. Every completed function is appended to `checkpoint.jsonl` in the
run directory as it finishes, so an interruption — Ctrl-C, a dropped
connection, a closed laptop — costs only the function in flight:

```bash
python -m src.cli analyze --resume --run-name agentic-v1 --dataset my-dataset \
    --path /path/to/target --config <same config> --react     # same flags as the original
```

Ctrl-C is handled rather than fatal: the partial run is saved and the summary
prints the exact `--resume` command to continue it.

Resume refuses to run against a checkpoint written by a *different* run —
different model, mode, source, function count, or a function that has moved to
a different index because the source changed. Silently skipping functions that
were never analysed and calling the result complete would be worse than not
resuming, so a mismatch is a hard error telling you to delete the checkpoint.

A partial run is marked as such in `analysis.json` (`meta.partial_run`,
`meta.functions_analysed` / `functions_total`). **Do not evaluate one as if it
were complete** — every function it never reached scores as a miss, so recall
reads as catastrophic rather than unfinished.

### Capping spend

```bash
python -m src.cli analyze ... --react --budget-usd 5.00
```

Checked between functions, so the final total can exceed the ceiling by at most
one function's cost. It counts *this run's* spend including edge resolution and
anything already done in a resumed run — otherwise a resumed run would get a
fresh budget on every restart. On reaching the ceiling the run stops, saves
what completed, and prints the resume command.

If the model is not in `PRICING`, spend is unknown and the ceiling cannot be
enforced: the run says so once and continues without it. Treating unknown cost
as $0 would silently make the ceiling meaningless.

Per-run output now ends with a phase breakdown:

```
Tokens used    : 118340 (prompt 96210 / completion 22130)
Estimated cost : $0.2043

Cost by phase (run analysis_o4_mini_20260725_...):
  edge_resolution        12 call(s)     4210 tokens  $0.0121
  react_loop            287 call(s)   114130 tokens  $0.1922
```

---

## 5. Evaluate — accuracy and cost together

```bash
python -m src.cli evaluate \
    --results experiments/datasets/my-dataset/runs/semantic-v1/analysis.json \
    --results experiments/datasets/my-dataset/runs/agentic-v1/analysis.json \
    --ground-truth experiments/datasets/my-dataset/ground_truth.json
```

Per run: precision / recall / F1, CWE accuracy on true positives, deduplicated
vulnerability recall, per-CWE breakdown, hallucination rate, and cost per true
positive. With two or more `--results`, a markdown comparison table:

| Run | Mode | Precision | Recall | F1 | CWE Acc (TP) | Unique Recall | Hallucination Rate | Cost (USD) | Cost/TP |
|-----|------|-----------|--------|----|--------------|--------------:|-------------------:|-----------:|--------:|

That table is the core result: **accuracy and cost on the same row, per mode.**

Two things to read carefully:
- `Unmatched findings` — flagged functions with no ground truth row. A large
  count means the ground truth is incomplete, not that the analyzer is wrong.
- `n/a` in a cost column — that run predates cost tracking, or its model is
  missing from `PRICING` in `src/llm/pricing.py`. Never read it as free.

---

## 6. Patches (optional)

```bash
python -m src.cli patch \
    --results experiments/datasets/my-dataset/runs/agentic-v1/analysis.json
```

Generates and validates a unified diff per flagged function and writes
`experiments/datasets/my-dataset/patches/`. **The analysed project is never
modified** unless you pass `--apply` (which prompts; `--yes` to skip).
Patch-generation spend is tracked as its own `patch_generation` phase.

---

## 7. Cost accounting

```bash
python -m src.cli cost                       # all-time: total, by phase, by key
python -m src.cli cost --run-id <run_id>     # one run, all phases
python -m src.cli cost --by-run --limit 20   # per run, most recent first
```

Backed by `experiments/cost_ledger.db` (SQLite, gitignored). One row per real
API call across every phase — `edge_resolution`, `call_graph_context`,
`react_loop`, `react_loop_fallback`, `patch_generation` — and every API key.
Edge-resolution cache hits never appear: they return before reaching the
resolver, so a cached graph can never inflate spend.

---

## What to verify after the recent changes

| Change | How to see it |
|--------|---------------|
| Coverage reporting | `analyze --dry-run` prints a `Skipped` line; `extraction.json` has `coverage` + `skipped_oversized[]` |
| Per-phase cost | `analyze` prints "Cost by phase"; `cost --run-id <id>` shows the same split |
| Patch cost tracked | `cost` lists a `patch_generation` phase after running `patch` |
| Multi-key attribution | Run twice under different `--api-key-alias`, then `cost` — a "By API key" section appears |
| Unknown model → unknown cost | Set an unlisted model in the config; cost reads `unknown`, never `$0.00` |
| Cache hits are free | Run `analyze` twice on the same repo; `edge_resolution` tokens stay flat on the second run |
| Uncurated ground truth guarded | `evaluate` against a fresh skeleton prints the `UNCURATED` warning |
| Ground truth scaffolding | `bootstrap-ground-truth` refuses to overwrite without `--force` |

---

## Remaining gaps

- **No post-cost-tracking run exists on any dataset yet.** Every archived run
  predates it, so `evaluate` correctly reports `n/a` for their cost. The
  cost-vs-accuracy table needs at least one fresh run per mode — this is the
  single highest-value thing left to do.
- **Large functions are reported but not analysed.** Chunking was dropped;
  revisit only if the reported skip count on the real repo proves material.
  (On Juice Shop it is 1 function of 379 — but it is `server.ts::configureApp`,
  which holds the route wiring and five project-marked vulnerable lines.)
