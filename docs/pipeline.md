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

## 2. Dry run — extraction + call graph, no LLM spend

```bash
python -m src.cli analyze --path /path/to/target --dry-run
```

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
with findings overlaid — useful as a thesis figure.

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
- **No budget ceiling.** `--budget-usd` needs checkpoint/resume to save a
  partial run cleanly, which does not exist yet.
