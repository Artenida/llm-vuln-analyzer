# Automated Evaluation (Sprint 5)

## Why

Sprints 1, 3, and 4 all measured precision/recall by hand — reading a completed
run's `findings[]` next to a ground truth dataset and counting matches in prose
(see `docs/business-logic.md`'s "3 Rounds" section). That doesn't scale past a
couple of dozen functions and isn't reproducible: re-running the same run
through the same counting exercise twice can silently drift. This sprint adds
`src/evaluation/` and a CLI `evaluate` command that do that counting
mechanically, against the existing `experiments/datasets/<name>/ground_truth.json`
schema — no changes to the ground truth format, no changes to analysis/report schemas.

## What it does

`python -m src.cli evaluate --results <analysis.json> --ground-truth <dataset.json>`

1. Loads the ground truth dataset (`function_name`, `file`, `vulnerable`,
   `cwe_id`, `severity`, optional `duplicate_of`).
2. For every ground truth row, finds the matching finding in the run's
   `findings[]` by `function_name`, disambiguating by `file_path` suffix when
   the same function name appears in more than one ground truth row (e.g. a
   deliberately duplicated bug, or two unrelated functions that share a name
   across files).
3. Scores each row as TP / FP / FN / TN based on `vulnerable` vs
   `vulnerability_found`, and separately tracks whether the assigned `cwe_id`
   was exactly correct.
4. Aggregates into:
   - **Instance-level detection metrics** — precision/recall/F1 treating every
     ground truth row independently.
   - **CWE accuracy on true positives** — of the functions correctly flagged
     vulnerable, what fraction also got the exact right CWE.
   - **Deduplicated (unique) vulnerability recall** — rows that share a
     `duplicate_of` chain collapse into one logical vulnerability, counted as
     detected if *any* instance was a TP. This is the number reported as
     "5/5 recall" style claims in `docs/business-logic.md`.
   - **Per-CWE breakdown** — planted / detected / correct-CWE counts per CWE
     id, for spotting which vulnerability classes a mode is weak on.
   - **Hallucination rate on flagged findings** — of the TP+FP findings, what
     fraction also carried `hallucination_flag: true`.
5. Saves a full per-instance JSON report to
   `experiments/datasets/<dataset>/evaluations/eval_<run_id>.json` — dataset
   inferred from the ground truth file's `dataset` field, overridable with
   `--output-dir` (never touches the run file, the ground truth file, or the
   analyzed project).
6. If `--results` is passed more than once, prints a markdown comparison table
   across runs (e.g. semantic vs agentic mode, or gpt-4o-mini vs o4-mini) —
   precision/recall/F1/CWE-accuracy/unique-recall/hallucination-rate side by
   side, keyed by each run's `analysis_mode`.

## Matching rules (why file disambiguation matters)

A ground truth dataset can have two rows with the same `function_name` in
different files (`auth-service.json` has `rateLimiter` in
`middleware/rateLimiter.js` and `routes/authRoutes.js`, and `changePassword`
as both a thin controller and a service function). Matching by name alone
would silently pair a row with the wrong finding. The matcher always narrows
candidates by checking whether the finding's `file_path` ends with the ground
truth row's `file` (case-insensitive, slash-normalized). If more than one
same-named finding exists but none of their files match a given row, that row
is left unanalyzed and the ambiguity is reported separately
(`unresolved_findings`) rather than guessed.

Findings whose `function_name` has no ground truth row at all (dataset gap, or
a hallucinated name) are reported separately as `unmatched_findings` and
excluded from the confusion matrix — they're neither a scored TP nor FP,
since there's no ground truth label to check them against.

## Example (real run, `auth-service`, `o4-mini` + ReAct)

```
Instance-level detection (TP=11 FP=0 FN=0 TN=13):
  Precision : 1.000
  Recall    : 1.000
  F1        : 1.000
  CWE accuracy (on TPs) : 0.636
  Hallucination rate (on flagged) : 0.000

Deduplicated vulnerability recall: 10/10 (1.000)

Per-CWE breakdown (planted / detected / correct-CWE):
  CWE-20      1 /  1 /  1
  CWE-208     1 /  1 /  1
  CWE-269     1 /  1 /  1
  CWE-306     1 /  1 /  0
  CWE-347     1 /  1 /  0
  CWE-798     1 /  1 /  0
  CWE-89      4 /  4 /  4
```

This confirms detection was perfect (every planted bug was flagged vulnerable,
no false alarms on the 13 clean functions), but exposes something the earlier
manual write-ups didn't quantify: only 64% of true positives got the *exact*
CWE the dataset planted — the misses are all near-adjacent CWEs (e.g.
`CWE-347` reported as `CWE-287`, `CWE-798` as `CWE-287`), not random noise.
That's a concrete, reproducible number for the thesis rather than "found it
correctly" prose.

Running the same dataset against an archived `gpt-4o-mini` run instead
(`--results <gpt4o-run> --results <o4-mini-run> --ground-truth
auth-service.json`) reproduces the qualitative Sprint 1 finding
("gpt-4o-mini has a higher false-positive rate on thin controllers") as a
concrete number: precision 0.79 vs 1.00, both at recall 1.00.

## What this does not do

- It does not run the LLM. `evaluate` is a pure offline scoring step over
  already-completed `analyze` runs — no API key or cost involved.
- It does not replace the prose write-ups in `docs/business-logic.md` /
  `docs/patching.md` — those explain *why* a false positive happened (the
  attribution-rule story). `evaluate` only produces the numbers; the
  reasoning about prompt changes still belongs in a dataset-specific doc.
- Severity is not currently scored (only `vulnerable` + `cwe_id`). Ground
  truth ordinarily assigns severity deterministically from the CWE, so a CWE
  match already implies a severity match in every dataset seen so far — a
  severity-mismatch case hasn't come up yet, so it wasn't added as a
  dimension to avoid over-building for a case none of the datasets exercise.

## Files

| File | Purpose |
|------|---------|
| `src/evaluation/ground_truth.py` | `GroundTruthEntry`/`GroundTruthDataset` + `load_ground_truth()` |
| `src/evaluation/evaluator.py` | Matching, scoring, `EvaluationReport`, `comparison_table()` |
| `tests/test_evaluation.py` | Synthetic-dataset coverage: TP/FP/FN scoring, duplicate-name disambiguation, dedup recall, unmatched findings, hallucination rate, JSON round-trip, comparison table |
| CLI `evaluate` command (`src/cli.py`) | `--results` (repeatable), `--ground-truth`, `--output-dir` |
