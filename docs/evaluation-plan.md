# Evaluation plan — uncertainty, and a second layer that needs no answer key

## Why

Chapter V currently rests on one thing: 379 rows scored against labels this
author curated, from one run of a non-deterministic system. Three objections
follow, and the current harness answers none of them.

| Objection | Currently answered by | Status |
|---|---|---|
| "0.487 and 0.900 are not that far apart on these counts" | nothing | Stage A |
| "your clean labels are your own opinion" | a caveat in `coverage_note` | Stages B, E |
| "a rerun would give different numbers" | nothing | Stage D |
| "the model may be right by accident" | evidence gate, partially | Stage C |

The response is not to abandon precision and recall. They are required: RQ3
compares two detectors, and there is no way to say which of them was right
without an answer key. The response is to put a band around them, and to add a
second evaluation layer that does not depend on the answer key at all, so that a
successful attack on the labels does not take the whole chapter with it.

| Stage | What it adds | Cost | State |
|---|---|---|---|
| A · Uncertainty bands | intervals on every reported metric | none | **done** |
| B · Provenance stamping | per-row evidence tier on the 47 unstamped rows | none | **done** |
| C · Groundedness layer | label-free scoring of every finding | ~$0 | **done** |
| D · Stability | run-to-run variance | ~$15 | pending |
| E · Second rater | agreement on a sample of clean rows | none | pending |
| F · Reporting | the template Chapter V uses | none | pending |

---

## Stage A · Uncertainty bands (done)

`src/evaluation/intervals.py`, wired into `EvaluationReport.to_dict()`. Three
bands, three different questions, deliberately not merged into one number.

**Sampling.** Wilson score intervals on precision and recall, a percentile
bootstrap (2000 resamples, fixed seed) on all three metrics because F1 is a
ratio of ratios and has no closed form. Rescored on
`runs/juice-shop-backend/analysis.json`:

| | Point | 95% interval |
|---|---|---|
| Precision | 0.487 | 0.380 to 0.596 |
| Recall | 0.691 | 0.560 to 0.797 |
| F1 | 0.571 | 0.464 to 0.663 |

The bootstrap agrees with Wilson to within 0.01, which is the check that the
counts are large enough to support the estimate at all.

The number this changes most is not ours. Semgrep's precision of 0.900 comes
from ten flagged rows, so its interval is **0.596 to 0.982**: one retracted
finding moves it to 0.800. Its recall interval is 0.089 to 0.283, which does not
come close to ours. The honest reading is that Semgrep's precision advantage is
real but weakly measured, while its recall deficit is measured well and is
large. Stating both is stronger than the bare point estimates, because a reader
who works out the interval themselves will otherwise work it out against us.

**Labels.** `label_sensitivity()` rescores with the 12
`BORDERLINE_PENDING_AUTHOR` rows resolved each way rather than guessing:

| | Precision | Recall | F1 |
|---|---|---|---|
| Undecided rows counted clean (status quo) | 0.487 | 0.691 | 0.571 |
| Undecided rows counted vulnerable | 0.551 | 0.642 | 0.593 |

Precision moves 6 points, so "precision is 0.487" should be written as "between
0.487 and 0.551 depending on 12 rows this work did not settle".

**Evidence tier.** `evidence_stratified_recall()` splits recall by how each
vulnerable row's label was established:

At the time Stage A ran, that was two tiers; Stage B split the second one into
three. The current table is under Stage B.

This is the most useful of the three bands for the defence. Every one of the
eight rows whose vulnerability is demonstrated rather than asserted was
detected.

---

## Stage B · Provenance stamping (done)

47 of the 55 vulnerable rows carried no `verification_status`. Their labels come
from `vuln-code-snippet` markers and `data/static/challenges.yml`, which is the
application's own documentation of its own flaws and therefore evidence that
does not depend on this author at all. That was a strength invisible in the data.

`src/evaluation/provenance.py` derives the tier from the checked-out source
rather than asserting it, so the assignment is reproducible and re-runnable if
the commit pin moves. Each stamped row also carries a `verification_reason`
naming the line the tier was read from, so any row can be checked in seconds.

| Tier | Evidence | Rows |
|---|---|---|
| `VERIFIED_VULNERABLE` | read; 4 confirmed by running an exploit | 8 |
| `PROJECT_DOCUMENTED_MARKER` | a `vuln-code-snippet vuln-line` comment marks these exact lines | 7 |
| `PROJECT_DOCUMENTED_CHALLENGE` | the function references a `challenges.<key>` defined in `challenges.yml` | 29 |
| `AUTHOR_READ` | no project source; established by reading alone | 11 |

**44 of the 55 vulnerable labels rest on evidence other than this author's
reading.** Only 11 do not, and those 11 are the authorisation and IDOR rows
Juice Shop does not annotate, which is itself consistent with the thesis
argument: the project marks the injection flaws and leaves the logic flaws
unmarked.

Recall by tier on `juice-shop-backend`:

| Tier | Detected | Recall |
|---|---|---|
| `VERIFIED_VULNERABLE` | 8/8 | **1.000** |
| `PROJECT_DOCUMENTED_MARKER` | 6/7 | 0.857 |
| `PROJECT_DOCUMENTED_CHALLENGE` | 16/29 | 0.552 |
| `AUTHOR_READ` | 8/11 | 0.727 |

Recall is highest on the tiers with the strongest evidence, which is the
opposite of what a labelling bias would produce. Written into
`ground_truth.json` with `ground_truth.backup-20260827-preProvenance.json` kept
beside it; the apply pass touched `verification_status` and
`verification_reason` only, and a field-by-field diff confirms no label moved.

---

## Stage C · The groundedness layer (done)

`src/evaluation/groundedness.py`, exposed as `python -m src.cli groundedness
--run <dir> [--evaluation <file>]`. Five checks, none of which consults the
ground truth and none of which calls a model. They ask whether a finding is
supported by the program it is about, not whether it is correct.

| Check | Question | Applicable | Pass rate |
|---|---|---|---|
| `location` | do `affected_lines` fall inside the function | 109 | 1.000 |
| `line_citations` | do line numbers named in the prose exist in the function | 3 | 1.000 |
| `flow_source` | is a flow CWE reported on code a taint source can reach | 33 | 0.333 |
| `cwe_in_taxonomy` | was the CWE one the prompt actually offered | 109 | 1.000 |
| `named_tokens` | do backticked identifiers appear in the code | 11 | 0.909 |
| `patch_validity` | does the proposed fix apply and re-parse | 109 | 0.780 |

**Groundedness rate: 71 of 109, 0.651.** A third of the findings are wrong about
something mechanically checkable, against a self-reported
`hallucination_rate_on_flagged` of **0.000** on the same 109 findings. That
contrast is the result: the existing hallucination metric reads a flag the model
sets about itself and measures nothing.

Two checks are weak and should be reported as such rather than quietly dropped.
`line_citations` and `named_tokens` apply to 3 and 11 findings because this model
rarely cites lines or quotes identifiers in prose; they are correct but nearly
inert on this run. `location` passes everything because the pipeline already
clamps out-of-range lines, so it confirms an existing control rather than finding
anything. `cwe_in_taxonomy` now passes everything too, but only because it found
a real defect and that defect was fixed — see below. It stays as a regression
guard.

### The filter hypothesis, tested and rejected

The plan predicted that ungrounded findings would be disproportionately false
positives, which would make groundedness a precision filter usable on codebases
with no ground truth. Cross-tabulated against the scored run, that is not what
happens:

| | TP | FP | Precision |
|---|---|---|---|
| Grounded | 29 | 33 | 0.468 |
| Ungrounded | 8 | 7 | **0.533** |

The ungrounded findings are *more* precise, not less, and every subgroup interval
overlaps every other, so the honest reading is that groundedness does not predict
correctness on this run at all. It stands as a hallucination measure and not as a
filter. Reporting this is worth more than dropping it: a negative result on a
stated hypothesis is evidence of a method, and the alternative is a thesis that
only reports the hypotheses that worked.

Adding the patch check narrowed the gap (it was 0.446 against 0.667 on the five
free checks alone) without reversing it, which is the more useful reading:
whether a patch applies is closer to being independent of whether the finding was
right than the other checks are, and it is still not a filter.

### What does predict a false positive

The same cross-tabulation shows the real split, and it is by vulnerability class
rather than by groundedness. Findings on flow CWEs run at **0.82** precision
(14/17) while everything else runs at **0.39**, which matches the evidence gate
breakdown independently. The analyzer's precision problem is concentrated in the
authorisation and business logic classes, which are exactly the classes where it
holds its recall advantage over Semgrep. That belongs in §5.6 as the central
failure analysis, and it is a sharper claim than anything the groundedness rate
supports.

### A taxonomy gap found on the way, since repaired

`check_cwe_in_taxonomy` failed 15 findings, and the cause was not the model. The
prompt in `src/llm/taxonomy.py` offered 24 CWEs. The juice-shop ground truth uses
23, of which **8 were never offered**: CWE-22, CWE-352, CWE-601, CWE-602,
CWE-611, CWE-807, CWE-918 and CWE-1427. Worse, `FLOW_CWES` in
`src/llm/evidence_gate.py` demanded a declared source for CWE-22, CWE-611 and
CWE-918, three classes the prompt did not name, so findings were gated against a
rule the model was never given. That is the Stage 4 drift returning between two
files instead of two prompt strings.

Measured before the repair: **4 of the 17 missed rows** carried one of these
classes (`routes/chat.ts::chat`, `routes/fileServer.ts::verify`,
`routes/order.ts::calculateApplicableDiscount`,
`routes/updateUserProfile.ts::updateUserProfile`), and **9 of the 38 true
positives** were found anyway, with the model supplying a CWE from training
rather than from the list.

Repaired 2026-08-27:

- all 8 classes added to `CWE_TAXONOMY_PROMPT` with narrowing clauses in the
  Stage 4 shape, written from the CWE definitions rather than from the rows that
  exposed the gap, so this is not tuning to the answer key. The prompt now offers
  32 classes;
- `SEVERITY_RULES_PROMPT` extended to cover all of them, and CWE-290, which had
  been listed in the taxonomy with no severity;
- `FLOW_CWES` and `EVIDENCE_GATE_PROMPT` extended with CWE-601 and CWE-1427,
  both genuinely source-to-sink classes;
- `ADDED_IN_TAXONOMY_REPAIR` records the eight so a re-run's new false positives
  can be attributed per class and an individual addition rolled back;
- **`tests/test_taxonomy_consistency.py`** asserts the invariants that would have
  caught this: every gated CWE is offered, every offered CWE has exactly one
  severity, and no severity entry names a class the taxonomy dropped;
- `EvaluationReport.taxonomy_coverage()` reports, on every run and every dataset,
  which ground-truth classes the prompt does not offer, how many rows they cover
  and what recall would be if all were recovered. `evaluate` prints a warning
  when that list is non-empty. It is empty now.

**Recall is unchanged at 0.691 until a run is made.** The repair lifts a ceiling
of 0.764; it does not by itself detect anything. Chapter V must state that the
0.691 figure was measured against a 24-class prompt and that the current prompt
offers 32, so the two are not comparable without a re-run.

### C5 and C6

Both added. `analysis.json` carries an empty `unified_diff`, but the run's
`*_patches.json` holds 109 patch records, so C5 scores for free after all:
**85 of 109 patches apply in memory and re-parse, 0.780**. The 24 failures are
almost all `hunk_context_not_found`, which is the generator emitting a diff whose
context does not match the source it was given.

C6 re-analyses each validated patch to see whether the finding survives it. It is
the only paid check, so it lives in `src/evaluation/patch_recheck.py` rather than
in `groundedness.py` — importing the free module must not make spending possible
— and it is reached only through `--recheck-patches`, which is off by default,
capped by `--max-rechecks` (20), and confirms before calling. It distinguishes
`resolved` from `displaced`, because a patch that closes an injection and opens
an authorisation hole is not a fix and must not be counted as one. **Not run:**
the code path is exercised only by tests with an injected fake client.

---

## Stage D · Stability

Every number in the thesis is n=1 on a non-deterministic system. Three repeat
runs of the identical config on juice-shop, about $5 and 52 minutes each, give:

- the spread of precision, recall and F1 across runs, reported as a range beside
  the sampling interval, since they are different sources of variance;
- a per-finding stability rate: of the findings reported in run 1, how many
  appear in all three. Unstable findings are a precision signal available
  without labels, and they belong with Stage C;
- a defensible answer to the examiner's first question about reproducibility.

This is the best value for money remaining in the project. It should be run
before the RQ1 no-context ablation if the budget only covers one of them, because
without it the ablation cannot distinguish an effect from noise.

---

## Stage E · Second rater

Sample 50 of the 291 `VERIFIED_CLEAN` rows at random, have a second person label
them blind against the same instructions, report raw agreement and Cohen's kappa,
and list every disagreement. No API cost, one afternoon of someone else's time.

This is the only stage that addresses the objection directly rather than working
around it, and it is standard in empirical software engineering. A kappa above
0.8 on a 50-row sample makes the 291 clean labels defensible in a way no amount
of self-review can.

---

## Stage F · Reporting

Section 5.1.3 gains a short subsection stating the three sources of uncertainty
and which stage answers each. Every metric in Chapter V is then written as point
estimate plus band, in one fixed form:

> Precision 0.487 (95% CI 0.380 to 0.596; 0.487 to 0.551 across the 12 unsettled
> rows), recall 0.691 (95% CI 0.560 to 0.797), on 379 rows of which 55 are
> vulnerable.

The comparison table in 5.4.1 gains the interval columns for both tools, which is
where Semgrep's ten-row precision becomes visible.

RQ4 should be re-scoped to reliability across all three axes: groundedness
(Stage C), stability (Stage D) and label agreement (Stage E). As drafted it
bundles classification accuracy with hallucination, and those now belong in
different sections.

---

## Order

A, B and C are done and cost nothing. What remains:

1. **E, the second rater** — no API cost, and it depends on someone else's
   calendar, so it should be started first even though it finishes last.
2. **D, stability** — three repeat runs, about $15. Nothing else in the plan
   needs money, and without it every number in Chapter V is n=1. If the budget
   stretches no further, spend it here rather than on the RQ1 ablation: an
   ablation with no variance estimate cannot separate an effect from noise.
3. **The taxonomy repair** found under Stage C — a one-line change with a
   measurable recall ceiling, worth folding into one of Stage D's three runs
   rather than paying for a run of its own.
4. **F, reporting** — last, once there are numbers to put in it.
