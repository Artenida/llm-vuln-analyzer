# Analysis quality plan — raising precision and recall on juice-shop

## Status

| Stage | State |
|---|---|
| 0 · Measurement harness + dataset hygiene | **applied** 2026-08-15 |
| 1 · Route & middleware context | **applied** 2026-08-15, code only — not yet re-measured |
| 2 · Evidence gate for flow CWEs | **applied** 2026-08-15, code only — not yet re-measured |
| 3–7 | not started |

Stage 1 is implemented and verified against a `--dry-run` extraction of
juice-shop (111 functions now carry route registrations, 28 of them with a
folded prefix guard). **The paid re-run that would confirm the −12 FP has not
been made**, so every number in this document is still the baseline. Run:

```bash
python -m src.cli analyze -p ../app-test/juice-shop -c experiments/configs/juice_shop.yaml \
  --react --run-name stage1 --dataset juice-shop --budget-usd 5
python -m src.cli evaluate -r experiments/datasets/juice-shop/runs/stage1/analysis.json \
  -g experiments/datasets/juice-shop/ground_truth.json
python experiments/scripts/diff_evals.py \
  experiments/datasets/juice-shop/runs/baseline-frozen/evaluation.json \
  experiments/datasets/juice-shop/evaluations/<new eval>.json
```

Two things were found while implementing and differ from what is written below:

1. **`save_call_graph` duplicated `nodes_to_dict` by hand**, so `route_registrations`
   reached the in-memory graph and the HTML export but was silently dropped from
   the saved `call_graph.json`. Fixed by delegating rather than patching, so the
   two serializers cannot drift again. Worth knowing that this class of bug was
   already latent for every other node field.
2. **The summary derivations moved to `src/evaluation/ground_truth.py`** rather
   than living in `experiments/scripts/`. `experiments/` is gitignored, so a test
   importing from there passes locally and fails on a fresh clone. The script is
   now a thin CLI over the tracked functions.

---

**Baseline being improved on:** run `agentic-v1` (o4-mini, ReAct, 379 functions),
scored against `ground_truth.json` after the 2026-08-11 verification pass:

| | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| agentic-v1 | 40 | 37 | 15 | 287 | **0.519** | **0.727** | **0.606** |

Cost: $1.98 analysis + $6.07 edge resolution = $8.05.

Each stage below is independently applicable and independently measurable. They
are ordered by (expected effect ÷ effort), not by dependency — the only hard
dependency is Stage 0, which is what makes the rest attributable.

---

## Stage map

| Stage | What | Est. effect | Effort | Depends on |
|---|---|---|---|---|
| 0 | Measurement harness + dataset hygiene | none (enables the rest) | S | — |
| 1 | Route & middleware context | **−12 FP, −1 FN** | M | 0 |
| 2 | Evidence gate for flow CWEs | **−8 FP** | S | 0 |
| 3 | Attribution: `attributed_to` / `also_implicates` | **+3 TP, −3 FP, −3 FN** | M | 0 |
| 4 | Taxonomy expansion + rule rewrites | **−4 to −6 FN** | S | 0 |
| 5 | Scope exclusions reported both ways | −5 FP (reported variant) | S | 0 |
| 6 | Oversized-function chunking | coverage 0.997 → 1.000 | M | 1 |
| 7 | Flow-level second pass | targets the 13-row NEITHER bucket | L | 1, 3 |

Projected after stages 1–4: **precision ≈ 0.75, recall ≈ 0.85**. These are
estimates derived by replaying the current findings against the fixed causes,
not predictions of a re-run — Stage 0 exists so each one gets checked.

Mapping to the ranked list in the earlier evaluation: fix 1 → Stage 1 (+6),
fix 2 → Stage 2, fix 3 → Stage 3, fix 4 → Stage 4, fix 5 → Stage 5,
fix 6 → Stage 7.

---

## Stage 0 — Measurement harness and dataset hygiene

Without this, stages 1–7 land as one undifferentiated re-run and no single
change can be credited or falsified.

### 0.1 Freeze the baseline

```bash
cp -r experiments/datasets/juice-shop/runs/agentic-v1 \
      experiments/datasets/juice-shop/runs/baseline-frozen
```

`experiments/` is gitignored, so this copy is the only reference point. Do not
overwrite `agentic-v1` in later stages — use `--run-name stage1`, `stage2`, …

### 0.2 A stage-diff script

New file: `experiments/scripts/diff_evals.py`

Takes two evaluation JSONs and prints, per instance row, the outcome
transitions — not just the aggregate deltas:

```
FP → TN   routes/address.ts::getAddress          (fixed)
TN → FP   routes/foo.ts::bar                     (REGRESSION)
FN → TP   lib/insecurity.ts::verify              (fixed)
```

Aggregate line at the end: `ΔTP +3  ΔFP −12  ΔFN −1  P 0.519→0.664`.

This is what turns "the number went up" into "these twelve rows changed, and
these two regressed". The regression column matters more than the headline: a
prompt change that fixes ten rows and breaks four is a different result from one
that fixes six and breaks none.

### 0.3 Fix the stale summary block

`experiments/datasets/juice-shop/ground_truth.json` → `summary.vulnerable` reads
**47**; the actual count of `vulnerable: true` rows is **55**. The
`by_cwe` block is stale by the same pass (missing CWE-345, and several counts
low). `summary.vulnerable_in_scope` / `vulnerable_out_of_scope` (28/19) should
be 30/25.

The row data is correct and the evaluator reads rows, not the summary — so no
metric is wrong. But the summary is what gets quoted in a write-up, so
regenerate it. Add `experiments/scripts/regen_gt_summary.py` that recomputes the
whole block from `functions[]`, and a test asserting summary == recomputed so it
cannot drift again.

### 0.4 Note on re-run cost

`EdgeCache` (`src/context/edge_cache.py`) is persistent and keyed per
(caller, raw_call), so re-runs cost **≈ $2, not $8** as long as extraction is
unchanged. Stages 1 and 6 change extraction and will partially miss the cache —
budget ~$3–4 for those two, ~$2 for the rest. Use `--budget-usd 5` on every
re-run as a guard.

**Verify:** `python -m src.cli evaluate -r <baseline>/analysis.json -g <gt>` still
reproduces 40/37/15/287 exactly.

---

## Stage 1 — Route and middleware context

**The single largest fix. 12 of 37 FPs (32%) trace to one cause.**

### Evidence

- `server.ts::configureApp` is 514 lines, over `max_function_lines: 200`, so it
  is the one function the extractor skips (`extraction.json.skipped_oversized`).
- It contains all **171** `app.get/post/put/delete/use(...)` registrations.
- Consequence in the built graph: `configureApp` exists only as
  `external::configureApp`, and **103 route-file handlers have zero callers**.
- So `get_callers(getAddressById)` answers *"No callers found — may be an entry
  point"*. The agent cannot see that `security.appendUserId()` overwrites
  `req.body.UserId` from the verified JWT before the handler runs, so it flags
  10 protected handlers for IDOR.
- **CWE-639 is the top predicted class: 20 findings, 12 of them FP** — 10 are
  this cluster. Two more (`allOrders`, `toggleDeliveryStatus`) are behind
  `security.isAccounting()`, also registered in `configureApp`.
- One FN too: `serveMetrics` (CWE-200) is missed because "unauthenticated" is
  only visible at the registration site.

**Chunking `configureApp` is not required for this stage.** `RouteExtractor`
runs on raw file *content* (`_extract_samples` calls it before any function-size
filtering), so the route table can be recovered from `server.ts` whether or not
the enclosing function is analysable.

### 1.1 — Extend the route extractor

File: [route_extractor.py](../src/ingestion/route_extractor.py)

Current pattern only matches `router.(get|post|put|delete)` — Juice Shop uses
`app.*`, so the route table is effectively **empty** for this dataset.

Changes:

1. Match both objects and `use`:
   ```python
   ROUTE_PATTERN = re.compile(
       r'\b(?:app|router)\.(get|post|put|delete|patch|all|use)\s*\(([^;]+?)\)\s*$',
       re.MULTILINE | re.DOTALL,
   )
   ```
   Regex on nested parens is fragile — prefer walking `call_expression` nodes
   from the tree-sitter AST instead, which the parser already produces. Regex is
   acceptable as a first cut; note the limitation in the docstring either way.

2. Preserve **handler order**. The current `args.split(',')` both loses the
   distinction between guards and the terminal handler and breaks on any comma
   inside a call argument (`security.isAuthorized()` is fine, `denyAll(['a','b'])`
   is not). Split on top-level commas only (paren-depth aware).

3. Extend `RouteDefinition` in [code_sample.py](../src/models/code_sample.py):
   ```python
   @dataclass
   class RouteDefinition:
       method: str
       path: str
       handlers: List[str]
       middleware: List[str] = field(default_factory=list)  # all but the last handler
       source_line: Optional[int] = None
       source_file: str = ""
   ```
   `middleware` is the ordered guard chain; `handlers[-1]` is the terminal
   handler. For `app.use(...)` with a path prefix, record it as a
   **prefix guard** (`method="USE"`) — that is how `isAuthorized()` is applied to
   `/rest/basket/:id` in Juice Shop, and it applies to every route under the
   prefix.

**Test:** `tests/test_ingestion.py` — feed a fixture with
`app.get('/api/Addresss/:id', security.isAuthorized(), security.appendUserId(), getAddressById)`
and assert `method="GET"`, `path="/api/Addresss/:id"`,
`middleware=["security.isAuthorized()", "security.appendUserId()"]`,
`handlers[-1]="getAddressById"`. Add a case with a comma inside an argument.

**Checkpoint:** run `--dry-run` on juice-shop and assert the extracted route
count is ≥ 150 (currently ~0).

### 1.2 — Wire routes into the call graph

File: [call_graph.py](../src/context/call_graph.py)

`_apply_route_entry_points` already maps handler names to nodes and sets
`is_entry_point`. Extend it to also record the guard chain on the node:

```python
@dataclass
class CallGraphNode:
    ...
    route_registrations: List[dict] = field(default_factory=list)
    # [{"method","path","middleware":[...],"source_file","source_line"}]
```

Also apply prefix guards: a `USE` registration on `/rest/basket` contributes its
middleware to every route whose path starts with that prefix. Match longest
prefix first, and keep registration order — `app.use` declared after a route
does not guard it in Express, so only fold in `USE` entries whose `source_line`
precedes the route's.

Serialize `route_registrations` in `nodes_to_dict` so it reaches
`call_graph.json` and the UI.

**Test:** `tests/test_context.py` (new) — build a graph from two fixture samples
plus a route list, assert the handler node carries the right `middleware` and
that a prefix `USE` guard is folded into a route beneath it but not into one
declared above it.

### 1.3 — Surface it to the model

Two prompt builders need it, plus one new tool.

**a. New tool** in [tools.py](../src/agent/tools.py):

```python
def get_route_context(self, function_name, file_path=None) -> list[dict]:
    """Route registrations that reach this function, with their guard chain."""
```

Register it in `ReActAgent._execute_tool`
([react_loop.py:168](../src/agent/react_loop.py#L168)) and document it in the
tool list inside `_REACT_SYSTEM`.

**b. Render it unconditionally into the state block**, not only on request —
this is exactly the information the agent does not know it is missing.
[client.py:_REACT_STATE_TEMPLATE](../src/llm/client.py#L228):

```
=== ROUTE CONTEXT ===
This function is registered as an HTTP handler at:
  GET /api/Addresss/:id   (server.ts:412)
    guards, in order: security.isAuthorized(), security.appendUserId()
  (prefix guard from server.ts:399: app.use('/rest/basket/:id', security.isAuthorized()))

A guard that runs BEFORE this handler has already enforced whatever it enforces.
Do not report a missing check that one of these guards performs. If you do not
know what a guard does, call get_source on it before flagging.
```

When there are no registrations, say so explicitly — *"No route registration was
found for this function. It may be internal, or the registration may be in a
file this run could not parse"* — rather than omitting the block. Silence reads
as "not an endpoint"; that ambiguity is what produced this FP cluster.

**c. Same block** in
[cli.py:_build_context_prompt](../src/cli.py#L589) for the non-ReAct path, so
the two modes stay comparable.

**d.** `security.appendUserId` and `security.isAuthorized` live in
`lib/insecurity.ts` and *are* extracted — so once the agent knows to look,
`get_source` already answers. No extra work needed.

### Expected effect

−12 FP (10 `appendUserId` + 2 `isAccounting`), −1 FN (`serveMetrics`).
Precision 0.519 → ≈0.66 with no recall loss.

### Risk

Handing the model a guard list invites the opposite error: trusting a guard that
does not do what its name suggests. `security.isAuthorized()` genuinely does not
check *ownership*, only authentication — the prompt text above says "whatever it
enforces", deliberately, and directs the agent to read the guard's source. Watch
Stage 0's regression column for `TP → FN` transitions on real IDOR rows
(`getMemories`, `getRecycleItem` are the canaries — both are real, both are
unguarded).

---

## Stage 2 — Evidence gate for flow CWEs

**8 of 37 FPs (22%), one uniform cause.**

### Evidence

All 8 CWE-117 predictions are false positives. Every one flags interpolation into
a logger call without asking whether the value is attacker-reachable: challenge
keys (`findChallengeByName`), config-file values (`validateConfig`,
`checkUniqueSpecialOnMemories`, `checkSpecialMemoriesHaveNoUserAssociated`),
`NODE_ENV`, and internal-only callers (`downloadToFile`,
`calculateFixItCheatScore`, `createFeedback`, `createSecurityAnswer`).

The `get_taint_path` tool exists and works. The prompt *suggests* it
("Use this when you suspect an injection or flow-based vuln") but never
**requires** it. Suggestion is not enough at this model size.

### Changes

File: [client.py](../src/llm/client.py) — `_REACT_SYSTEM`, and the mirrored block
in `_build_context_prompt`.

Add a hard gate:

```
EVIDENCE GATE — flow-dependent CWEs (89, 79, 95, 117, 22, 918, 611)
These describe untrusted data reaching a dangerous sink. They require a SOURCE,
not just a sink. Before reporting one you MUST be able to name the source, and
it must be one of:
  (a) a parameter of THIS function, where this function is a route handler
      (see ROUTE CONTEXT above), or
  (b) a request object read directly in this function (req.body/query/params/
      headers/cookies/files), or
  (c) a path returned by get_taint_path(<this function>) that starts at an
      entry point — quote the path in your explanation.
If you cannot name the source, the value is NOT attacker-controlled. A config
value, an environment variable, a hardcoded literal, a database row written only
by the app itself, or a value passed in by an internal caller is not a source.
State that and return clean.

Add to your explanation, for these CWEs only, a line of the form:
  SOURCE: <where the untrusted value enters>
An explanation for one of these CWEs without a SOURCE line is invalid.
```

Enforcement is prompt-level and therefore soft. Add a cheap post-hoc check in
`run_saver.save_run`: if `cwe_id` is in the gated set and the explanation has no
`SOURCE:` line, set `hallucination_flag = True`. That does not suppress the
finding — it makes the failure countable, and `hallucination_rate` (currently
0.0) becomes a live signal instead of a constant.

### Expected effect

−8 FP. Precision alone: 0.519 → 0.579; combined with Stage 1: ≈0.72.

### Measured reach, before the re-run — APPLIED 2026-08-15

Replaying the gate's CWE set over the frozen baseline (no LLM calls; this only
asks which findings the gate would *apply* to):

**It touches 28 of the 77 flagged findings — 17 TP and 13 FP.**

| CWE | TP | FP |
|---|---|---|
| CWE-117 | 0 | **8** |
| CWE-22 | 5 | 2 |
| CWE-79 | 3 | 3 |
| CWE-89 | 3 | 0 |
| CWE-95 | 3 | 0 |
| CWE-611 | 2 | 0 |
| CWE-918 | 1 | 0 |

Three corrections to the estimate above:

1. **The ceiling is −13 FP, not −8.** CWE-117 is the cluster, but CWE-22 and
   CWE-79 contribute five more.
2. **The risk is four times what §Risk claimed.** I named three CWE-22 true
   positives as the canaries; there are in fact **17 true positives inside the
   gate's scope**, spread over seven CWEs. A gate worded too broadly takes them
   with it, and that would cost more recall than the precision it buys.
3. **The separation is structural, which is the encouraging part.** Every one of
   the 13 false positives sits in `data/`, `lib/` or `lib/startup/` — bootstrap,
   config-validation and internal utility code with no request in scope at all.
   Every one of the 17 true positives is in `routes/` (or `lib/xml.ts`,
   `models/user.ts`) and reads `req.*` directly, so it satisfies clause (b)
   without needing a taint path. The gate is asking a question whose answer
   already differs sharply between the two groups.

**Pre-registered canaries — these 17 must not flip to FN:**

```
CWE-611  lib/xml.ts::parseXmlString              CWE-22   routes/keyserver.ts::serveKeyFiles
CWE-79   models/user.ts::set                     CWE-22   routes/logfileserver.ts::serveLogFiles
CWE-95   routes/b2border.ts::b2bOrder            CWE-89   routes/login.ts::login
CWE-22   routes/fileserver.ts::verify            CWE-918  routes/profileimageurlupload.ts::profileImageUrlUpload
CWE-22   routes/fileupload.ts::extractZipBuffer  CWE-22   routes/quarantineserver.ts::serveQuarantineFiles
CWE-611  routes/fileupload.ts::handleXmlUpload   CWE-89   routes/search.ts::searchProducts
CWE-95   routes/showproductreviews.ts::showProductReviews   CWE-89   routes/trackorder.ts::trackOrder
CWE-95   routes/userprofile.ts::getUserProfile   CWE-79   routes/videohandler.ts::promotionVideo
```

Note `models/user.ts::set` appears in both lists — different rows (the CWE-79
email setter is a true positive, the sanitizeLegacy attribution is not).

### Deviation from the plan as written

§Changes said to set `hallucination_flag = True` on a finding that fails the
gate. **Not done, deliberately.** `hallucination_rate` is a reported metric with
an established meaning ("of everything it flagged, how much was fabricated"), and
quietly changing what feeds it would make the baseline and every later run
incomparable — the exact failure Stage 0 exists to prevent.

Instead each finding carries its own field:

- `evidence_gate`: `"satisfied"` | `"missing_source"` | `"not_applicable"`
- `declared_source`: the text of the SOURCE line, for auditing
- run summary: `flow_findings`, `flow_findings_without_source`
- evaluation report: `evidence_gate_breakdown`, giving TP/FP/precision per verdict

That breakdown is the number that decides whether the gate should ever become a
suppression rule. If `missing_source` findings turn out to be overwhelmingly
false positives, an unsubstantiated flow claim is a usable precision signal; if
they are a mix, this stays a reporting field. Nothing is suppressed either way —
dropping findings here would move recall as well as precision and make the
stage's own effect unreadable.

Runs made before the gate existed report an empty breakdown rather than a
re-derived one: scoring the old prompt against a rule it was never given would
be measuring the wrong thing.

### Risk

Over-gating suppresses real flow bugs whose source is one hop away — see the
17 canaries above, which is the real exposure. The CWE-22 true positives
(`serveLogFiles`, `serveKeyFiles`, `serveQuarantineFiles`) all read `req.params`
directly and should satisfy clause (b); if they flip to FN, clause (b) is
mis-worded. Because nothing is suppressed, a first re-run cannot lose recall to
this stage at all — it can only reveal how often the model substantiates its own
flow claims. That is the intended order: measure, then decide about enforcement.

---

## Stage 3 — Attribution: pair the finding instead of moving it

**Converts 3 double-penalties into 3 credits. This is the honest version of the
"AI flags a different function" hypothesis — measured, it is worth 3 rows, not
37.**

### Evidence

Measured against the call graph: 5 of 37 FPs are adjacent to an FN row, and 3 of
15 FNs are adjacent to a flagged FP. The genuine same-bug pairs are exactly
three:

| Flagged (FP) | Ground truth row (FN) | The bug |
|---|---|---|
| `lib/insecurity.ts::hash` | `models/user.ts::set` @75-77 | unsalted MD5 |
| `lib/insecurity.ts::sanitizeLegacy` | `models/user.ts::set` @47-54 | weak sanitizer |
| `lib/insecurity.ts::decode` | `lib/insecurity.ts::discountFromCoupon` | unverified token |

Each is counted **twice** against the tool — once as FP at the sink, once as FN
at the caller. And the cause is the prompt working as written
([client.py:130-133](../src/llm/client.py#L130-L133), "Do NOT flag a
vulnerability because a CALLEE has it"). The model obeyed and said so:

> `securityAnswer.ts::set` — *"any hardcoded key issue is in the hmac function
> itself, not in this caller."*
> `user.ts::set` — *"any weakness lies in the sanitizeLegacy callee, not here."*

The anti-bleed rule is correct and should stay — without it, one bad sink
would light up every one of its callers. The fix is to let a finding *name its
counterpart* rather than choose between them.

### Changes

**a. Report schema.** [client.py](../src/llm/client.py) — add to
`VulnerabilityReport` and to both JSON schemas in the prompts:

```python
attributed_to: Optional[str] = None      # node_id where the defect lives
also_implicates: list[str] = field(default_factory=list)  # node_ids that are unsafe because of it
```

Prompt wording:

```
- When the defect lives in a function OTHER than the target, you still report
  vulnerability_found on the target ONLY if the target's own use of it is unsafe.
  Set "attributed_to" to the node_id where the defective code is, and list in
  "also_implicates" the node_ids that are unsafe as a consequence.
  Example: the target calls a weak sanitizer. The weakness is the sanitizer's;
  the decision to rely on it is the target's. Report it once, with
  attributed_to = the sanitizer and also_implicates = [the target].
  Use node_id form "<file>::<function>". Never list more than 3.
```

**b. Persist** both fields in `run_saver.save_run`.

**c. Evaluator credit.** [evaluator.py](../src/evaluation/evaluator.py) —
in `_assign_findings`, after the existing name+file+line assignment, run a
second pass: a GT row still unmatched may claim a finding whose
`attributed_to` or `also_implicates` resolves to that row's
`(file, function_name)`, provided that finding has not already been claimed.

Record the mechanism on the verdict so it is auditable:

```python
@dataclass
class InstanceVerdict:
    ...
    match_basis: str = "direct"   # "direct" | "attributed_to" | "also_implicates"
```

Report metrics **both ways** — strict (direct only) and attribution-aware — in
`to_dict`. Not a substitute: an attribution-aware number that hides how much of
itself came from indirect credit is not defensible in a write-up. Print both.

**d. Guard against gaming.** Cap `also_implicates` at 3 (enforce at parse time,
truncate with a log line). Without a cap, "implicates everything" is a strictly
winning strategy under this scoring, and the metric stops meaning anything.

### Expected effect

Attribution-aware: +3 TP, −3 FP, −3 FN → precision ≈0.60, recall ≈0.78 on this
stage alone. Strict metric unchanged by construction.

### Risk

This is the stage most likely to be read as marking your own homework. The
mitigations are the ones above — dual reporting, the cap, and `match_basis` on
every row — and the fact that the three pairs were identified from the *existing*
run before the mechanism was built. Report the pre-registered list of three in
the write-up so a reader can check that nothing else crept in.

---

## Stage 4 — Taxonomy expansion and rule rewrites

**8 of 15 FNs are `taxonomy_scope: out_of_scope` — the tool has no label for
them. 2 more are misled by a rule that is actively wrong.**

### Evidence

The ground truth already tags every vulnerable row: **30 in-scope, 25
out-of-scope** for the CWE list in `_REACT_SYSTEM`. Of the 15 FNs, 8 are
out-of-scope, by CWE: 345×2, 200×2, 425×2, 916×1, 776×1.

Two failures are especially clean, because the model saw the defect and had
nowhere to put it:

- `generateCoupon` (CWE-345): *"The function constructs a coupon code … and
  applies a **reversible encoding**. There is no use of hardcoded secrets,
  injection, authorization bypass, or other security-relevant issues."* It
  described the vulnerability and returned clean, because "unkeyed reversible
  encoding used as an integrity token" is not in the list.
- `updateAuthenticatedUsers` (CWE-347): *"uses jwt.verify with the known public
  key … it does not accept unsigned or tampered tokens."* The code calls
  `jwt.verify` **without an `algorithms` option**, so `alg:none` passes. The
  prompt's rule reads *"JWT or token accepted without signature verification
  (jwt.decode vs jwt.verify)"* — the model applied it correctly and got the
  wrong answer. Same for `verify` (`jws.verify` on the pinned `jws@0.2.6`).

### 4.1 — Add the missing CWE classes

[client.py](../src/llm/client.py) `_REACT_SYSTEM` and the mirrored list in
`_build_context_prompt`:

```
CWE-345  An integrity/authenticity token built with a REVERSIBLE, UNKEYED
         encoding (base64, z85, hex, Hashids, a bare checksum) instead of a
         MAC or signature. If an attacker who can read the algorithm can mint a
         valid token, it is CWE-345 — regardless of how obscure the encoding is.
CWE-425  A sensitive file or endpoint reachable by URL alone, with no
         authorization check, relying on the path not being guessed.
CWE-776  User-supplied XML/YAML parsed with entity/anchor expansion enabled and
         no size or expansion limit (billion laughs). A timeout alone does not
         fix it; the memory is allocated before the timeout fires.
CWE-916  A password, security answer, or other guessable secret stored under a
         FAST hash (MD5, SHA-*, HMAC-SHA256) instead of a deliberately slow KDF
         (bcrypt/scrypt/argon2), or without a per-record salt.
CWE-200  A response returns data the caller should not see — another user's
         record, an internal config, a CAPTCHA's own answer, unauthenticated
         metrics or diagnostics.
```

Add matching severity defaults (345 → high, 425 → medium, 776 → medium,
916 → high, 200 → medium).

### 4.2 — Rewrite the CWE-347 rule

Replace the `decode` vs `verify` heuristic:

```
CWE-347  A token is trusted without its signature being properly verified.
         Calling a verify() function is NOT sufficient. It is still CWE-347 if:
         - no algorithm allowlist is pinned (`algorithms: ['RS256']` absent), so
           a forged `alg:none` or an HS256 token signed with the public key is
           accepted;
         - the library version predates the alg-confusion fix (check package.json
           if you can reach it);
         - the result of a decode-without-verify is used for any security
           decision (identity, ownership, role), even if a verify happens elsewhere.
         Reading a token purely for display/logging is not CWE-347.
```

### 4.3 — Kill the "challenge flag means intentional" excuse

A distinct FN pattern, ~2–3 rows:

> `saveLoginIp` — *"The special challenge branch bypass is intentional for testing."*
> `product.ts::set` — *"the raw input path is only active in challenge mode and
> not exposed in production."*

The model excused a reachable code path because a flag guards it. Add:

```
- A code path guarded by a feature flag, challenge flag, or environment check is
  still a code path. Report it as a vulnerability and say in the explanation
  which flag enables it. Do NOT assume a flag is off in production, and do NOT
  treat "this looks deliberate" or "this is for testing" as a reason to return
  clean — a deliberately planted vulnerability is still a vulnerability.
```

### Expected effect

−4 to −6 FN. Recall 0.727 → ≈0.82.

### Risk

Every added CWE is a new way to be wrong; expect some new FPs, especially
CWE-916 (any `crypto.createHash` on anything) and CWE-425 (any `res.sendFile`).
The narrowing clauses above are load-bearing. This stage is the one most likely
to show up as `TN → FP` in the Stage 0 regression column — check it before
keeping the change, and be prepared to drop an individual CWE if it pays for
itself in FPs.

Also worth reporting either way: recall over in-scope rows only is the honest
number for "how good is the analyzer at what it claims to detect" (currently
23/30 = 0.77 vs the headline 0.727), and both should appear in the write-up.

---

## Stage 5 — Scope exclusions, reported both ways

**5 of 37 FPs.**

### Evidence

`verifyPreLoginChallenges`, `verifySecurityAnswerChallenges`,
`serverSideChallenges`, `checkKeys`, `checkCorrectFix` are all Juice Shop's
own **challenge-detection harness**. Their "hardcoded credentials" are the
demo answers the harness compares against — they *are* the challenge, not a
leak. The ground truth documents this exclusion; the analyzer never sees it.
The dataset also carries `excluded_scope: "ctf_integrity"` on 8 further rows.

### Changes

**a. Dataset-side, not analyzer-side.** Do **not** feed an exclusion list into
the prompt — telling the analyzer which files not to flag, on a dataset whose
answer key is derived from those same exclusions, is tuning to the key.

Instead, add to `ground_truth.json` a top-level block:

```json
"scoring_scopes": {
  "harness": {
    "description": "Juice Shop's own challenge-detection code...",
    "files": ["routes/verify.ts", "lib/accuracy.ts", "lib/antiCheat.ts",
              "lib/codingChallenges.ts", "routes/vulnCodeSnippet.ts",
              "routes/vulnCodeFixes.ts", "lib/challengeUtils.ts",
              "routes/checkKeys.ts"]
  }
}
```

**b. Evaluator flag.** `evaluate --exclude-scope harness` filters those rows
*and* the findings on them, and records in the output which scope was excluded
and how many rows it removed. Default is no exclusion.

**c. Report both.** The evaluation JSON gains a `scoped_metrics` block so a
single run yields both numbers without re-scoring:

```json
"detection_metrics": {...},                     // all 379 rows
"scoped_metrics": {"excluding_harness": {...}}  // application code only
```

### Expected effect

−5 FP in the excluded variant (precision +≈0.05 there). The headline number is
unchanged by design.

### Risk

Low, provided both numbers are always published together. The write-up framing
that survives review is: *"on application code, precision is X; including the
app's own test harness, which this dataset excludes from its answer key, it is
Y"* — with both stated, and the exclusion list fixed in advance.

---

## Stage 6 — Oversized-function chunking

**Coverage honesty. Note: this does NOT produce Stage 1's metric gain — Stage 1
gets it from the route table, which needs no chunking.**

### Evidence

`functions_skipped_oversized: 1` — `configureApp`, 514 lines, coverage 0.9974.
Juice Shop's own `vuln-code-snippet` markers put **5 documented vulnerabilities**
inside it (`directoryListing`, `accessLogDisclosure`, `changeProduct`,
`registerAdmin`, `resetPasswordMorty`), all currently outside every metric.
Semgrep found 4 findings there that cannot be scored either way.

### Changes

**a. Chunk rather than drop.** [parser.py](../src/ingestion/parser.py)
`_walk_functions` — when `line_count > max_lines`, instead of only recording a
`SkippedFunction`, split the body at **top-level statement boundaries** within
the function (tree-sitter gives these directly; `configureApp` is a flat
sequence of `app.use(...)` / `app.get(...)` statements, so it splits cleanly).

Emit each chunk as a `FunctionNode` named `configureApp#1`, `#2`, … carrying
**true file-relative** `start_line`/`end_line`, so `affected_lines` clamping in
`run_saver` and line-overlap matching in the evaluator both keep working.

Keep the `SkippedFunction` record as well, marked `chunked: True` — coverage
reporting should say "covered as 3 chunks", not silently claim a whole function.

Add config `ingestion.chunk_oversized: bool = True` so the old behaviour is one
setting away and the two are comparable.

**b. Chunks are not call-graph nodes by default.** A chunk is a prompt unit, not
a semantic function. Wiring `configureApp#2` into the graph as a caller of every
handler in it would be wrong-ish but is arguably better than
`external::configureApp`. Recommendation: keep chunks out of the graph for now
and let Stage 1's `route_registrations` carry the relationship — it is the
accurate representation. Revisit only if Stage 7 needs the edges.

**c. Ground truth must grow.** Chunk findings will land in
`unmatched_findings` (no GT rows exist for them) and therefore score as nothing
at all — neither TP nor FP. Before claiming any metric change from this stage,
add rows for the chunks, anchored on the five Juice Shop markers. That is a
manual curation task with the same standard of evidence as the earlier passes,
and it belongs in `docs/juice-shop-gt-verification.md` as a new round.

### Expected effect

Coverage 0.9974 → 1.000. Metric effect is **unknown until (c) is done** and could
go either way — 5 new vulnerable rows is 5 new chances to miss. State it as a
coverage result, not a precision result.

### Risk

Chunk boundaries can split a guard from what it guards, manufacturing a new
class of FP ("this route has no auth check" when the check is in chunk #1).
Mitigation: prepend to every chunk after the first a one-line header — *"This is
part N of M of `configureApp`; lines 170–340 precede it"* — and include the
route context block from Stage 1.

---

## Stage 7 — Flow-level second pass

**The structural limit. Single-function analysis cannot find these, however good
the prompt gets.**

### Evidence

All six execution-proven vulnerabilities from the verification pass are in the
**NEITHER** bucket — missed by both the LLM agent and Semgrep. The pattern is
consistent:

> `generateCoupon` mints a token with a reversible unkeyed encoding.
> `discountFromCoupon` accepts it with a month-format regex and no MAC.

The analyzer examined **both** functions and called **both** clean — correctly,
at function scope. Neither one is wrong on its own; the pair is. Same shape for
`continueCode`/`restoreProgress` (Hashids), and for the `verify` /
`updateAuthenticatedUsers` alg-confusion pair.

### Changes

A second pass, after the per-function pass, over **groups** rather than
functions. Candidate grouping strategies, cheapest first:

1. **Route cluster** — a route + its middleware chain + its terminal handler +
   every internal function that handler calls at depth ≤ 2. Requires Stage 1.
2. **Producer/consumer pair** — two functions where one *mints* a value
   (`generate*`, `create*`, `sign*`, `encode*`) and another *validates* it
   (`verify*`, `check*`, `decode*`, `from*`) over the same encoding. Cheap to
   detect from the graph plus name heuristics; this is exactly the coupon case.
3. **Model + its writers** — a Sequelize model's setters plus every route that
   writes to it.

Prompt for this pass asks a different question:

```
You are shown a GROUP of functions that participate in one workflow.
Do not repeat per-function defects — those have already been analysed.
Report only defects that exist BETWEEN these functions:
  - a value produced by one and trusted by another without integrity protection
  - a check performed in one path and skipped in another that reaches the same sink
  - an ordering requirement (pay → ship, verify → act) not enforced across the group
  - two functions that disagree about who is responsible for a check, so neither does it
Report each finding against the function where the fix belongs, and list the
others in also_implicates.
```

Findings from this pass carry `analysis_mode: "flow_pass"` so they can be scored
separately and their cost attributed.

### Cost

Roughly +$1–2 per run at o4-mini prices, depending on group count and overlap.
Cap group size (≤ 6 functions, ≤ 800 lines) and deduplicate groups that are
subsets of others.

### Expected effect

Not quantified — this targets the 13-row NEITHER bucket, which no configuration
of the current pipeline has ever hit. Treat it as the experimental stage: even a
negative result ("a flow pass at this model size finds 0 of 13") is a publishable
finding, given that both a mature rule engine and a per-function LLM agent
scored 0 there.

### Risk

Highest-variance stage, and the one most likely to generate a new FP population
with no precedent in the current data. Run it on `auth-service` (small, fully
curated, known planted flow bugs) before juice-shop.

---

## What is deliberately NOT in this plan

**A confidence threshold.** Confidence is degenerate in this run: 47 of 77
flagged findings sit at exactly 0.90, every clean verdict at 0.10 or 0.15.
Sweeping the threshold moves F1 from 0.606 (t≤0.7) to 0.627 (t=0.75) and back
down to 0.577 (t=0.9) — noise, bought by discarding true positives. Precision has
to come from required evidence (Stages 1–2), not from self-reported certainty.
Worth one paragraph in the write-up as a negative result: *asking an LLM how sure
it is produced no usable signal at this model size.*

**Edge-resolution spend.** $6.07 of the $8.05 run cost buys a graph that still
leaves 103 handlers caller-less. Stage 1 fixes the handlers by another route
entirely, at which point the LLM edge resolver should be re-examined — static
resolution plus the persistent cache may be nearly as good for a fraction of the
cost. Testing that needs an `--offline-edges` flag on `analyze`; today
`offline_edges` is hardwired to `dry_run` ([cli.py:281](../src/cli.py#L281)), so
there is no way to run a real analysis on a statically-resolved graph. That is a
cost-efficiency experiment, not a quality fix, so it is out of scope here; it
deserves its own measurement against the same baseline.

---

## Suggested order of work

1. **Stage 0** — half a day, unblocks attribution of everything else.
2. **Stage 2** — smallest diff with a real effect; a good end-to-end test of the
   Stage 0 harness.
3. **Stage 1** — the big one. Do it in the three sub-steps, checking the route
   count after 1.1 before touching the prompt.
4. **Stage 4** — prompt-only, but the most likely to regress; the harness is
   proven by then.
5. **Stage 3** — touches the evaluator, so do it once the analyzer side is
   stable and the run is worth re-scoring.
6. **Stage 5** — mechanical.
7. **Stages 6 and 7** — separate pieces of work; 6 needs curation, 7 needs an
   experiment design.

Re-run and re-score after each. Expect ~$2–4 per re-run with a warm edge cache.
