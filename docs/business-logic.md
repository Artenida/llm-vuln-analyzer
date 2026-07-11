# Business Logic & Authorization Analysis (Sprint 4)

## Goal

Detect vulnerabilities that are invisible to syntactic/CWE-pattern matching because the code is syntactically fine but violates an application-level invariant — who is allowed to touch which resource, in what order, with what data. This is scoped **only** to the agentic (`--react`) mode: these bugs need the agent to actively check callers/callees/authorization state across the call graph before answering, which the semantic single-pass mode (`call_graph_context`) has no mechanism to do.

No new tools, no new `ToolSet` methods, no `VulnerabilityReport` schema changes, and no changes to `_ANALYSIS_SYSTEM` (single-pass mode). Everything below is confined to `_REACT_SYSTEM` in `src/llm/client.py`.

## CWE Taxonomy Added

| CWE | Name | What it looks like |
|-----|------|---------------------|
| CWE-639 | Broken object-level authorization (IDOR) | A resource is fetched/mutated by a client-supplied id with no check that it belongs to the requesting user |
| CWE-862 | Missing function-level authorization | A privileged action (refund, delete, role change) runs with no check of the caller's role anywhere in it |
| CWE-841 | Improper enforcement of behavioral workflow | A required prior step (e.g. payment) isn't checked before a later one (e.g. shipping) |
| CWE-915 | Mass assignment | An entire client-supplied object is merged into a stored record instead of only the user-editable fields |
| CWE-362 | Race condition on business state | A "used"/"locked" flag is checked, work happens, then the flag is written — a TOCTOU window for double-redemption |

Severity defaults: CWE-639/862 → high (same tier as CWE-89/347/798); CWE-841/915/362 → medium.

## The Attribution Rule

The single most important addition, found through evaluation (see below) rather than designed upfront: business-logic CWEs need the **same caller/callee attribution discipline** the prompt already enforces for SQL injection ("flag the query builder, not the `db.execute()` wrapper"). A low-level repository/data-access function (`findById`, `save`, an ORM call) that just does what its caller told it to is not where CWE-639/862 belong — the authorization decision belongs to the caller that decided *which* id to fetch and *whether* the requester may touch it. The checklist in `_REACT_SYSTEM` states this explicitly and tells the agent to use `get_callers` + `get_source` to find that decision point instead.

## Ground Truth Dataset

`experiments/ground_truth/orders-service.json` — a Node.js order-management service (`../app-test/orders-service/`, sibling to this repo, same convention as `auth-service`/`billing-service`) with 5 intentionally planted business-logic bugs across 27 functions: `getOrderById` (CWE-639), `updateOrder` (CWE-915), `shipOrder` (CWE-841), `refundOrder` (CWE-862), `redeemCoupon` (CWE-362), all in the service layer, with thin clean controllers and a fixture auth middleware (`identifyUser`) that looks up role server-side rather than testing token verification again (already covered by `auth-service`/CWE-347).

## Evaluation — 3 Rounds

**Round 1** (initial prompt, initial fixture): all 5 planted bugs found with correct CWE/severity. Two extra findings, both real signal, not noise:
- `applyCoupon` (controller, CWE-639) — turned out to be a genuine 6th bug I hadn't planned: `redeemCoupon` never took a `user` parameter, so it never checked order ownership. The agent found the real gap but attributed it to the thin controller instead of the service function.
- `identifyUser` (CWE-269) — the fixture read `role` directly from an `x-user-role` header, which the model correctly identified as privilege-from-client-input. My ground-truth label ("not a target") was wrong, not the finding.

**Fix (fixture, not prompt):** added `fakeDb.findUserRole(id)` (server-side role lookup, header ignored) and an ownership check + `user` param on `redeemCoupon`.

**Round 2** (same prompt, fixed fixture): the two issues above were gone, but two *new* false positives appeared: `findOrdersByUserId` and `saveOrder` in `database/fakeDb.js` were flagged CWE-639 for having no ownership check — i.e. the repository layer itself, not the caller that should own that decision.

**Fix (prompt):** added the attribution rule above to `_REACT_SYSTEM`.

**Round 3** (final): all 5 planted bugs still found correctly; both repository-layer false positives gone. One residual false positive: the thin `shipOrder` **controller** was also flagged CWE-862 (no role check) alongside the correct service-layer CWE-841 finding — a thin-controller misattribution the existing "don't flag a controller that only delegates" rule didn't catch here, since the controller genuinely sits on a route with no role gate at all. Documented rather than chased further (see `experiments/ground_truth/orders-service.json` notes on `shipOrder`).

**Net result:** 5/5 recall on the planted taxonomy, correct CWE and severity on every one, zero regressions on the 16+ clean thin-controller/repository functions, one known residual false-positive pattern (privileged action reachable via a thin controller with no gate anywhere) left as a documented limitation rather than a fourth prompt-tuning round.

## Known Limitations

- The `identifyUser` fixture's identity itself (`x-user-id`) is still unauthenticated/spoofable by design (out of scope — see `auth-service`/CWE-347). A reviewer (human or model) reading only this function may reasonably flag it; that is expected, not a false positive against this dataset.
- The thin-controller misattribution on `shipOrder` (Round 3) suggests the "don't flag a controller that only delegates" rule needs to also account for "unless the delegate itself performs a privileged action with genuinely no gate anywhere in the chain" — left as a future prompt refinement, not implemented here to avoid over-fitting the prompt to one fixture.
- One sample size (`orders-service`, 27 functions, 5 vulnerable) — same caveat as `auth-service`: enough to demonstrate the approach, not enough for a strong precision/recall claim on its own.

## Exit Criteria (from `docs/sprint-plan.md`)

- [x] `--react` flags IDOR / mass-assignment / workflow-bypass bugs in the new reference app at a precision comparable to Sprint 1's injection-class results (5/5 recall, correct CWE/severity)
- [x] Semantic (`call_graph_context`) mode and `VulnerabilityReport` schema unchanged — all changes confined to `_REACT_SYSTEM`
- [x] `docs/business-logic.md` written documenting the taxonomy, checklist, and evaluation results
