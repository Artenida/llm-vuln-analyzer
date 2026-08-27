"""
Does the proposed fix actually remove the finding?

The last groundedness check, and the only one that costs money: re-analyse the
patched code and see whether the same class is still reported. Kept out of
`groundedness.py` deliberately — everything in that module is free and offline,
and a caller should not be able to start spending by importing it.

What a verdict means, and does not:

  resolved      the same CWE is no longer reported on the patched function. The
                fix removed what the model itself could see. It is NOT proof the
                vulnerability is gone: the same model that missed a flaw before
                the patch will miss it after.
  unresolved    the same CWE is still reported. This is the stronger signal of
                the two, because the model is contradicting its own remediation.
  displaced     the function is still flagged, but under a different CWE. Worth
                separating: a fix that closes an injection and opens an
                authorisation hole is not a fix, and lumping it with `resolved`
                would hide that.

Grading a model's output with the same model is circular, which is why this is
never used as a verdict on whether a vulnerability exists. It answers a narrower
question the model is entitled to answer: is your own patch consistent with your
own finding.

Nothing here runs unless a caller passes a client and an explicit budget.
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)

RESOLVED = "resolved"
UNRESOLVED = "unresolved"
DISPLACED = "displaced"
SKIPPED = "skipped"


def recheck_one(finding: dict, patch: Optional[dict], analyze: Callable) -> dict:
    """Re-analyse one patched function.

    `analyze` takes the patched source and returns a report-shaped dict with
    `vulnerability_found` and `cwe_id`. Injected rather than constructed here so
    the caller owns the client, the model choice and the budget, and so this is
    testable without a key.
    """
    if patch is None or patch.get("patch_valid") is not True:
        return {"verdict": SKIPPED, "reason": "no valid patch to re-analyse"}
    patched_code = (patch.get("patched_code") or "").strip()
    if not patched_code:
        return {"verdict": SKIPPED, "reason": "patch record carries no patched code"}

    original_cwe = finding.get("cwe_id")
    try:
        report = analyze(patched_code, finding)
    except Exception as e:                                  # noqa: BLE001
        # A failed re-check is not a passed one. Recording the error keeps a
        # transport failure from being counted as a fix that worked.
        logger.warning("re-check failed for %s: %s", finding.get("function_name"), e)
        return {"verdict": SKIPPED, "reason": f"re-analysis failed: {e}"}

    if not report.get("vulnerability_found"):
        return {"verdict": RESOLVED, "reason": f"{original_cwe} no longer reported",
                "cwe_after": None}
    cwe_after = report.get("cwe_id")
    if cwe_after == original_cwe:
        return {"verdict": UNRESOLVED, "reason": f"{original_cwe} still reported",
                "cwe_after": cwe_after}
    return {"verdict": DISPLACED,
            "reason": f"{original_cwe} gone but {cwe_after} now reported",
            "cwe_after": cwe_after}


def recheck_run(groundedness: dict, patches: dict, analyze: Callable,
                limit: Optional[int] = None) -> dict:
    """Re-check every finding that has a valid patch.

    `limit` caps how many calls are made, because this is one model call per
    patched function and the caller is paying for each one. Findings beyond the
    limit are reported as skipped rather than omitted, so the denominator stays
    honest.
    """
    index = {}
    for row in patches.get("patches", []):
        key = (str(row.get("file_path") or "").replace("\\", "/").lower(),
               row.get("function_name"))
        index.setdefault(key, []).append(row)

    results = []
    spent = 0
    for row in groundedness["rows"]:
        key = (str(row.get("file_path") or "").replace("\\", "/").lower(),
               row.get("function_name"))
        candidates = index.get(key) or []
        patch = candidates[0] if len(candidates) == 1 else None

        if limit is not None and spent >= limit:
            outcome = {"verdict": SKIPPED, "reason": f"call limit of {limit} reached"}
        else:
            outcome = recheck_one(row, patch, analyze)
            if outcome["verdict"] != SKIPPED:
                spent += 1
        results.append({
            "function_name": row.get("function_name"),
            "file_path": row.get("file_path"),
            "cwe_id": row.get("cwe_id"),
            **outcome,
        })

    counts = {v: 0 for v in (RESOLVED, UNRESOLVED, DISPLACED, SKIPPED)}
    for r in results:
        counts[r["verdict"]] += 1
    checked = counts[RESOLVED] + counts[UNRESOLVED] + counts[DISPLACED]
    return {
        "calls_made": spent,
        "counts": counts,
        # Over the findings actually re-checked, not over all of them: a run
        # where most patches were invalid would otherwise report a flattering
        # rate off a handful of rows.
        "resolution_rate": round(counts[RESOLVED] / checked, 4) if checked else None,
        "rows": results,
    }
