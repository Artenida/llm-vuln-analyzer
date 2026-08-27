"""
Uncertainty around the detection metrics.

`detection_metrics()` returns point estimates computed from 379 rows, 55 of them
vulnerable. A precision of 0.487 over 78 flagged rows and a precision of 0.900
over 10 flagged rows are not comparable as bare numbers: the second is one
retracted finding away from 0.800. Reporting them side by side without an
interval overstates how much separates the two tools.

Three independent sources of uncertainty, kept apart because they are answered
differently:

  1. Sampling — this dataset is one sample of the vulnerabilities that could
     have been planted. Answered by a Wilson score interval on precision and
     recall, and by a bootstrap interval on F1 (which is not a proportion, so
     Wilson does not apply to it).
  2. Labels — 12 juice-shop rows are BORDERLINE_PENDING_AUTHOR, and rows read
     without an exploit are weaker evidence than the four confirmed by running
     one. Answered by `label_sensitivity()`, which rescores with the disputed
     rows flipped rather than guessing which way they go.
  3. Run to run variance — the model is not deterministic. NOT answered here;
     it needs repeated runs, and no interval computed from a single run can
     stand in for them. See docs/evaluation-plan.md.

Nothing here replaces a point estimate. Every function returns a band that gets
published beside the headline figure.
"""
from __future__ import annotations

import math
import random
from typing import Optional

# Fixed so an evaluation report is reproducible: rescoring the same run must
# produce a byte-identical file, which docs/analysis-quality-plan.md relies on
# to tell a real change from noise.
_BOOTSTRAP_SEED = 20260827
_BOOTSTRAP_ITERATIONS = 2000


def wilson_interval(successes: int, total: int, z: float = 1.96) -> Optional[dict]:
    """95% Wilson score interval for a binomial proportion.

    Wilson rather than the textbook normal approximation because the counts here
    are small and the proportions sit near the ends of the range, which is
    exactly where the normal approximation produces bounds below 0 or above 1.
    Returns None when there is nothing to estimate from — an interval over zero
    observations would be [0, 1], which reads as a measurement but is not one.
    """
    if total <= 0:
        return None
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    margin = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return {
        "point": round(p, 4),
        "low": round(max(0.0, centre - margin), 4),
        "high": round(min(1.0, centre + margin), 4),
        "n": total,
        "method": "wilson_95",
    }


def _metrics_from_outcomes(outcomes: list) -> tuple:
    tp = outcomes.count("TP")
    fp = outcomes.count("FP")
    fn = outcomes.count("FN")
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return precision, recall, f1


def bootstrap_metrics(outcomes: list, iterations: int = _BOOTSTRAP_ITERATIONS) -> Optional[dict]:
    """Percentile bootstrap over the scored rows, for all three metrics.

    Resamples the per-row outcomes with replacement and recomputes the metrics
    each time. This is the only one of the three that covers F1, because F1 is a
    ratio of ratios and has no closed-form interval. It also serves as a check on
    the Wilson bounds: where the two disagree materially, the row counts are too
    small to support the claim being made from them.
    """
    if not outcomes:
        return None
    rng = random.Random(_BOOTSTRAP_SEED)
    n = len(outcomes)
    draws = {"precision": [], "recall": [], "f1": []}
    for _ in range(iterations):
        sample = [outcomes[rng.randrange(n)] for _ in range(n)]
        p, r, f = _metrics_from_outcomes(sample)
        draws["precision"].append(p)
        draws["recall"].append(r)
        draws["f1"].append(f)

    point = _metrics_from_outcomes(outcomes)
    out = {"method": "percentile_bootstrap_95", "iterations": iterations,
           "seed": _BOOTSTRAP_SEED, "rows": n}
    for key, value in zip(("precision", "recall", "f1"), point):
        series = sorted(draws[key])
        lo = series[int(0.025 * (iterations - 1))]
        hi = series[int(0.975 * (iterations - 1))]
        out[key] = {"point": round(value, 4), "low": round(lo, 4), "high": round(hi, 4)}
    return out


# Rows whose label is explicitly unsettled. Flipping these is the honest way to
# report a metric that depends on them: not "precision is 0.487" but "precision
# is 0.487, and between X and Y depending on how the 12 undecided rows resolve".
_DISPUTED_STATUSES = {"BORDERLINE_PENDING_AUTHOR"}


def label_sensitivity(instances: list) -> Optional[dict]:
    """Rescore with the disputed rows resolved each way.

    `pessimistic` is the status quo: an undecided row counts as clean, so a
    finding on it is a false positive. `optimistic` treats every undecided row as
    genuinely vulnerable, so the same finding becomes a true positive and an
    unflagged one becomes a missed detection. The truth is somewhere between, and
    the width of the gap is the part of the headline number that rests on labels
    nobody has settled.

    Returns None when the dataset has no disputed rows, which is most of them.
    """
    disputed = [i for i in instances if (i.verification_status or "") in _DISPUTED_STATUSES]
    if not disputed:
        return None

    pessimistic = [i.outcome for i in instances]

    optimistic = []
    for i in instances:
        if (i.verification_status or "") not in _DISPUTED_STATUSES:
            optimistic.append(i.outcome)
        elif i.predicted_vulnerable:
            optimistic.append("TP")     # was FP: the flag was right after all
        else:
            optimistic.append("FN")     # was TN: a real vulnerability went unreported

    result = {
        "disputed_rows": len(disputed),
        "disputed_status": sorted(_DISPUTED_STATUSES),
        "rows": [{"file": i.file, "function_name": i.function_name,
                  "outcome_if_clean": i.outcome,
                  "outcome_if_vulnerable": "TP" if i.predicted_vulnerable else "FN"}
                 for i in disputed],
    }
    for name, outcomes in (("pessimistic", pessimistic), ("optimistic", optimistic)):
        p, r, f = _metrics_from_outcomes(outcomes)
        result[name] = {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}
    return result


def evidence_stratified_recall(instances: list) -> Optional[dict]:
    """Recall computed separately per evidence tier of the vulnerable rows.

    The point of this split is that the tiers do not depend on the same person.
    A juice-shop row labelled from the project's own `vuln-code-snippet` markers
    is an external claim; one confirmed by running an exploit is a demonstrated
    fact; one established by reading alone is this author's judgement. Recall
    over the first two tiers is a number that survives an objection to the third,
    so it is worth reporting on its own rather than only in aggregate.
    """
    vulnerable = [i for i in instances if i.gt_vulnerable]
    if not vulnerable:
        return None
    tiers: dict = {}
    for i in vulnerable:
        # UNSTAMPED, not an assumed provenance. juice-shop's 47 unstamped
        # vulnerable rows came from the project's own markers, but that is true
        # of this dataset and not of the four written for this work, so the
        # tier has to be recorded per row rather than inferred here.
        tier = i.verification_status or "UNSTAMPED"
        row = tiers.setdefault(tier, {"detected": 0, "total": 0})
        row["total"] += 1
        if i.outcome == "TP":
            row["detected"] += 1
    for tier, row in tiers.items():
        row["recall"] = round(row["detected"] / row["total"], 4) if row["total"] else 0.0
        row["interval"] = wilson_interval(row["detected"], row["total"])
    return tiers
