"""
Automated evaluation harness.

Matches a completed analysis run (experiments/datasets/<name>/runs/*/analysis.json)
against a ground truth dataset (experiments/datasets/<name>/ground_truth.json) and
computes precision/recall/F1 — replacing the manual counting done by hand in
docs/business-logic.md and the Sprint 1 writeups.

Two matching granularities, because a ground truth dataset may plant the same
logical bug in more than one file (see auth-service's rateLimiter duplicate):

  - instance-level: every (function, file) row in the ground truth is scored
    independently — this is what "coverage" means.
  - vuln-level (deduplicated): rows that share a `vuln_id` (via `duplicate_of`)
    collapse into one logical vulnerability, counted as detected if ANY of its
    instances was a true positive. This is what "recall" means for the thesis
    numbers (e.g. "5/5 recall" in docs/business-logic.md).
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple

from src.evaluation.ground_truth import GroundTruthDataset, GroundTruthEntry, load_ground_truth
from src.llm import attribution

logger = logging.getLogger(__name__)


def _norm_path(p: str) -> str:
    return p.replace("\\", "/").lower().lstrip("/")


@dataclass
class InstanceVerdict:
    instance_id: str
    function_name: str
    file: str
    gt_vulnerable: bool
    gt_cwe: Optional[str]
    analyzed: bool                      # False if no finding matched this gt row at all
    predicted_vulnerable: Optional[bool]
    predicted_cwe: Optional[str]
    outcome: str                        # "TP" | "FP" | "FN" | "TN"
    cwe_correct: Optional[bool]         # only meaningful when outcome == "TP"
    hallucination_flag: bool = False
    # "satisfied" | "missing_source" | "not_applicable" | None (runs predating
    # the evidence gate). See src/llm/evidence_gate.py.
    evidence_gate: Optional[str] = None
    # Set when a finding reported against ANOTHER function named this row in its
    # `attributed_to` / `also_implicates`. Never changes `outcome`, which stays
    # strict; it feeds the second metric set only.
    attributed_basis: Optional[str] = None
    # Set on a clean row whose own false positive turned out to be the same
    # detection that recovered a genuinely vulnerable row elsewhere.
    attribution_neutralized: bool = False

    @property
    def match_basis(self) -> str:
        return self.attributed_basis or "direct"

    @property
    def attributed_outcome(self) -> str:
        """This row's outcome once cross-function attribution is credited.

        Two adjustments, and only these two:
          - a missed vulnerable row that a finding explicitly named becomes a
            detection (FN -> TP);
          - a false alarm that was in fact that same detection stops counting as
            an independent one (FP -> TN).
        The second only ever fires because the first did, so the only way to
        erase a false positive is to have genuinely found a vulnerability that
        was otherwise missed.
        """
        if self.attributed_basis and self.outcome == "FN":
            return "TP"
        if self.attribution_neutralized and self.outcome == "FP":
            return "TN"
        return self.outcome


def _claim_by_attribution(
    gt: GroundTruthDataset,
    findings: list,
    assignment: dict,
) -> dict:
    """Second pass: let an unmatched vulnerable row claim a finding that named it.

    The prompts tell the model not to flag a function for a defect that lives in
    its callee, and it complies — so the detection is reported against the sink
    while the ground truth labels the caller (or the reverse). Scored naively
    that is one false positive plus one false negative for a bug the tool found.
    A finding that explicitly names this row in `attributed_to` or
    `also_implicates` is the same detection, so it may be claimed here.

    Constraints that keep this honest:
      - only vulnerable rows that were MISSED are eligible, so this can never
        displace or overwrite evidence-based matching;
      - a finding already credited as a detection on its own row cannot be
        claimed again, and each finding may be claimed by one row only, so one
        finding never yields more than one detection;
      - only findings that actually claim a vulnerability count;
      - `attributed_to` (an explicit "the defect is here") outranks
        `also_implicates` (a consequence), and both are recorded on the verdict.

    Returns {row_index: (finding, basis)}.
    """
    # Findings that already earned a true positive where they were filed. Letting
    # one of these be claimed again would count a single detection twice.
    already_claimed = {
        id(f) for i, f in assignment.items()
        if f is not None
        and f.get("vulnerability_found")
        and gt.entries[i].vulnerable
    }
    claims: dict = {}

    def _missed(i: int, entry) -> bool:
        """Vulnerable, and the row's own finding did not flag it."""
        if not entry.vulnerable:
            return False
        direct = assignment.get(i)
        return direct is None or not direct.get("vulnerability_found")

    for basis in ("attributed_to", "also_implicates"):
        for i, entry in enumerate(gt.entries):
            if i in claims or not _missed(i, entry):
                continue
            for finding in findings:
                if id(finding) in already_claimed:
                    continue
                if not finding.get("vulnerability_found"):
                    continue
                raw = finding.get(basis)
                candidates = [raw] if isinstance(raw, str) else list(raw or [])
                if any(
                    attribution.matches_row(c, entry.file, entry.function_name)
                    for c in candidates
                ):
                    claims[i] = (finding, basis)
                    already_claimed.add(id(finding))
                    break

    return claims


def _score_instance(gt: GroundTruthEntry, finding: Optional[dict]) -> InstanceVerdict:
    if finding is None:
        predicted_vulnerable: Optional[bool] = None
        predicted_cwe = None
        analyzed = False
        outcome = "FN" if gt.vulnerable else "TN"
        cwe_correct = None
        hallucination = False
        gate = None
    else:
        predicted_vulnerable = bool(finding.get("vulnerability_found"))
        predicted_cwe = finding.get("cwe_id")
        analyzed = True
        hallucination = bool(finding.get("hallucination_flag"))
        gate = finding.get("evidence_gate")

        if gt.vulnerable and predicted_vulnerable:
            outcome = "TP"
            cwe_correct = (predicted_cwe == gt.cwe_id) if gt.cwe_id else None
        elif gt.vulnerable and not predicted_vulnerable:
            outcome = "FN"
            cwe_correct = None
        elif not gt.vulnerable and predicted_vulnerable:
            outcome = "FP"
            cwe_correct = None
        else:
            outcome = "TN"
            cwe_correct = None

    return InstanceVerdict(
        instance_id=gt.instance_id,
        function_name=gt.function_name,
        file=gt.file,
        gt_vulnerable=gt.vulnerable,
        gt_cwe=gt.cwe_id,
        analyzed=analyzed,
        predicted_vulnerable=predicted_vulnerable,
        predicted_cwe=predicted_cwe,
        outcome=outcome,
        cwe_correct=cwe_correct,
        hallucination_flag=hallucination,
        evidence_gate=gate,
    )


@dataclass
class ConfusionMetrics:
    tp: int
    fp: int
    fn: int
    tn: int

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict:
        return {
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
        }


@dataclass
class CWEBreakdownRow:
    cwe_id: str
    planted: int          # unique (deduplicated) vulnerabilities of this CWE in ground truth
    detected: int          # planted vulns flagged as vulnerable (any CWE assigned)
    cwe_correct: int       # planted vulns flagged as vulnerable AND with the correct CWE

    def to_dict(self) -> dict:
        return {
            "cwe_id": self.cwe_id,
            "planted": self.planted,
            "detected": self.detected,
            "cwe_correct": self.cwe_correct,
        }


@dataclass
class EvaluationReport:
    run_id: str
    dataset: str
    analysis_mode: Optional[str]
    model: Optional[str]
    source_path: Optional[str]
    instances: list                         # list[InstanceVerdict]
    unmatched_findings: list                # findings with no corresponding ground truth row
    unresolved_findings: list               # findings whose function name matched >1 gt row, file couldn't disambiguate
    # Read from the run's summary. None when the run recorded no usage, or ran
    # against a model missing from the pricing table — never a fabricated $0.
    total_cost_usd: Optional[float] = None
    total_tokens: Optional[int] = None

    # ── aggregate metrics ────────────────────────────────────────────────────

    def detection_metrics(self) -> ConfusionMetrics:
        """Instance-level: was the function correctly flagged vulnerable or not, regardless of CWE.

        Strict — a finding counts for a row only if it was reported against that
        row. This stays the headline number.
        """
        tp = sum(1 for i in self.instances if i.outcome == "TP")
        fp = sum(1 for i in self.instances if i.outcome == "FP")
        fn = sum(1 for i in self.instances if i.outcome == "FN")
        tn = sum(1 for i in self.instances if i.outcome == "TN")
        return ConfusionMetrics(tp, fp, fn, tn)

    def attributed_detection_metrics(self) -> ConfusionMetrics:
        """The same, crediting a finding that named this row from another function.

        Reported ALONGSIDE the strict figure, never instead of it. A number that
        includes indirect credit without showing how much of itself came from
        indirect credit is not defensible, so `attribution_summary()` reports the
        rows involved and every verdict carries its own `match_basis`.
        """
        outcomes = [i.attributed_outcome for i in self.instances]
        return ConfusionMetrics(
            outcomes.count("TP"), outcomes.count("FP"),
            outcomes.count("FN"), outcomes.count("TN"),
        )

    def scoped_metrics(self, gt: GroundTruthDataset) -> dict:
        """The same run scored again with each declared scope excluded.

        juice-shop ships its own challenge-detection harness — `routes/verify.ts`,
        `lib/antiCheat.ts` and friends — whose "hardcoded credentials" are the demo
        answers it compares against. They are the challenge, not a leak, and the
        ground truth already excludes them; five false positives land there.

        Reported alongside the full figure, never instead of it. The framing that
        survives review is "on application code precision is X; including the
        app's own test harness, which this dataset excludes from its answer key,
        it is Y" — with both stated and the exclusion list fixed in advance.
        """
        out: dict = {}
        for scope in sorted(gt.scoring_scopes or {}):
            files = gt.scope_files(scope)
            if not files:
                continue
            kept = [
                i for i in self.instances
                if not any(_norm_path(i.file).endswith(f) for f in files)
            ]
            outcomes = [i.outcome for i in kept]
            spec = gt.scoring_scopes[scope]
            out[f"excluding_{scope}"] = {
                "description": spec.get("description", ""),
                "rows_excluded": len(self.instances) - len(kept),
                **ConfusionMetrics(
                    outcomes.count("TP"), outcomes.count("FP"),
                    outcomes.count("FN"), outcomes.count("TN"),
                ).to_dict(),
            }
        return out

    def attribution_summary(self) -> dict:
        """Exactly which rows the attribution-aware metric differs on, and why.

        Empty on runs predating Stage 3, and on runs where the model never
        redirected a finding — in both cases the two metric sets are identical.
        """
        recovered = [i for i in self.instances if i.attributed_basis and i.outcome == "FN"]
        neutralized = [i for i in self.instances if i.attribution_neutralized and i.outcome == "FP"]
        return {
            "rows_recovered": [
                {"file": i.file, "function_name": i.function_name,
                 "gt_cwe": i.gt_cwe, "basis": i.attributed_basis}
                for i in recovered
            ],
            "false_positives_neutralized": [
                {"file": i.file, "function_name": i.function_name}
                for i in neutralized
            ],
            "delta": {
                "tp": len(recovered),
                "fn": -len(recovered),
                "fp": -len(neutralized),
            },
        }

    def cwe_accuracy(self) -> float:
        """Among instance-level true positives, fraction with the exact correct CWE assigned."""
        tps = [i for i in self.instances if i.outcome == "TP" and i.gt_cwe is not None]
        if not tps:
            return 0.0
        correct = sum(1 for i in tps if i.cwe_correct)
        return correct / len(tps)

    def unique_vuln_ids(self, gt: GroundTruthDataset) -> dict:
        """Maps vuln_id -> list of InstanceVerdict for that logical vulnerability."""
        by_instance_id = {gt_entry.instance_id: gt_entry for gt_entry in gt.entries}
        groups: dict = defaultdict(list)
        for inst in self.instances:
            entry = by_instance_id.get(inst.instance_id)
            vuln_id = entry.vuln_id if entry else inst.instance_id
            groups[vuln_id].append(inst)
        return groups

    def unique_recall(self, gt: GroundTruthDataset) -> dict:
        """Deduplicated recall: a planted vuln counts as detected if ANY of its planted
        instances (e.g. the same bug copy-pasted into two files) was a true positive."""
        groups = self.unique_vuln_ids(gt)
        vulnerable_groups = {vid: members for vid, members in groups.items()
                              if any(m.gt_vulnerable for m in members)}
        detected = sum(
            1 for members in vulnerable_groups.values()
            if any(m.outcome == "TP" for m in members)
        )
        total = len(vulnerable_groups)
        return {
            "planted": total,
            "detected": detected,
            "recall": round(detected / total, 4) if total else 0.0,
        }

    def cwe_breakdown(self, gt: GroundTruthDataset) -> list:
        groups = self.unique_vuln_ids(gt)
        by_cwe: dict = defaultdict(lambda: {"planted": 0, "detected": 0, "cwe_correct": 0})

        by_instance_id = {e.instance_id: e for e in gt.entries}
        for vuln_id, members in groups.items():
            if not any(m.gt_vulnerable for m in members):
                continue
            # canonical entry carries the CWE label for this vuln group
            canonical = by_instance_id.get(vuln_id)
            cwe = canonical.cwe_id if canonical else next(
                (m.gt_cwe for m in members if m.gt_cwe), "UNKNOWN"
            )
            cwe = cwe or "UNKNOWN"
            by_cwe[cwe]["planted"] += 1
            if any(m.outcome == "TP" for m in members):
                by_cwe[cwe]["detected"] += 1
            if any(m.outcome == "TP" and m.cwe_correct for m in members):
                by_cwe[cwe]["cwe_correct"] += 1

        return [
            CWEBreakdownRow(cwe_id=cwe, **counts).to_dict()
            for cwe, counts in sorted(by_cwe.items())
        ]

    def evidence_gate_breakdown(self) -> dict:
        """How flagged findings split by evidence-gate verdict, against the truth.

        This is the number that says whether the gate is worth enforcing. If
        `missing_source` findings are overwhelmingly false positives, an
        unsubstantiated flow claim is a usable precision signal and could later
        become a suppression rule. If they are a mix, it is only a reporting
        field and should stay one.

        Empty for runs made before the gate existed — those findings carry no
        verdict, and inventing one for them by re-reading their explanations
        would measure the old prompt against a rule it was never given.
        """
        flagged = [i for i in self.instances if i.outcome in ("TP", "FP")]
        buckets: dict = defaultdict(lambda: {"tp": 0, "fp": 0})
        for inst in flagged:
            if not inst.evidence_gate:
                continue
            buckets[inst.evidence_gate]["tp" if inst.outcome == "TP" else "fp"] += 1

        out = {}
        for verdict, counts in sorted(buckets.items()):
            total = counts["tp"] + counts["fp"]
            out[verdict] = {
                **counts,
                "precision": round(counts["tp"] / total, 4) if total else None,
            }
        return out

    def hallucination_rate(self) -> float:
        flagged = [i for i in self.instances if i.outcome in ("TP", "FP")]
        if not flagged:
            return 0.0
        return sum(1 for i in flagged if i.hallucination_flag) / len(flagged)

    def cost_per_tp(self) -> Optional[float]:
        """$ cost per true positive — None if cost is unknown for this run, or
        there are no true positives to divide by (would be a divide-by-zero,
        not a meaningful $0 rate)."""
        if self.total_cost_usd is None:
            return None
        tp = sum(1 for i in self.instances if i.outcome == "TP")
        if tp == 0:
            return None
        return self.total_cost_usd / tp

    def to_dict(self, gt: GroundTruthDataset) -> dict:
        return {
            "schema_version": "1.0",
            "run_id": self.run_id,
            "dataset": self.dataset,
            "analysis_mode": self.analysis_mode,
            "model": self.model,
            "source_path": self.source_path,
            "generated_at": datetime.now().isoformat(),
            "detection_metrics": self.detection_metrics().to_dict(),
            # Strict is the headline; this is the same run scored with
            # cross-function attribution credited, published beside it so a
            # reader can see exactly how much came from indirect credit.
            "detection_metrics_attribution_aware": self.attributed_detection_metrics().to_dict(),
            "attribution_summary": self.attribution_summary(),
            # Empty unless the dataset declares `scoring_scopes`. Never replaces
            # the headline figure above.
            "scoped_metrics": self.scoped_metrics(gt),
            "cwe_accuracy_on_true_positives": round(self.cwe_accuracy(), 4),
            "unique_vulnerability_recall": self.unique_recall(gt),
            "cwe_breakdown": self.cwe_breakdown(gt),
            "hallucination_rate_on_flagged": round(self.hallucination_rate(), 4),
            "evidence_gate_breakdown": self.evidence_gate_breakdown(),
            "total_cost_usd": self.total_cost_usd,
            "total_tokens": self.total_tokens,
            "cost_per_tp_usd": self.cost_per_tp(),
            "unmatched_findings": self.unmatched_findings,
            "unresolved_findings": self.unresolved_findings,
            "instances": [
                {
                    "instance_id": i.instance_id,
                    "function_name": i.function_name,
                    "file": i.file,
                    "gt_vulnerable": i.gt_vulnerable,
                    "gt_cwe": i.gt_cwe,
                    "analyzed": i.analyzed,
                    "predicted_vulnerable": i.predicted_vulnerable,
                    "predicted_cwe": i.predicted_cwe,
                    "outcome": i.outcome,
                    "cwe_correct": i.cwe_correct,
                    "hallucination_flag": i.hallucination_flag,
                    "evidence_gate": i.evidence_gate,
                    "match_basis": i.match_basis,
                    "attributed_outcome": i.attributed_outcome,
                }
                for i in self.instances
            ],
        }


def _build_finding_index(findings: list) -> dict:
    """function_name -> list of finding dicts, for disambiguation by file."""
    index: dict = defaultdict(list)
    for f in findings:
        name = f.get("function_name")
        if name:
            index[name].append(f)
    return index


def _overlap_score(gt_entry: GroundTruthEntry, finding: dict) -> int:
    """How strongly a finding points at this particular function.

    Used only to break ties between ground-truth rows that share a file and a
    function name. A finding's affected_lines are clamped to its own function's
    range when the run is saved, so lines landing inside this row's source range
    are strong evidence the finding belongs to it.
    """
    if not gt_entry.source_lines:
        return 0
    start, end = gt_entry.source_lines[0], gt_entry.source_lines[-1]
    lines = finding.get("affected_lines") or []
    return sum(1 for line in lines if start <= line <= end)


def _assign_findings(gt: GroundTruthDataset, finding_index: dict) -> dict:
    """Maps ground-truth row index -> the finding that belongs to it (or None).

    Assignment is done per (function_name, file) group rather than row by row,
    because the interesting case is several rows sharing one key: four
    Sequelize setters called `set` in one file. Matching each row
    independently hands the same finding to all four, which counts one
    detection as several true positives *and* several false positives.

    Within a colliding group, findings are matched to rows by line overlap and
    each finding is claimed at most once. Rows and findings that cannot be
    separated by lines fall back to source order, which is the order both were
    produced in.
    """
    assignment: dict = {}
    ambiguous: set = set()

    groups: dict = defaultdict(list)
    for i, entry in enumerate(gt.entries):
        groups[(entry.function_name, _norm_path(entry.file))].append(i)

    for (name, file_suffix), idxs in groups.items():
        candidates = [
            c for c in finding_index.get(name, [])
            if _norm_path(c.get("file_path") or "").endswith(file_suffix)
        ]

        if len(idxs) == 1:
            # No collision — keep the original behaviour exactly, including
            # the "same name in another file entirely" ambiguity signal.
            entry = gt.entries[idxs[0]]
            finding, is_ambiguous = _match_finding(entry, finding_index.get(name, []))
            assignment[idxs[0]] = finding
            if is_ambiguous:
                ambiguous.add(idxs[0])
            continue

        remaining = list(candidates)

        # Strongest line evidence first, so a confident match is not stolen by
        # a weaker one earlier in the list.
        scored = sorted(
            (
                (_overlap_score(gt.entries[i], c), i, ci)
                for i in idxs
                for ci, c in enumerate(remaining)
            ),
            key=lambda t: -t[0],
        )

        taken_rows: set = set()
        taken_findings: set = set()
        for score, row_i, cand_i in scored:
            if score <= 0 or row_i in taken_rows or cand_i in taken_findings:
                continue
            assignment[row_i] = remaining[cand_i]
            taken_rows.add(row_i)
            taken_findings.add(cand_i)

        # Anything the lines could not separate: pair off in source order and
        # record that the verdict was positional rather than evidenced.
        leftover_rows = [i for i in idxs if i not in taken_rows]
        leftover_findings = [c for ci, c in enumerate(remaining) if ci not in taken_findings]
        for row_i, finding in zip(leftover_rows, leftover_findings):
            assignment[row_i] = finding
            ambiguous.add(row_i)
        for row_i in leftover_rows[len(leftover_findings):]:
            assignment[row_i] = None

    return {"assignment": assignment, "ambiguous": ambiguous}


def _match_finding(gt_entry: GroundTruthEntry, candidates: list) -> tuple:
    """Returns (finding_or_None, ambiguous: bool). Always disambiguates by file suffix
    match — never assumes a same-named finding belongs to this row without checking,
    since ground truth datasets can plant the same function name in multiple files
    (e.g. a duplicated rateLimiter bug)."""
    if not candidates:
        return None, False

    target = _norm_path(gt_entry.file)
    matches = [c for c in candidates if _norm_path(c.get("file_path") or "").endswith(target)]
    if matches:
        # multiple findings mapping to the same file is unexpected but deterministic: take the first
        return matches[0], False

    if len(candidates) > 1:
        # several same-named findings exist, but none of their files match this gt row —
        # genuinely ambiguous rather than simply "not analyzed"
        return None, True

    return None, False  # the one candidate belongs to a different file entirely — not analyzed for this row


def evaluate_run(
    analysis_path: str | Path, ground_truth_path: str | Path
) -> Tuple[EvaluationReport, GroundTruthDataset]:
    analysis_path = Path(analysis_path)
    with open(analysis_path, encoding="utf-8") as f:
        run_data = json.load(f)

    gt = load_ground_truth(ground_truth_path)
    findings = run_data.get("findings", [])
    finding_index = _build_finding_index(findings)
    gt_names = {e.function_name for e in gt.entries}

    instances: list = []
    unresolved_findings: list = []

    resolved = _assign_findings(gt, finding_index)
    assignment, ambiguous_rows = resolved["assignment"], resolved["ambiguous"]

    # Runs from before Stage 3 carry neither field, so this is a no-op on them
    # and the frozen baseline stays byte-identical when re-scored.
    attribution_claims = _claim_by_attribution(gt, findings, assignment)

    for i, entry in enumerate(gt.entries):
        finding = assignment.get(i)
        if i in ambiguous_rows:
            unresolved_findings.append({
                "function_name": entry.function_name,
                "expected_file": entry.file,
                "candidate_files": [
                    c.get("file_path") for c in finding_index.get(entry.function_name, [])
                ],
            })

        verdict = _score_instance(entry, finding)

        # The strict verdict stands as the row's own outcome; the attribution
        # claim is recorded beside it and only affects the second metric set.
        # Overwriting `outcome` here would make the headline number silently
        # attribution-aware, which is the thing that would not survive review.
        claim = attribution_claims.get(i)
        if claim is not None:
            verdict.attributed_basis = claim[1]

        instances.append(verdict)

    # Link the two halves of each recovered pair. A finding that recovered a
    # missed vulnerable row is not also an independent false alarm on whichever
    # clean row it was filed against — it is one detection, and was being counted
    # as two errors. Neutralising is deliberately conditional on the recovery
    # having happened, so "implicate a real bug to erase a false positive" only
    # pays if the tool genuinely found a vulnerability nobody else caught.
    claimed_findings = {id(f) for f, _ in attribution_claims.values()}
    for i, inst in enumerate(instances):
        direct = assignment.get(i)
        if direct is not None and id(direct) in claimed_findings and inst.outcome == "FP":
            inst.attribution_neutralized = True

    # Findings whose function name has no ground truth row at all — can't be scored
    # (either the dataset doesn't cover this function, or the LLM hallucinated the name).
    unmatched_findings = [
        {"function_name": f.get("function_name"), "file_path": f.get("file_path"),
         "vulnerability_found": f.get("vulnerability_found"), "cwe_id": f.get("cwe_id")}
        for f in findings
        if f.get("function_name") not in gt_names
    ]

    analysis_modes = {f.get("analysis_mode") for f in findings if f.get("analysis_mode")}
    analysis_mode = next(iter(analysis_modes)) if len(analysis_modes) == 1 else (
        "/".join(sorted(analysis_modes)) if analysis_modes else None
    )

    run_summary = run_data.get("summary", {})

    report = EvaluationReport(
        run_id=run_data.get("run_id", analysis_path.stem),
        dataset=gt.dataset,
        analysis_mode=analysis_mode,
        model=run_data.get("model"),
        source_path=run_data.get("source_path"),
        instances=instances,
        unmatched_findings=unmatched_findings,
        unresolved_findings=unresolved_findings,
        # absent when a run recorded no usage — stays None, not 0
        total_cost_usd=run_summary.get("total_cost_usd"),
        total_tokens=run_summary.get("total_tokens"),
    )
    return report, gt


def save_evaluation_report(
    report: EvaluationReport,
    gt: GroundTruthDataset,
    output_folder: str = "experiments/results/evaluations",
    filename: Optional[str] = None,
) -> Path:
    folder = Path(output_folder)
    folder.mkdir(parents=True, exist_ok=True)
    name = filename or f"eval_{report.run_id}.json"
    out_path = folder / name

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(gt), f, indent=2, ensure_ascii=False)

    logger.info("Evaluation report saved -> %s", out_path)
    return out_path


def save_comparison_report(
    reports_and_gt: list,
    output_folder: str = "experiments/results/evaluations",
    filename: Optional[str] = None,
) -> Path:
    """Persists the cross-run comparison alongside the per-run reports.

    The per-run JSON was already saved; the comparison table was not — it was
    printed once and lost with the terminal scrollback. It is also the single
    output that answers the question the whole mode split exists to answer
    (accuracy and cost, per mode, on one row), so it is the last thing that
    should be ephemeral.

    Written as markdown because that is the form it gets quoted in.
    """
    folder = Path(output_folder)
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = folder / (filename or f"comparison_{stamp}.md")

    dataset = reports_and_gt[0][0].dataset if reports_and_gt else "?"
    gt = reports_and_gt[0][1] if reports_and_gt else None

    lines = [
        f"# Run comparison — {dataset}",
        "",
        f"Generated: {datetime.now().isoformat(timespec='seconds')}",
        "",
    ]

    # A saved table outlives the terminal warning that was printed next to it,
    # so the caveat has to travel with the file or it will be read as a result.
    if gt is not None and gt.needs_curation:
        cs = gt.curation_status
        lines += [
            "> **These numbers are not valid.** The ground truth is an uncurated "
            f"skeleton (`curation_status.reviewed` is false): "
            f"{cs.get('functions_unreviewed', '?')} row(s) default to clean and "
            f"{cs.get('functions_prefilled_vulnerable', '?')} are unconfirmed. "
            "Curate it and re-run before quoting anything here.",
            "",
        ]

    lines += ["## Runs compared", ""]
    for report, _ in reports_and_gt:
        cost = f"${report.total_cost_usd:.4f}" if report.total_cost_usd is not None else "n/a"
        lines.append(
            f"- `{report.run_id}` — mode: {report.analysis_mode or '?'}, "
            f"model: {report.model or '?'}, cost: {cost}"
        )

    lines += ["", "## Results", "", comparison_table(reports_and_gt), ""]

    out_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Comparison report saved -> %s", out_path)
    return out_path


def comparison_table(reports_and_gt: list) -> str:
    """Markdown table comparing multiple runs (e.g. semantic vs agentic mode) against
    ground truth. `reports_and_gt` is a list of (EvaluationReport, GroundTruthDataset)."""
    header = (
        "| Run | Mode | Precision | Recall | F1 | CWE Acc (TP) | Unique Recall | Hallucination Rate | Cost (USD) | Cost/TP |\n"
        "|-----|------|-----------|--------|----|--------------|--------------:|--------------------:|-----------:|--------:|"
    )
    rows = [header]
    for report, gt in reports_and_gt:
        m = report.detection_metrics()
        ur = report.unique_recall(gt)
        cost_str = f"${report.total_cost_usd:.4f}" if report.total_cost_usd is not None else "n/a"
        cost_per_tp = report.cost_per_tp()
        cost_per_tp_str = f"${cost_per_tp:.4f}" if cost_per_tp is not None else "n/a"
        rows.append(
            f"| {report.run_id} | {report.analysis_mode or '?'} "
            f"| {m.precision:.2f} | {m.recall:.2f} | {m.f1:.2f} "
            f"| {report.cwe_accuracy():.2f} | {ur['detected']}/{ur['planted']} "
            f"| {report.hallucination_rate():.2f} | {cost_str} | {cost_per_tp_str} |"
        )
    return "\n".join(rows)
