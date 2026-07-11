"""
Automated evaluation harness.

Matches a completed analysis run (experiments/runs/*/analysis.json) against a
ground truth dataset (experiments/ground_truth/*.json) and computes precision/
recall/F1 — replacing the manual counting done by hand in docs/business-logic.md
and the Sprint 1 writeups.

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


def _score_instance(gt: GroundTruthEntry, finding: Optional[dict]) -> InstanceVerdict:
    if finding is None:
        predicted_vulnerable: Optional[bool] = None
        predicted_cwe = None
        analyzed = False
        outcome = "FN" if gt.vulnerable else "TN"
        cwe_correct = None
        hallucination = False
    else:
        predicted_vulnerable = bool(finding.get("vulnerability_found"))
        predicted_cwe = finding.get("cwe_id")
        analyzed = True
        hallucination = bool(finding.get("hallucination_flag"))

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

    # ── aggregate metrics ────────────────────────────────────────────────────

    def detection_metrics(self) -> ConfusionMetrics:
        """Instance-level: was the function correctly flagged vulnerable or not, regardless of CWE."""
        tp = sum(1 for i in self.instances if i.outcome == "TP")
        fp = sum(1 for i in self.instances if i.outcome == "FP")
        fn = sum(1 for i in self.instances if i.outcome == "FN")
        tn = sum(1 for i in self.instances if i.outcome == "TN")
        return ConfusionMetrics(tp, fp, fn, tn)

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

    def hallucination_rate(self) -> float:
        flagged = [i for i in self.instances if i.outcome in ("TP", "FP")]
        if not flagged:
            return 0.0
        return sum(1 for i in flagged if i.hallucination_flag) / len(flagged)

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
            "cwe_accuracy_on_true_positives": round(self.cwe_accuracy(), 4),
            "unique_vulnerability_recall": self.unique_recall(gt),
            "cwe_breakdown": self.cwe_breakdown(gt),
            "hallucination_rate_on_flagged": round(self.hallucination_rate(), 4),
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

    for entry in gt.entries:
        candidates = finding_index.get(entry.function_name, [])
        finding, ambiguous = _match_finding(entry, candidates)
        if ambiguous:
            unresolved_findings.append({
                "function_name": entry.function_name,
                "expected_file": entry.file,
                "candidate_files": [c.get("file_path") for c in candidates],
            })
        instances.append(_score_instance(entry, finding))

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

    report = EvaluationReport(
        run_id=run_data.get("run_id", analysis_path.stem),
        dataset=gt.dataset,
        analysis_mode=analysis_mode,
        model=run_data.get("model"),
        source_path=run_data.get("source_path"),
        instances=instances,
        unmatched_findings=unmatched_findings,
        unresolved_findings=unresolved_findings,
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


def comparison_table(reports_and_gt: list) -> str:
    """Markdown table comparing multiple runs (e.g. semantic vs agentic mode) against
    ground truth. `reports_and_gt` is a list of (EvaluationReport, GroundTruthDataset)."""
    header = (
        "| Run | Mode | Precision | Recall | F1 | CWE Acc (TP) | Unique Recall | Hallucination Rate |\n"
        "|-----|------|-----------|--------|----|--------------|--------------:|--------------------:|"
    )
    rows = [header]
    for report, gt in reports_and_gt:
        m = report.detection_metrics()
        ur = report.unique_recall(gt)
        rows.append(
            f"| {report.run_id} | {report.analysis_mode or '?'} "
            f"| {m.precision:.2f} | {m.recall:.2f} | {m.f1:.2f} "
            f"| {report.cwe_accuracy():.2f} | {ur['detected']}/{ur['planted']} "
            f"| {report.hallucination_rate():.2f} |"
        )
    return "\n".join(rows)
