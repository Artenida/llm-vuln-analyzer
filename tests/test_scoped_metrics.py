"""Scored-both-ways metrics for dataset-declared scope exclusions.

juice-shop ships its own challenge-detection harness (routes/verify.ts,
lib/antiCheat.ts and friends). Its "hardcoded credentials" are the demo answers
it compares against - they are the challenge, not a leak - and five baseline
false positives land there.

The exclusion is declared in the dataset, not fed to the analyzer. Telling the
analyzer which files not to flag, on a dataset whose answer key derives from
those same exclusions, would be tuning to the key. And the scoped figure is
always published beside the full one, never in place of it.

Run with:
    python -m pytest tests/test_scoped_metrics.py -v
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.evaluation.evaluator import evaluate_run
from src.evaluation.ground_truth import load_ground_truth


def _write(tmp_path, rows, scopes=None):
    gt = tmp_path / "ground_truth.json"
    payload = {"dataset": "t", "description": "", "source_path": "src", "functions": rows}
    if scopes is not None:
        payload["scoring_scopes"] = scopes
    gt.write_text(json.dumps(payload), encoding="utf-8")

    run = tmp_path / "analysis.json"
    findings = [
        {"function_name": r["function_name"], "file_path": r["file"],
         "vulnerability_found": r.pop("_flagged", False), "cwe_id": "CWE-798",
         "affected_lines": [], "severity": "high", "explanation": "x",
         "confidence": 0.9, "hallucination_flag": False}
        for r in rows
    ]
    run.write_text(json.dumps({"run_id": "r", "model": "o4-mini",
                               "source_path": "src", "findings": findings}), encoding="utf-8")
    return run, gt


HARNESS_SCOPE = {
    "harness": {
        "description": "the app's own challenge-detection code",
        "files": ["routes/verify.ts", "lib/antiCheat.ts"],
    }
}


class TestScopedMetrics:

    def setup_method(self):
        self.rows = [
            # False positives inside the harness.
            {"function_name": "serverSideChallenges", "file": "routes/verify.ts",
             "vulnerable": False, "source_lines": [1, 5], "_flagged": True},
            {"function_name": "calculateFixItCheatScore", "file": "lib/antiCheat.ts",
             "vulnerable": False, "source_lines": [1, 5], "_flagged": True},
            # A real detection in application code.
            {"function_name": "login", "file": "routes/login.ts", "vulnerable": True,
             "cwe_id": "CWE-798", "source_lines": [1, 5], "_flagged": True},
            # A false positive in application code — must survive the exclusion.
            {"function_name": "helper", "file": "lib/utils.ts", "vulnerable": False,
             "source_lines": [1, 5], "_flagged": True},
        ]

    def _score(self, tmp_path, scopes=HARNESS_SCOPE):
        run, gt_path = _write(tmp_path, self.rows, scopes)
        report, gt = evaluate_run(run, gt_path)
        return report.to_dict(gt)

    def test_full_metrics_are_unchanged_by_the_declaration(self, tmp_path):
        """The headline number must not move because a scope was declared."""
        data = self._score(tmp_path)
        assert data["detection_metrics"]["fp"] == 3
        assert data["detection_metrics"]["tp"] == 1

    def test_scoped_metrics_drop_only_the_declared_files(self, tmp_path):
        data = self._score(tmp_path)
        scoped = data["scoped_metrics"]["excluding_harness"]
        assert scoped["fp"] == 1          # lib/utils.ts survives
        assert scoped["tp"] == 1
        assert scoped["rows_excluded"] == 2

    def test_both_figures_are_published(self, tmp_path):
        data = self._score(tmp_path)
        assert "detection_metrics" in data
        assert "excluding_harness" in data["scoped_metrics"]

    def test_scope_description_travels_with_the_numbers(self, tmp_path):
        """A scoped figure without a statement of what was excluded invites the
        reader to assume it is the headline."""
        data = self._score(tmp_path)
        assert data["scoped_metrics"]["excluding_harness"]["description"]

    def test_dataset_without_scopes_reports_none(self, tmp_path):
        data = self._score(tmp_path, scopes=None)
        assert data["scoped_metrics"] == {}

    def test_empty_file_list_is_ignored(self, tmp_path):
        """An empty scope would otherwise report a duplicate of the headline
        under a name implying something was excluded."""
        data = self._score(tmp_path, scopes={"harness": {"files": []}})
        assert data["scoped_metrics"] == {}

    def test_path_separators_do_not_matter(self, tmp_path):
        data = self._score(tmp_path, scopes={
            "harness": {"description": "d", "files": [r"routes\verify.ts"]}
        })
        assert data["scoped_metrics"]["excluding_harness"]["rows_excluded"] == 1


class TestScopeLoading:

    def test_scopes_are_loaded_and_normalised(self, tmp_path):
        gt_path = tmp_path / "gt.json"
        gt_path.write_text(json.dumps({
            "dataset": "t", "functions": [],
            "scoring_scopes": {"harness": {"files": ["/Routes/Verify.TS", r"lib\a.ts"]}},
        }), encoding="utf-8")

        gt = load_ground_truth(gt_path)
        assert gt.scope_files("harness") == ["routes/verify.ts", "lib/a.ts"]

    def test_unknown_scope_is_empty_not_an_error(self, tmp_path):
        gt_path = tmp_path / "gt.json"
        gt_path.write_text(json.dumps({"dataset": "t", "functions": []}), encoding="utf-8")
        assert load_ground_truth(gt_path).scope_files("nope") == []


class TestJuiceShopScope:
    """The declared list must correspond to files that actually exist in the
    dataset — a typo'd path silently excludes nothing and quietly inflates the
    scoped figure's credibility."""

    GT = Path(__file__).parent.parent / "experiments" / "datasets" / "juice-shop" / "ground_truth.json"

    def setup_method(self):
        if not self.GT.exists():
            pytest.skip("juice-shop dataset not present (experiments/ is gitignored)")
        self.data = json.loads(self.GT.read_text(encoding="utf-8"))

    def test_every_declared_file_exists_in_the_dataset(self):
        declared = set(self.data["scoring_scopes"]["harness"]["files"])
        present = {f["file"] for f in self.data["functions"]}
        assert declared <= present, f"declared but absent: {sorted(declared - present)}"

    def test_the_scope_is_documented(self):
        assert self.data["scoring_scopes"]["harness"]["description"]
