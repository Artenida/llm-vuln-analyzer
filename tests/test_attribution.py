"""Tests for cross-function attribution of findings.

Three juice-shop bugs are counted twice against the tool - once as a false
positive at the sink, once as a false negative at the caller - because the
anti-bleed rule makes the model disclaim a defect it can see in a callee:

    lib/insecurity.ts::hash           <-> models/user.ts::set   (unsalted MD5)
    lib/insecurity.ts::sanitizeLegacy <-> models/user.ts::set   (weak sanitizer)
    lib/insecurity.ts::decode         <-> discountFromCoupon

This is the stage most open to the objection that the tool is marking its own
homework, so most of what is pinned here is the limits: the cap, the
one-claim-per-finding rule, that the strict metric never moves, and that a false
positive can only be neutralised by a detection that genuinely happened.

Run with:
    python -m pytest tests/test_attribution.py -v
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.llm import attribution as attr


class TestNodeIdNormalisation:

    def test_full_node_id(self):
        assert attr.normalize_node_id("lib/insecurity.ts::hash") == "lib/insecurity.ts::hash"

    def test_backslashes_normalised(self):
        assert attr.normalize_node_id(r"lib\insecurity.ts::hash") == "lib/insecurity.ts::hash"

    def test_windows_absolute_path_keeps_its_drive(self):
        got = attr.normalize_node_id(r"C:\app\lib\insecurity.ts::hash")
        assert got == "C:/app/lib/insecurity.ts::hash"

    def test_bare_function_name_accepted(self):
        """The model supplies one often enough that rejecting it would throw away
        real attributions."""
        assert attr.normalize_node_id("hash") == "hash"

    def test_quotes_and_whitespace_stripped(self):
        assert attr.normalize_node_id('  "lib/x.ts::f"  ') == "lib/x.ts::f"

    @pytest.mark.parametrize("junk", [None, "", "  ", "null", "none", "N/A", "-",
                                      "the hash function in insecurity"])
    def test_unusable_values_are_dropped_not_stored(self, junk):
        """Downstream code should never have to guess what this field means."""
        assert attr.normalize_node_id(junk) is None


class TestImplicatedList:

    def test_capped(self):
        """Uncapped, 'implicate everything' is a strictly winning strategy and
        the metric stops measuring anything. This cap is load-bearing."""
        values = [f"a.ts::f{i}" for i in range(10)]
        assert len(attr.clean_implicated(values)) == attr.MAX_IMPLICATED

    def test_deduplicated(self):
        assert attr.clean_implicated(["a.ts::f", "a.ts::f"]) == ["a.ts::f"]

    def test_drops_the_attributed_target(self):
        got = attr.clean_implicated(["a.ts::f", "b.ts::g"], attributed_to="a.ts::f")
        assert got == ["b.ts::g"]

    def test_unusable_entries_removed(self):
        assert attr.clean_implicated(["a.ts::f", "", None, "null"]) == ["a.ts::f"]

    def test_a_bare_word_survives_but_can_never_match_a_row(self):
        """A single prose word is indistinguishable from a function name, so it
        is not worth rejecting here — matching requires an exact function-name
        match against a real row, which prose will never satisfy."""
        assert attr.clean_implicated(["unclear"]) == ["unclear"]
        assert not attr.matches_row("unclear", "models/user.ts", "set")

    def test_string_instead_of_list(self):
        assert attr.clean_implicated("a.ts::f") == ["a.ts::f"]

    @pytest.mark.parametrize("value", [None, [], 42, {"a": 1}])
    def test_non_list_shapes(self, value):
        assert attr.clean_implicated(value) == []


class TestRowMatching:

    def test_matches_on_file_suffix_and_exact_name(self):
        """The run records absolute paths, the ground truth repo-relative ones."""
        assert attr.matches_row(
            r"C:\app\juice-shop\models\user.ts::set", "models/user.ts", "set"
        )

    def test_function_name_must_match_exactly(self):
        """A looser test would let one finding claim any row in the file."""
        assert not attr.matches_row("models/user.ts::setRole", "models/user.ts", "set")

    def test_wrong_file_rejected(self):
        assert not attr.matches_row("models/feedback.ts::set", "models/user.ts", "set")

    def test_bare_name_matches_on_name_alone(self):
        assert attr.matches_row("set", "models/user.ts", "set")

    def test_empty_node_id(self):
        assert not attr.matches_row("", "models/user.ts", "set")


# ── end-to-end scoring ────────────────────────────────────────────────────────

def _gt(tmp_path, rows):
    path = tmp_path / "ground_truth.json"
    path.write_text(json.dumps({
        "dataset": "t", "description": "", "source_path": "src", "functions": rows,
    }), encoding="utf-8")
    return path


def _run(tmp_path, findings):
    path = tmp_path / "analysis.json"
    path.write_text(json.dumps({
        "run_id": "r", "model": "o4-mini", "source_path": "src", "findings": findings,
    }), encoding="utf-8")
    return path


def _finding(fn, file, found=True, cwe="CWE-327", **kw):
    return {
        "function_name": fn, "file_path": file, "vulnerability_found": found,
        "cwe_id": cwe if found else None, "affected_lines": [], "severity": "high",
        "explanation": "x", "confidence": 0.9, "hallucination_flag": False,
        **kw,
    }


class TestAttributionScoring:
    """The hash/set pair: the defect is in the sink, the ground truth labels the
    caller, and the model reports it once and names both."""

    def setup_method(self):
        self.rows = [
            {"function_name": "hash", "file": "lib/insecurity.ts", "vulnerable": False,
             "source_lines": [41, 45]},
            {"function_name": "set", "file": "models/user.ts", "vulnerable": True,
             "cwe_id": "CWE-916", "source_lines": [75, 77]},
        ]
        self.findings = [
            _finding("hash", "lib/insecurity.ts",
                     attributed_to="lib/insecurity.ts::hash",
                     also_implicates=["models/user.ts::set"]),
            _finding("set", "models/user.ts", found=False),
        ]

    def _score(self, tmp_path):
        from src.evaluation.evaluator import evaluate_run
        report, gt = evaluate_run(_run(tmp_path, self.findings), _gt(tmp_path, self.rows))
        return report, report.to_dict(gt)

    def test_strict_metric_counts_it_as_two_errors(self, tmp_path):
        """This is the behaviour being corrected — and it must stay available."""
        _, data = self._score(tmp_path)
        assert data["detection_metrics"]["fp"] == 1
        assert data["detection_metrics"]["fn"] == 1
        assert data["detection_metrics"]["tp"] == 0

    def test_attribution_aware_metric_counts_it_as_one_detection(self, tmp_path):
        _, data = self._score(tmp_path)
        aware = data["detection_metrics_attribution_aware"]
        assert aware["tp"] == 1
        assert aware["fn"] == 0
        assert aware["fp"] == 0

    def test_both_metrics_are_published(self, tmp_path):
        """A number that includes indirect credit without showing how much came
        from indirect credit is not defensible."""
        _, data = self._score(tmp_path)
        assert "detection_metrics" in data
        assert "detection_metrics_attribution_aware" in data

    def test_summary_names_the_rows_involved(self, tmp_path):
        _, data = self._score(tmp_path)
        summary = data["attribution_summary"]
        assert summary["rows_recovered"][0]["function_name"] == "set"
        assert summary["rows_recovered"][0]["basis"] == "also_implicates"
        assert summary["false_positives_neutralized"][0]["function_name"] == "hash"
        assert summary["delta"] == {"tp": 1, "fn": -1, "fp": -1}

    def test_every_row_records_how_it_was_matched(self, tmp_path):
        _, data = self._score(tmp_path)
        by_name = {i["function_name"]: i for i in data["instances"]}
        assert by_name["set"]["match_basis"] == "also_implicates"
        assert by_name["hash"]["match_basis"] == "direct"


class TestAttributionLimits:

    def test_a_finding_can_only_be_claimed_once(self, tmp_path):
        """Otherwise one finding is credited as several detections."""
        from src.evaluation.evaluator import evaluate_run

        rows = [
            {"function_name": "sink", "file": "lib/a.ts", "vulnerable": False, "source_lines": [1, 5]},
            {"function_name": "one", "file": "lib/b.ts", "vulnerable": True,
             "cwe_id": "CWE-327", "source_lines": [1, 5]},
            {"function_name": "two", "file": "lib/c.ts", "vulnerable": True,
             "cwe_id": "CWE-327", "source_lines": [1, 5]},
        ]
        findings = [_finding("sink", "lib/a.ts",
                             also_implicates=["lib/b.ts::one", "lib/c.ts::two"])]
        report, gt = evaluate_run(_run(tmp_path, findings), _gt(tmp_path, rows))
        data = report.to_dict(gt)

        assert data["detection_metrics_attribution_aware"]["tp"] == 1
        assert len(data["attribution_summary"]["rows_recovered"]) == 1

    def test_false_positive_is_not_neutralised_without_a_recovery(self, tmp_path):
        """The only way to erase a false positive is to have genuinely found a
        vulnerability that was otherwise missed. Implicating a clean row, or one
        already detected, buys nothing."""
        from src.evaluation.evaluator import evaluate_run

        rows = [
            {"function_name": "sink", "file": "lib/a.ts", "vulnerable": False, "source_lines": [1, 5]},
            {"function_name": "innocent", "file": "lib/b.ts", "vulnerable": False,
             "source_lines": [1, 5]},
        ]
        findings = [_finding("sink", "lib/a.ts", also_implicates=["lib/b.ts::innocent"])]
        report, gt = evaluate_run(_run(tmp_path, findings), _gt(tmp_path, rows))
        data = report.to_dict(gt)

        assert data["detection_metrics"]["fp"] == 1
        assert data["detection_metrics_attribution_aware"]["fp"] == 1
        assert data["attribution_summary"]["delta"]["fp"] == 0

    def test_a_row_already_matched_directly_is_never_displaced(self, tmp_path):
        """Attribution runs second and only fills gaps, so it can never overwrite
        evidence-based matching."""
        from src.evaluation.evaluator import evaluate_run

        rows = [
            {"function_name": "target", "file": "lib/a.ts", "vulnerable": True,
             "cwe_id": "CWE-89", "source_lines": [1, 5]},
            {"function_name": "other", "file": "lib/b.ts", "vulnerable": False,
             "source_lines": [1, 5]},
        ]
        findings = [
            _finding("target", "lib/a.ts", cwe="CWE-89"),
            _finding("other", "lib/b.ts", also_implicates=["lib/a.ts::target"]),
        ]
        report, gt = evaluate_run(_run(tmp_path, findings), _gt(tmp_path, rows))
        data = report.to_dict(gt)

        by_name = {i["function_name"]: i for i in data["instances"]}
        assert by_name["target"]["match_basis"] == "direct"
        assert by_name["target"]["outcome"] == "TP"

    def test_clean_verdicts_cannot_attribute(self, tmp_path):
        """A finding that reports nothing has nothing to credit elsewhere."""
        from src.evaluation.evaluator import evaluate_run

        rows = [
            {"function_name": "sink", "file": "lib/a.ts", "vulnerable": False, "source_lines": [1, 5]},
            {"function_name": "missed", "file": "lib/b.ts", "vulnerable": True,
             "cwe_id": "CWE-327", "source_lines": [1, 5]},
        ]
        findings = [_finding("sink", "lib/a.ts", found=False,
                             also_implicates=["lib/b.ts::missed"])]
        report, gt = evaluate_run(_run(tmp_path, findings), _gt(tmp_path, rows))
        data = report.to_dict(gt)

        assert data["detection_metrics_attribution_aware"]["fn"] == 1

    def test_runs_without_the_fields_are_unaffected(self, tmp_path):
        """Re-scoring the frozen baseline must give byte-identical numbers."""
        from src.evaluation.evaluator import evaluate_run

        rows = [{"function_name": "f", "file": "a.ts", "vulnerable": True,
                 "cwe_id": "CWE-89", "source_lines": [1, 5]}]
        findings = [_finding("f", "a.ts", found=False)]
        report, gt = evaluate_run(_run(tmp_path, findings), _gt(tmp_path, rows))
        data = report.to_dict(gt)

        assert data["detection_metrics"] == data["detection_metrics_attribution_aware"]
        assert data["attribution_summary"]["delta"] == {"tp": 0, "fn": 0, "fp": 0}


class TestParsing:

    def test_cap_is_enforced_at_parse_time(self):
        """Before it reaches the saved run, so a malformed claim never persists."""
        from src.llm.client import _parse_attribution
        from src.models import CodeSample, Language

        sample = CodeSample(function_name="f", file_path="a.ts", code="x",
                            language=Language.TYPESCRIPT, start_line=1, end_line=2)
        parsed = _parse_attribution(
            {"attributed_to": "b.ts::g",
             "also_implicates": [f"c.ts::h{i}" for i in range(10)]},
            sample,
        )
        assert len(parsed["also_implicates"]) == attr.MAX_IMPLICATED
        assert parsed["attributed_to"] == "b.ts::g"

    def test_self_attribution_is_dropped(self):
        """Naming the target as the defect's home is the default case, not a
        redirection — storing it would make every finding look redirected."""
        from src.llm.client import _parse_attribution
        from src.models import CodeSample, Language

        sample = CodeSample(function_name="f", file_path="a.ts", code="x",
                            language=Language.TYPESCRIPT, start_line=1, end_line=2)
        parsed = _parse_attribution({"attributed_to": "a.ts::f"}, sample)
        assert parsed["attributed_to"] is None

    def test_absent_fields_are_safe(self):
        from src.llm.client import _parse_attribution
        from src.models import CodeSample, Language

        sample = CodeSample(function_name="f", file_path="a.ts", code="x",
                            language=Language.TYPESCRIPT, start_line=1, end_line=2)
        parsed = _parse_attribution({}, sample)
        assert parsed == {"attributed_to": None, "also_implicates": []}
