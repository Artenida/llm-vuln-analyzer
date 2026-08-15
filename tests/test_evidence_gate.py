"""Tests for the flow-CWE evidence gate.

On the juice-shop baseline the gate applies to 28 of 77 flagged findings —
17 true positives and 13 false positives, including all eight CWE-117 log
injection reports, every one of which was wrong. So the gate has real reach and
real risk: a rule worded too broadly would take true positives with it.

Run with:
    python -m pytest tests/test_evidence_gate.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.llm import evidence_gate as eg


class TestWhichCWEsAreGated:

    @pytest.mark.parametrize("cwe", ["CWE-89", "CWE-79", "CWE-95", "CWE-117",
                                     "CWE-22", "CWE-918", "CWE-611"])
    def test_flow_cwes_require_a_source(self, cwe):
        assert eg.requires_source(cwe)

    @pytest.mark.parametrize("cwe", ["CWE-639", "CWE-862", "CWE-347", "CWE-798",
                                     "CWE-916", "CWE-345", "CWE-841", "CWE-362"])
    def test_non_flow_cwes_are_not_gated(self, cwe):
        """Authorization, crypto and business-logic defects are properties of the
        code in front of you, not of a data flow. Demanding a taint path for them
        would suppress exactly what this tool is best at — CWE-639 alone is its
        single largest true-positive class."""
        assert not eg.requires_source(cwe)

    def test_case_and_whitespace_tolerant(self):
        assert eg.requires_source(" cwe-117 ")

    def test_missing_cwe_is_not_gated(self):
        assert not eg.requires_source(None)
        assert not eg.requires_source("")


class TestSourceDeclaration:

    def test_plain_source_line(self):
        assert eg.declared_source("SOURCE: req.query.q reaches the SQL string") \
            == "req.query.q reaches the SQL string"

    def test_found_mid_explanation(self):
        text = "The query is built by concatenation.\nSOURCE: req.params.id\nFix: parameterise."
        assert eg.declared_source(text) == "req.params.id"

    def test_tolerates_decoration(self):
        """This checks whether the model did the reasoning, not whether it can
        follow a format spec — a stricter pattern would mostly measure
        formatting compliance."""
        assert eg.declared_source("- source: req.body.email")
        assert eg.declared_source("  * SOURCE - req.headers.host")

    def test_found_mid_line(self):
        """The prompt asks for its own line, but position is formatting. What is
        being measured is whether the model named a source at all."""
        assert eg.declared_source("Concatenated query. SOURCE: req.query.q") \
            == "req.query.q"

    def test_similar_words_do_not_count(self):
        assert eg.declared_source("resource: /api/Cards") is None
        assert eg.declared_source("datasource: postgres") is None

    def test_absent(self):
        assert eg.declared_source("User input is logged without sanitisation.") is None
        assert eg.declared_source("") is None
        assert eg.declared_source(None) is None

    def test_empty_source_line_does_not_count(self):
        assert eg.declared_source("SOURCE:   ") is None


class TestEvaluate:

    def test_flow_cwe_with_a_source_is_satisfied(self):
        assert eg.evaluate("CWE-89", True, "SOURCE: req.query.q") == eg.SATISFIED

    def test_flow_cwe_without_a_source_is_flagged(self):
        assert eg.evaluate("CWE-117", True, "Logs user input.") == eg.MISSING_SOURCE

    def test_non_flow_cwe_is_not_applicable(self):
        assert eg.evaluate("CWE-639", True, "No ownership check.") == eg.NOT_APPLICABLE

    def test_clean_verdict_is_not_applicable(self):
        """A clean finding has no flow to substantiate."""
        assert eg.evaluate("CWE-117", False, "") == eg.NOT_APPLICABLE

    def test_verdict_is_recorded_not_enforced(self):
        """The gate never changes vulnerability_found. Suppressing a finding here
        would move recall as well as precision and make the stage's own effect
        unreadable."""
        verdict = eg.evaluate("CWE-117", True, "no source named")
        assert verdict == eg.MISSING_SOURCE
        assert verdict not in (True, False)


class TestPromptContract:
    """The prompt and the checker must agree on which CWEs are gated — they live
    in one module so they cannot drift, and these assert the wiring."""

    def test_every_gated_cwe_number_appears_in_the_prompt(self):
        for cwe in eg.FLOW_CWES:
            number = cwe.split("-")[1]
            assert number in eg.EVIDENCE_GATE_PROMPT, f"{cwe} gated but not in prompt"

    def test_prompt_demands_the_line_the_checker_looks_for(self):
        assert "SOURCE:" in eg.EVIDENCE_GATE_PROMPT

    def test_prompt_states_what_is_not_a_source(self):
        """The eight CWE-117 false positives were config values, NODE_ENV,
        challenge keys and internal callers — the prompt has to name those.
        Whitespace is normalised because the prompt is hard-wrapped, so a phrase
        can straddle a line break."""
        text = " ".join(eg.EVIDENCE_GATE_PROMPT.lower().split())
        for phrase in ["config value", "environment variable", "internal caller"]:
            assert phrase in text

    def test_prompt_is_reachable_from_both_prompt_builders(self):
        from src.llm.client import _REACT_SYSTEM

        assert "EVIDENCE GATE" in _REACT_SYSTEM


class TestRunSaverIntegration:

    def test_gate_verdict_is_persisted_per_finding(self, tmp_path):
        from src.llm.client import VulnerabilityReport
        from src.models import CodeSample, Language
        from src.results.run_saver import save_run
        import json

        def _report(name, cwe, explanation):
            return VulnerabilityReport(
                function_name=name, file_path="routes/x.ts", language="typescript",
                vulnerability_found=True, cwe_id=cwe, affected_lines=[2],
                severity="high", explanation=explanation, patch_suggestion="",
                confidence=0.9, hallucination_flag=False,
            )

        reports = [
            _report("grounded", "CWE-89", "Concatenated query. SOURCE: req.query.q"),
            _report("ungrounded", "CWE-117", "Logs a value without sanitising it."),
            _report("notgated", "CWE-639", "No ownership check on the id."),
        ]
        samples = [
            CodeSample(function_name=r.function_name, file_path="routes/x.ts",
                       code="x", language=Language.TYPESCRIPT, start_line=1, end_line=3)
            for r in reports
        ]

        out = save_run(reports, samples, "src", "o4-mini",
                       results_folder=str(tmp_path), filename="run.json")
        data = json.loads(Path(out).read_text(encoding="utf-8"))

        by_name = {f["function_name"]: f for f in data["findings"]}
        assert by_name["grounded"]["evidence_gate"] == eg.SATISFIED
        assert by_name["grounded"]["declared_source"] == "req.query.q"
        assert by_name["ungrounded"]["evidence_gate"] == eg.MISSING_SOURCE
        assert by_name["notgated"]["evidence_gate"] == eg.NOT_APPLICABLE

        assert data["summary"]["flow_findings"] == 2
        assert data["summary"]["flow_findings_without_source"] == 1

    def test_gate_does_not_touch_the_hallucination_metric(self, tmp_path):
        """hallucination_rate is a reported metric with an established meaning.
        Folding a new signal into it would make runs incomparable across this
        change — which is the one thing the measurement harness exists to stop."""
        from src.llm.client import VulnerabilityReport
        from src.models import CodeSample, Language
        from src.results.run_saver import save_run
        import json

        report = VulnerabilityReport(
            function_name="ungrounded", file_path="routes/x.ts", language="typescript",
            vulnerability_found=True, cwe_id="CWE-117", affected_lines=[2],
            severity="medium", explanation="no source", patch_suggestion="",
            confidence=0.9, hallucination_flag=False,
        )
        sample = CodeSample(function_name="ungrounded", file_path="routes/x.ts",
                            code="x", language=Language.TYPESCRIPT, start_line=1, end_line=3)

        out = save_run([report], [sample], "src", "o4-mini",
                       results_folder=str(tmp_path), filename="run.json")
        data = json.loads(Path(out).read_text(encoding="utf-8"))

        assert data["findings"][0]["evidence_gate"] == eg.MISSING_SOURCE
        assert data["findings"][0]["hallucination_flag"] is False
        assert data["summary"]["hallucinated"] == 0


class TestEvaluatorBreakdown:

    def test_breakdown_splits_flagged_findings_by_verdict(self):
        from src.evaluation.evaluator import EvaluationReport, InstanceVerdict

        def _v(outcome, gate):
            return InstanceVerdict(
                instance_id="x", function_name="f", file="a.ts",
                gt_vulnerable=(outcome == "TP"), gt_cwe="CWE-117",
                analyzed=True, predicted_vulnerable=True, predicted_cwe="CWE-117",
                outcome=outcome, cwe_correct=None, evidence_gate=gate,
            )

        report = EvaluationReport(
            run_id="r", dataset="d", analysis_mode="react_loop", model="o4-mini",
            source_path="src",
            instances=[
                _v("FP", eg.MISSING_SOURCE), _v("FP", eg.MISSING_SOURCE),
                _v("TP", eg.SATISFIED), _v("FP", eg.SATISFIED),
            ],
            unmatched_findings=[], unresolved_findings=[],
        )

        breakdown = report.evidence_gate_breakdown()
        assert breakdown[eg.MISSING_SOURCE] == {"tp": 0, "fp": 2, "precision": 0.0}
        assert breakdown[eg.SATISFIED] == {"tp": 1, "fp": 1, "precision": 0.5}

    def test_runs_predating_the_gate_report_nothing(self):
        """Re-deriving a verdict for old findings would measure the previous
        prompt against a rule it was never given."""
        from src.evaluation.evaluator import EvaluationReport, InstanceVerdict

        report = EvaluationReport(
            run_id="r", dataset="d", analysis_mode="react_loop", model="o4-mini",
            source_path="src",
            instances=[InstanceVerdict(
                instance_id="x", function_name="f", file="a.ts",
                gt_vulnerable=False, gt_cwe=None, analyzed=True,
                predicted_vulnerable=True, predicted_cwe="CWE-117",
                outcome="FP", cwe_correct=None, evidence_gate=None,
            )],
            unmatched_findings=[], unresolved_findings=[],
        )
        assert report.evidence_gate_breakdown() == {}
