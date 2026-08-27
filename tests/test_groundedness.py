"""Tests for src/evaluation/groundedness.py and src/evaluation/provenance.py."""
import json

import pytest

from src.evaluation.groundedness import (
    FAIL,
    NOT_APPLICABLE,
    PASS,
    check_cwe_in_taxonomy,
    check_flow_source,
    check_line_citations,
    check_location,
    check_named_tokens,
    cross_tabulate,
    score_findings,
    taint_reachable,
    taxonomy_cwes,
)
from src.evaluation.provenance import (
    AUTHOR_TIER,
    CHALLENGE_TIER,
    MARKER_TIER,
    derive_tier,
    load_challenge_keys,
)
from src.evaluation.ground_truth import GroundTruthEntry

SAMPLE = {"file_path": "routes/x.ts", "function_name": "handler",
          "start_line": 10, "end_line": 20, "code": "const q = db.query(req.body.id)"}


class TestLocation:
    def test_lines_inside_the_function_pass(self):
        assert check_location({"affected_lines": [12, 15]}, SAMPLE)["status"] == PASS

    def test_a_line_outside_the_function_fails(self):
        r = check_location({"affected_lines": [12, 99]}, SAMPLE)
        assert r["status"] == FAIL and "99" in r["reason"]

    def test_no_lines_is_not_a_failure(self):
        assert check_location({"affected_lines": []}, SAMPLE)["status"] == NOT_APPLICABLE


class TestLineCitations:
    def test_citation_inside_the_span_passes(self):
        f = {"explanation": "The query on line 14 interpolates input."}
        assert check_line_citations(f, SAMPLE)["status"] == PASS

    def test_citation_outside_the_span_fails(self):
        f = {"explanation": "See line 400 where the value is read."}
        assert check_line_citations(f, SAMPLE)["status"] == FAIL

    def test_a_range_is_read_at_both_ends(self):
        assert check_line_citations({"explanation": "lines 12-40"}, SAMPLE)["status"] == FAIL

    def test_bare_numbers_are_not_citations(self):
        # "10 characters" is not a line reference; treating it as one would
        # manufacture failures out of ordinary prose.
        f = {"explanation": "A password of only 10 characters is accepted."}
        assert check_line_citations(f, SAMPLE)["status"] == NOT_APPLICABLE


class TestFlowSource:
    GRAPH = {
        "a.ts::route": {"function_name": "route", "callees": ["b.ts::mid"],
                        "is_entry_point": True},
        "b.ts::mid": {"function_name": "mid", "callees": ["c.ts::sink"]},
        "c.ts::sink": {"function_name": "sink", "callees": []},
        "d.ts::orphan": {"function_name": "orphan", "callees": []},
    }

    def test_non_flow_cwe_is_not_applicable(self):
        r = check_flow_source({"cwe_id": "CWE-639"}, "c.ts::sink",
                              self.GRAPH["c.ts::sink"], frozenset())
        assert r["status"] == NOT_APPLICABLE

    def test_flow_cwe_without_a_declared_source_fails(self):
        r = check_flow_source({"cwe_id": "CWE-89", "declared_source": ""},
                              "c.ts::sink", self.GRAPH["c.ts::sink"], frozenset())
        assert r["status"] == FAIL

    def test_reachable_sink_passes(self):
        reachable = taint_reachable(self.GRAPH)
        r = check_flow_source({"cwe_id": "CWE-89", "declared_source": "req.body"},
                              "c.ts::sink", self.GRAPH["c.ts::sink"], reachable)
        assert r["status"] == PASS

    def test_unreachable_function_fails(self):
        reachable = taint_reachable(self.GRAPH)
        r = check_flow_source({"cwe_id": "CWE-89", "declared_source": "req.body"},
                              "d.ts::orphan", self.GRAPH["d.ts::orphan"], reachable)
        assert r["status"] == FAIL

    def test_taint_reachable_follows_the_whole_chain(self):
        assert taint_reachable(self.GRAPH) == frozenset(
            {"a.ts::route", "b.ts::mid", "c.ts::sink"}
        )


class TestCweInTaxonomy:
    def test_an_offered_cwe_passes(self):
        assert check_cwe_in_taxonomy({"cwe_id": "CWE-89"}, taxonomy_cwes())["status"] == PASS

    def test_a_cwe_the_prompt_never_offered_fails(self):
        # This assertion used to name CWE-22, which was in FLOW_CWES and in no
        # prompt. The taxonomy repair added it, so the case moved to a class
        # genuinely outside the list. The check is what surfaced that drift.
        assert check_cwe_in_taxonomy({"cwe_id": "CWE-434"}, taxonomy_cwes())["status"] == FAIL

    def test_every_gated_flow_cwe_is_offered(self):
        # The regression this check exists for. Asserted properly in
        # tests/test_taxonomy_consistency.py; repeated here because a change to
        # either list should fail next to the check that reads them.
        from src.llm.evidence_gate import FLOW_CWES
        assert not (FLOW_CWES - taxonomy_cwes())

    def test_a_vulnerability_with_no_cwe_fails(self):
        assert check_cwe_in_taxonomy({"cwe_id": None}, taxonomy_cwes())["status"] == FAIL


class TestNamedTokens:
    def test_a_quoted_identifier_present_in_the_code_passes(self):
        f = {"explanation": "The call to `db.query` is unsafe."}
        assert check_named_tokens(f, SAMPLE, None, {})["status"] == PASS

    def test_an_invented_identifier_fails(self):
        f = {"explanation": "The call to `db.executeRawUnsafe` is unsafe."}
        assert check_named_tokens(f, SAMPLE, None, {})["status"] == FAIL

    def test_prose_in_backticks_is_ignored(self):
        f = {"explanation": "This is `not an identifier` at all."}
        assert check_named_tokens(f, SAMPLE, None, {})["status"] == NOT_APPLICABLE

    def test_a_callee_name_counts_as_present(self):
        graph = {"y.ts::sanitize": {"function_name": "sanitize", "callees": []}}
        node = {"callees": ["y.ts::sanitize"]}
        f = {"explanation": "It never calls `sanitize`."}
        assert check_named_tokens(f, SAMPLE, node, graph)["status"] == PASS


class TestScoreFindings:
    def _run(self):
        analysis = {"findings": [
            {"function_name": "handler", "file_path": "routes/x.ts", "cwe_id": "CWE-639",
             "vulnerability_found": True, "affected_lines": [12], "explanation": "bad"},
            {"function_name": "handler", "file_path": "routes/x.ts", "cwe_id": "CWE-639",
             "vulnerability_found": False, "affected_lines": [], "explanation": "fine"},
        ]}
        extraction = {"results": [SAMPLE]}
        graph = {"graph": {"routes/x.ts::handler": {
            "function_name": "handler", "file_path": "routes/x.ts", "callees": []}}}
        return score_findings(analysis, extraction, graph)

    def test_only_flagged_findings_are_scored(self):
        assert self._run()["findings_scored"] == 1

    def test_a_finding_passing_every_applicable_check_is_grounded(self):
        report = self._run()
        assert report["grounded"] == 1
        assert report["rows"][0]["failed_checks"] == []


class TestCrossTabulate:
    def test_splits_outcomes_by_groundedness(self):
        groundedness = {"rows": [
            {"function_name": "a", "file_path": "/abs/routes/a.ts", "grounded": True},
            {"function_name": "b", "file_path": "/abs/routes/b.ts", "grounded": False},
            {"function_name": "z", "file_path": "/abs/routes/z.ts", "grounded": True},
        ]}
        evaluation = {"instances": [
            {"file": "routes/a.ts", "function_name": "a", "outcome": "TP"},
            {"file": "routes/b.ts", "function_name": "b", "outcome": "FP"},
        ]}
        x = cross_tabulate(groundedness, evaluation)
        assert x["table"]["grounded"] == {"TP": 1, "FP": 0}
        assert x["table"]["ungrounded"] == {"TP": 0, "FP": 1}
        # The row with no ground truth entry is reported, not silently dropped.
        assert x["findings_not_in_ground_truth"] == 1


class TestProvenance:
    def _write(self, tmp_path, name, text):
        (tmp_path / name).write_text(text, encoding="utf-8")

    def test_a_vuln_line_marker_in_the_span_is_the_strongest_tier(self, tmp_path):
        self._write(tmp_path, "r.ts", "\n".join([
            "function f () {",
            "  q(x) // vuln-code-snippet vuln-line someChallenge",
            "}",
        ]))
        entry = GroundTruthEntry("f", "r.ts", True, source_lines=[1, 3])
        assert derive_tier(entry, tmp_path)["tier"] == MARKER_TIER

    def test_a_neutral_line_marker_does_not_count(self, tmp_path):
        # Only `vuln-line` asserts a defect; the others delimit the snippet the
        # player is shown.
        self._write(tmp_path, "r.ts", "function f () {\n  q(x) // vuln-code-snippet neutral-line k\n}")
        entry = GroundTruthEntry("f", "r.ts", True, source_lines=[1, 3])
        assert derive_tier(entry, tmp_path)["tier"] == AUTHOR_TIER

    def test_a_challenge_reference_is_the_middle_tier(self, tmp_path):
        self._write(tmp_path, "r.ts", "function f () {\n  solve(challenges.myChallenge)\n}")
        entry = GroundTruthEntry("f", "r.ts", True, source_lines=[1, 3])
        r = derive_tier(entry, tmp_path, challenge_keys={"myChallenge"})
        assert r["tier"] == CHALLENGE_TIER

    def test_a_challenge_key_the_project_does_not_define_is_ignored(self, tmp_path):
        self._write(tmp_path, "r.ts", "function f () {\n  solve(challenges.invented)\n}")
        entry = GroundTruthEntry("f", "r.ts", True, source_lines=[1, 3])
        assert derive_tier(entry, tmp_path, challenge_keys={"real"})["tier"] == AUTHOR_TIER

    def test_evidence_outside_the_function_span_does_not_count(self, tmp_path):
        self._write(tmp_path, "r.ts", "\n".join([
            "const KEY = 'x' // vuln-code-snippet vuln-line k",
            "function f () {",
            "  sign(KEY)",
            "}",
        ]))
        entry = GroundTruthEntry("f", "r.ts", True, source_lines=[2, 4])
        assert derive_tier(entry, tmp_path)["tier"] == AUTHOR_TIER

    def test_a_row_with_no_line_range_falls_back_to_author(self, tmp_path):
        self._write(tmp_path, "r.ts", "function f () {}")
        assert derive_tier(GroundTruthEntry("f", "r.ts", True), tmp_path)["tier"] == AUTHOR_TIER

    def test_missing_source_file_is_not_an_error(self, tmp_path):
        entry = GroundTruthEntry("f", "gone.ts", True, source_lines=[1, 2])
        assert derive_tier(entry, tmp_path)["tier"] == AUTHOR_TIER

    def test_challenge_keys_are_read_from_the_project_file(self, tmp_path):
        (tmp_path / "data" / "static").mkdir(parents=True)
        (tmp_path / "data" / "static" / "challenges.yml").write_text(
            "-\n  name: 'X'\n  key: firstChallenge\n-\n  name: 'Y'\n  key: secondChallenge\n",
            encoding="utf-8",
        )
        assert load_challenge_keys(tmp_path) == {"firstChallenge", "secondChallenge"}


class TestPatchValidity:
    def test_a_validated_patch_passes(self):
        from src.evaluation.groundedness import check_patch_validity
        patch = {"unified_diff": "@@ -1 +1 @@\n-a\n+b", "patch_valid": True}
        assert check_patch_validity({}, patch)["status"] == PASS

    def test_a_patch_that_does_not_apply_fails_with_its_reason(self):
        from src.evaluation.groundedness import check_patch_validity
        patch = {"unified_diff": "@@ -1 +1 @@\n-a\n+b", "patch_valid": False,
                 "patch_error": "hunk_context_not_found"}
        r = check_patch_validity({}, patch)
        assert r["status"] == FAIL and "hunk_context_not_found" in r["reason"]

    def test_no_patch_record_is_not_a_failure(self):
        # A run that was never patched has proposed no bad fix, it has proposed
        # none. Failing it would punish the run for a command nobody ran.
        from src.evaluation.groundedness import check_patch_validity
        assert check_patch_validity({}, None)["status"] == NOT_APPLICABLE

    def test_an_empty_diff_is_not_a_failure(self):
        from src.evaluation.groundedness import check_patch_validity
        assert check_patch_validity({}, {"unified_diff": "  "})["status"] == NOT_APPLICABLE


class TestPatchRecheck:
    """C6 — needs a model call, so every test here injects a fake one."""

    FINDING = {"function_name": "handler", "file_path": "routes/x.ts", "cwe_id": "CWE-89"}
    PATCH = {"patch_valid": True, "patched_code": "const q = db.query('?', [id])"}

    def test_a_clean_reanalysis_is_resolved(self):
        from src.evaluation.patch_recheck import RESOLVED, recheck_one
        out = recheck_one(self.FINDING, self.PATCH, lambda code, f: {"vulnerability_found": False})
        assert out["verdict"] == RESOLVED

    def test_the_same_cwe_coming_back_is_unresolved(self):
        from src.evaluation.patch_recheck import UNRESOLVED, recheck_one
        out = recheck_one(self.FINDING, self.PATCH,
                          lambda code, f: {"vulnerability_found": True, "cwe_id": "CWE-89"})
        assert out["verdict"] == UNRESOLVED

    def test_a_different_cwe_is_displaced_not_resolved(self):
        # A fix that closes an injection and opens an authorisation hole is not
        # a fix; counting it as one would be the whole point of the check lost.
        from src.evaluation.patch_recheck import DISPLACED, recheck_one
        out = recheck_one(self.FINDING, self.PATCH,
                          lambda code, f: {"vulnerability_found": True, "cwe_id": "CWE-639"})
        assert out["verdict"] == DISPLACED

    def test_an_invalid_patch_is_skipped_not_resolved(self):
        from src.evaluation.patch_recheck import SKIPPED, recheck_one
        out = recheck_one(self.FINDING, {"patch_valid": False}, lambda code, f: 1 / 0)
        assert out["verdict"] == SKIPPED

    def test_a_failing_call_is_skipped_not_resolved(self):
        from src.evaluation.patch_recheck import SKIPPED, recheck_one

        def boom(code, f):
            raise RuntimeError("connection reset")

        out = recheck_one(self.FINDING, self.PATCH, boom)
        assert out["verdict"] == SKIPPED and "connection reset" in out["reason"]

    def test_the_call_limit_is_respected_and_the_rest_reported_as_skipped(self):
        from src.evaluation.patch_recheck import SKIPPED, recheck_run
        rows = [{"function_name": f"f{i}", "file_path": "routes/x.ts", "cwe_id": "CWE-89"}
                for i in range(5)]
        patches = {"patches": [{"file_path": "routes/x.ts", "function_name": f"f{i}",
                                "patch_valid": True, "patched_code": "ok"} for i in range(5)]}
        out = recheck_run({"rows": rows}, patches,
                          lambda code, f: {"vulnerability_found": False}, limit=2)
        assert out["calls_made"] == 2
        assert out["counts"][SKIPPED] == 3
        # The denominator covers only what was actually re-checked.
        assert out["resolution_rate"] == 1.0
