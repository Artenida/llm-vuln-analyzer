"""Tests for the flow-level pass — grouping, prompting, and parsing.

All six execution-proven juice-shop vulnerabilities are in the NEITHER bucket,
missed by both the LLM agent and Semgrep. The canonical case:

    generateCoupon      z85-encodes a discount   -> analysed, correctly clean
    discountFromCoupon  accepts it on a regex    -> analysed, correctly clean

Neither function is wrong. The pair is. No single-function prompt reaches that,
which is why grouping is the unit of work here.

Run with:
    python -m pytest tests/test_flow_pass.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.agent import flow_groups as fg
from src.agent.flow_pass import FlowPass, format_group_prompt
from src.models import CodeSample, Language


def _sample(name, file="lib/insecurity.ts", start=1, end=10, code="function f () {}"):
    return CodeSample(function_name=name, file_path=file, code=code,
                      language=Language.TYPESCRIPT, start_line=start, end_line=end)


class TestSubjectExtraction:

    def test_producer_subject(self):
        assert fg._subject("generateCoupon", fg._PRODUCER_VERBS) == "coupon"

    def test_consumer_subject_keeps_its_qualifier(self):
        assert fg._subject("discountFromCoupon", fg._CONSUMER_VERBS) == "discountcoupon"

    def test_all_matching_verbs_are_stripped(self):
        """Stripping only the first left `discountFromCoupon` unable to pair with
        `generateCoupon` — the one case this strategy exists for."""
        assert "from" not in fg._subject("discountFromCoupon", fg._CONSUMER_VERBS)

    def test_name_without_a_verb(self):
        assert fg._subject("hash", fg._PRODUCER_VERBS) is None

    def test_subject_too_short_is_rejected(self):
        assert fg._subject("generate", fg._PRODUCER_VERBS) is None


class TestSubjectMatching:

    def test_exact(self):
        assert fg._subjects_match("coupon", "coupon")

    def test_containment(self):
        assert fg._subjects_match("coupon", "discountcoupon")

    def test_short_fragments_do_not_pair(self):
        """Containment is looser than equality, so a short fragment would pair
        unrelated functions."""
        assert not fg._subjects_match("key", "monkeypatch")

    def test_unrelated(self):
        assert not fg._subjects_match("coupon", "password")


class TestProducerConsumerGroups:

    def test_the_coupon_pair_is_grouped(self):
        samples = [
            _sample("generateCoupon"),
            _sample("discountFromCoupon", start=20, end=30),
            _sample("hash", start=40, end=45),
        ]
        groups = fg.build_producer_consumer_groups(samples)
        assert len(groups) == 1
        names = {n.rpartition("::")[2] for n in groups[0].node_ids}
        assert names == {"generateCoupon", "discountFromCoupon"}

    def test_rationale_names_what_to_look_for(self):
        """A group with no stated reason is just a longer prompt."""
        samples = [_sample("generateCoupon"), _sample("discountFromCoupon", start=20, end=30)]
        rationale = fg.build_producer_consumer_groups(samples)[0].rationale
        assert "forged" in rationale

    def test_a_producer_with_no_consumer_is_not_a_group(self):
        assert fg.build_producer_consumer_groups([_sample("generateCoupon")]) == []

    def test_chunks_are_never_grouped(self):
        """A chunk is a slice of one function, not a participant in a workflow."""
        chunk = _sample("configureApp#1")
        chunk.chunk_of = "configureApp"
        samples = [_sample("generateCoupon"), _sample("verifyCoupon", start=20, end=30), chunk]
        groups = fg.build_producer_consumer_groups(samples)
        assert all("#" not in n for g in groups for n in g.node_ids)

    def test_oversized_groups_are_dropped(self):
        """Past the cap a group stops being a workflow and becomes a file dump."""
        samples = [_sample(f"generateThing{i}", start=1, end=500) for i in range(3)]
        samples += [_sample(f"verifyThing{i}", start=1, end=500) for i in range(3)]
        assert fg.build_producer_consumer_groups(samples) == []


class TestRouteClusterGroups:

    def test_handler_and_its_callees_are_grouped(self):
        samples = [_sample("getAddress", "routes/address.ts"),
                   _sample("findAddress", "lib/db.ts", start=20, end=30)]
        graph = {
            "routes/address.ts::getAddress": {
                "route_registrations": [{"method": "GET", "path": "/api/Addresss"}],
                "callees": ["lib/db.ts::findAddress"], "callers": [],
            },
            "lib/db.ts::findAddress": {
                "route_registrations": [], "callees": [], "callers": [],
            },
        }
        groups = fg.build_route_cluster_groups(samples, graph)
        assert len(groups) == 1
        assert groups[0].label == "GET /api/Addresss"
        assert len(groups[0].node_ids) == 2

    def test_a_function_with_no_registration_anchors_nothing(self):
        """Clusters anchor on something actually reachable over HTTP, not on any
        function that happens to have callees."""
        samples = [_sample("helper", "lib/a.ts"), _sample("other", "lib/b.ts", start=20, end=30)]
        graph = {
            "lib/a.ts::helper": {"route_registrations": [],
                                 "callees": ["lib/b.ts::other"], "callers": []},
            "lib/b.ts::other": {"route_registrations": [], "callees": [], "callers": []},
        }
        assert fg.build_route_cluster_groups(samples, graph) == []

    def test_external_callees_are_not_members(self):
        samples = [_sample("getAddress", "routes/address.ts")]
        graph = {"routes/address.ts::getAddress": {
            "route_registrations": [{"method": "GET", "path": "/x"}],
            "callees": ["external::res.json"], "callers": [],
        }}
        assert fg.build_route_cluster_groups(samples, graph) == []


class TestDeduplication:

    def test_a_route_cluster_absorbs_its_own_subset(self):
        """Analysing a group and its own subset pays twice for one question.
        Here the model-writer group is wholly contained in the route cluster."""
        samples = [
            _sample("addFeedback", "routes/feedback.ts"),
            _sample("set", "models/feedback.ts", start=20, end=30),
        ]
        graph = {
            "routes/feedback.ts::addFeedback": {
                "route_registrations": [{"method": "POST", "path": "/api/Feedbacks"}],
                "callees": ["models/feedback.ts::set"], "callers": [],
            },
            "models/feedback.ts::set": {
                "route_registrations": [], "callees": [],
                "callers": ["routes/feedback.ts::addFeedback"],
            },
        }
        groups = fg.build_flow_groups(samples, graph)
        assert len(groups) == 1
        assert groups[0].kind == "route_cluster"

    def test_max_groups_caps_the_spend(self):
        samples = [_sample("generateCoupon"), _sample("verifyCoupon", start=20, end=30),
                   _sample("generateToken", start=40, end=50),
                   _sample("verifyToken", start=60, end=70)]
        assert len(fg.build_flow_groups(samples, {}, max_groups=1)) == 1


class TestPrompt:

    def setup_method(self):
        self.group = fg.FlowGroup(
            kind="producer_consumer",
            label="coupon: generateCoupon + discountFromCoupon",
            node_ids=["lib/insecurity.ts::generateCoupon", "lib/insecurity.ts::discountFromCoupon"],
            rationale="one mints, one accepts",
        )
        self.by_id = {
            "lib/insecurity.ts::generateCoupon": _sample("generateCoupon", code="z85.encode(x)"),
            "lib/insecurity.ts::discountFromCoupon": _sample(
                "discountFromCoupon", start=20, end=30, code="z85.decode(c)"),
        }

    def test_every_member_body_is_included(self):
        prompt = format_group_prompt(self.group, self.by_id)
        assert "z85.encode(x)" in prompt
        assert "z85.decode(c)" in prompt

    def test_rationale_and_line_numbers_travel_with_it(self):
        prompt = format_group_prompt(self.group, self.by_id)
        assert "one mints, one accepts" in prompt
        assert "lines 20–30" in prompt

    def test_system_prompt_forbids_repeating_per_function_findings(self):
        """Duplicating the per-function pass would inflate the flow pass's
        apparent yield with findings it did not contribute."""
        from src.agent.flow_pass import FLOW_SYSTEM

        text = " ".join(FLOW_SYSTEM.split())
        assert "Do NOT repeat per-function defects" in text
        assert "report nothing" in text

    def test_system_prompt_names_the_unkeyed_encoding_pattern(self):
        from src.agent.flow_pass import FLOW_SYSTEM

        text = " ".join(FLOW_SYSTEM.lower().split())
        assert "reversible or unkeyed encoding" in text


class TestParsing:

    def setup_method(self):
        self.group = fg.FlowGroup(
            kind="producer_consumer", label="coupon",
            node_ids=["lib/insecurity.ts::generateCoupon", "lib/insecurity.ts::discountFromCoupon"],
        )
        self.by_id = {
            "lib/insecurity.ts::generateCoupon": _sample("generateCoupon"),
            "lib/insecurity.ts::discountFromCoupon": _sample("discountFromCoupon", start=20, end=30),
        }
        self.flow = FlowPass.__new__(FlowPass)

    def test_finding_is_filed_against_the_attributed_function(self):
        report = self.flow._to_report(
            {"attributed_to": "lib/insecurity.ts::generateCoupon",
             "also_implicates": ["lib/insecurity.ts::discountFromCoupon"],
             "cwe_id": "CWE-345", "severity": "high", "explanation": "e",
             "confidence": 0.8},
            self.group, self.by_id,
        )
        assert report.function_name == "generateCoupon"
        assert report.cwe_id == "CWE-345"
        assert report.also_implicates == ["lib/insecurity.ts::discountFromCoupon"]

    def test_mode_is_recorded_separately(self):
        """Flow findings must be distinguishable, or a negative result for this
        stage cannot be told from the rest of the run."""
        report = self.flow._to_report(
            {"attributed_to": "generateCoupon", "cwe_id": "CWE-345", "explanation": "e"},
            self.group, self.by_id,
        )
        assert report.analysis_mode == "flow_pass"

    def test_bare_function_name_resolves_within_the_group(self):
        report = self.flow._to_report(
            {"attributed_to": "discountFromCoupon", "cwe_id": "CWE-345", "explanation": "e"},
            self.group, self.by_id,
        )
        assert report.function_name == "discountFromCoupon"

    def test_a_finding_naming_nothing_in_the_group_is_dropped(self):
        """A flow finding pointing outside the prompt is not evidence about
        anything the model was shown."""
        assert self.flow._to_report(
            {"attributed_to": "some/other.ts::unrelated", "cwe_id": "CWE-345",
             "explanation": "e"},
            self.group, self.by_id,
        ) is None

    def test_a_finding_with_no_attribution_is_dropped(self):
        """Unscoreable against any row, and an unscoreable finding is not a result."""
        assert self.flow._to_report(
            {"cwe_id": "CWE-345", "explanation": "e"}, self.group, self.by_id
        ) is None

    def test_implicates_are_capped(self):
        report = self.flow._to_report(
            {"attributed_to": "generateCoupon",
             "also_implicates": [f"a.ts::f{i}" for i in range(10)],
             "cwe_id": "CWE-345", "explanation": "e"},
            self.group, self.by_id,
        )
        from src.llm.attribution import MAX_IMPLICATED

        assert len(report.also_implicates) <= MAX_IMPLICATED

    def test_malformed_entry_does_not_raise(self):
        assert self.flow._to_report("not a dict", self.group, self.by_id) is None
