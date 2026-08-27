"""The taxonomy is referenced from four places. These assert they agree.

Every failure this file can produce has already happened once:

  - the ReAct prompt listed 18 CWEs and the single-pass prompt 7, so the two
    analysis modes were compared as though they differed only in tool access
    (repaired in Stage 4, and the reason `taxonomy.py` exists at all);
  - `evidence_gate.FLOW_CWES` demanded a declared source for CWE-22, CWE-611 and
    CWE-918, three classes `CWE_TAXONOMY_PROMPT` never offered, so findings were
    gated against a rule the model was never given (repaired 2026-08-27);
  - the severity table omitted classes the taxonomy listed, leaving the model to
    invent a severity for them.

None of these is detectable by reading one file, which is why they survived. A
test is the only place the invariant can live.
"""
import re

import pytest

from src.llm.evidence_gate import FLOW_CWES
from src.llm.taxonomy import (
    ADDED_IN_STAGE_4,
    ADDED_IN_TAXONOMY_REPAIR,
    CWE_TAXONOMY_PROMPT,
    SEVERITY_RULES_PROMPT,
)

_CWE = re.compile(r"CWE-\d+")


def taxonomy_cwes() -> set:
    return set(_CWE.findall(CWE_TAXONOMY_PROMPT))


def test_every_flow_cwe_is_offered_by_the_prompt():
    missing = FLOW_CWES - taxonomy_cwes()
    assert not missing, (
        f"{sorted(missing)} are gated as flow CWEs but never offered to the model. "
        "Either add them to CWE_TAXONOMY_PROMPT or remove them from FLOW_CWES."
    )


def test_every_taxonomy_cwe_has_a_severity():
    severities = set(_CWE.findall(SEVERITY_RULES_PROMPT))
    missing = taxonomy_cwes() - severities
    assert not missing, f"{sorted(missing)} have no severity rule, so the model must guess"


def test_severity_rules_do_not_cover_classes_the_taxonomy_dropped():
    # The reverse direction: a severity entry for a class no longer offered is
    # dead text in every prompt, and the next person to read it will assume the
    # class is available.
    stale = set(_CWE.findall(SEVERITY_RULES_PROMPT)) - taxonomy_cwes()
    assert not stale, f"{sorted(stale)} have a severity but are not in the taxonomy"


def test_no_cwe_is_listed_at_two_severities():
    high, medium = SEVERITY_RULES_PROMPT.split("medium", 1)
    both = set(_CWE.findall(high)) & set(_CWE.findall(medium))
    assert not both, f"{sorted(both)} appear at more than one severity"


@pytest.mark.parametrize("added", sorted(ADDED_IN_STAGE_4 | ADDED_IN_TAXONOMY_REPAIR))
def test_recorded_additions_are_actually_in_the_prompt(added):
    # These sets exist so a re-run's new false positives can be attributed per
    # class. A set naming a class the prompt does not offer would misattribute
    # them silently.
    assert added in taxonomy_cwes()


def test_the_repair_set_matches_what_the_repair_added():
    # Guards against the set and the prompt text being edited apart. If a class
    # is deliberately rolled back, remove it from both.
    assert ADDED_IN_TAXONOMY_REPAIR == {
        "CWE-22", "CWE-352", "CWE-601", "CWE-602",
        "CWE-611", "CWE-807", "CWE-918", "CWE-1427",
    }


def test_the_two_addition_sets_do_not_overlap():
    assert not (ADDED_IN_STAGE_4 & ADDED_IN_TAXONOMY_REPAIR)
