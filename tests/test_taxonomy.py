"""The CWE taxonomy is shared, complete, and says what Stage 4 needs it to say.

Eight of the fifteen juice-shop misses are rows the ground truth itself tags
`taxonomy_scope: out_of_scope` — real vulnerabilities the tool had no label for.
Two of those the model described correctly and then returned clean, because there
was nowhere to put the observation.

Run with:
    python -m pytest tests/test_taxonomy.py -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.llm import taxonomy as tx


def _norm(text: str) -> str:
    """Prompts are hard-wrapped, so a phrase can straddle a line break."""
    return " ".join(text.lower().split())


class TestNewClasses:

    @pytest.mark.parametrize("cwe", sorted(tx.ADDED_IN_STAGE_4))
    def test_added_class_is_in_the_taxonomy(self, cwe):
        assert cwe in tx.CWE_TAXONOMY_PROMPT

    @pytest.mark.parametrize("cwe", sorted(tx.ADDED_IN_STAGE_4))
    def test_added_class_has_a_severity(self, cwe):
        """A class with no severity default gets an inconsistent one per finding."""
        assert cwe in tx.SEVERITY_RULES_PROMPT

    def test_cwe_345_describes_the_defect_the_model_already_saw(self):
        """generateCoupon: 'applies a reversible encoding ... no security-relevant
        issues'. It had the observation and no label."""
        text = _norm(tx.CWE_TAXONOMY_PROMPT)
        assert "reversible" in text
        assert "unkeyed" in text
        assert "mac or signature" in text

    def test_cwe_776_rules_out_the_timeout_excuse(self):
        """handleYamlUpload was excused as safe because it runs in a VM with a
        timeout. The memory is allocated before the timeout fires."""
        assert "timeout alone does not fix it" in _norm(tx.CWE_TAXONOMY_PROMPT)

    @pytest.mark.parametrize("cwe,narrowing", [
        ("CWE-345", "opaque random identifier"),
        ("CWE-425", "genuinely public"),
        ("CWE-776", "expansion is disabled or capped"),
        ("CWE-916", "cache key"),
        ("CWE-200", "explicitly masks"),
    ])
    def test_each_added_class_carries_narrowing_text(self, cwe, narrowing):
        """Every added class is a new way to be wrong. CWE-916 without narrowing
        matches any createHash call; CWE-425 matches any sendFile."""
        assert narrowing in _norm(tx.CWE_TAXONOMY_PROMPT)


class TestCWE347Rewrite:

    def test_no_longer_teaches_decode_versus_verify(self):
        """The old rule read 'jwt.decode vs jwt.verify'. updateAuthenticatedUsers
        calls jwt.verify without an algorithms option, so alg:none passes — the
        model applied the rule correctly and got the wrong answer."""
        assert "jwt.decode vs jwt.verify" not in tx.CWE_TAXONOMY_PROMPT

    def test_requires_a_pinned_algorithm_list(self):
        text = _norm(tx.CWE_TAXONOMY_PROMPT)
        assert "algorithm allowlist" in text
        assert "alg:none" in text

    def test_covers_library_version_behaviour(self):
        """lib/insecurity.ts::verify is only exploitable because of the pinned
        jws@0.2.6, which honours the token's own alg header."""
        assert "algorithm-confusion" in _norm(tx.CWE_TAXONOMY_PROMPT)

    def test_still_excludes_display_only_decoding(self):
        assert "display or logging is not cwe-347" in _norm(tx.CWE_TAXONOMY_PROMPT)


class TestFeatureFlagRule:

    def test_states_a_flagged_path_is_still_a_path(self):
        text = _norm(tx.FEATURE_FLAG_RULE)
        assert "still a code path" in text

    def test_rejects_each_excuse_the_model_actually_used(self):
        """product.ts::set - 'only active in challenge mode and not exposed in
        production'. saveLoginIp - 'intentional for testing'."""
        text = _norm(tx.FEATURE_FLAG_RULE)
        assert "off in production" in text
        assert "for testing" in text
        assert "deliberately planted vulnerability is still a vulnerability" in text


class TestSharedAcrossPrompts:

    def test_both_prompts_use_the_same_taxonomy(self):
        """These two lists had drifted to 18 CWEs and 7, so the modes could not
        be fairly compared."""
        from src.llm.client import _REACT_SYSTEM
        from src.cli import _build_context_prompt
        from src.agent.tools import ToolSet
        from src.models import CodeSample, Language

        sample = CodeSample(function_name="f", file_path="a.ts", code="x",
                            language=Language.TYPESCRIPT, start_line=1, end_line=2)
        single = _build_context_prompt(
            sample, {"callers": [], "callees": []}, ToolSet({}, {}), [sample]
        )

        for cwe in ["CWE-345", "CWE-425", "CWE-776", "CWE-916", "CWE-200", "CWE-639"]:
            assert cwe in _REACT_SYSTEM, f"{cwe} missing from ReAct prompt"
            assert cwe in single, f"{cwe} missing from single-pass prompt"

    def test_both_prompts_carry_the_feature_flag_rule(self):
        from src.llm.client import _REACT_SYSTEM
        from src.cli import _build_context_prompt
        from src.agent.tools import ToolSet
        from src.models import CodeSample, Language

        sample = CodeSample(function_name="f", file_path="a.ts", code="x",
                            language=Language.TYPESCRIPT, start_line=1, end_line=2)
        single = _build_context_prompt(
            sample, {"callers": [], "callees": []}, ToolSet({}, {}), [sample]
        )
        assert "still a code path" in _REACT_SYSTEM
        assert "still a code path" in single

    def test_no_duplicate_taxonomy_left_inline(self):
        """A hand-copied second list is how the drift happened the first time."""
        import inspect
        import src.cli as cli_module

        source = inspect.getsource(cli_module._build_context_prompt)
        assert "CWE-89   SQL/NoSQL built by string concat" not in source


class TestTaxonomyIntegrity:

    def test_every_severity_entry_exists_in_the_taxonomy(self):
        import re

        graded = set(re.findall(r"CWE-\d+", tx.SEVERITY_RULES_PROMPT))
        listed = set(re.findall(r"CWE-\d+", tx.CWE_TAXONOMY_PROMPT))
        assert graded <= listed, f"graded but not defined: {sorted(graded - listed)}"

    def test_every_defined_class_has_a_severity(self):
        import re

        listed = set(re.findall(r"CWE-\d+", tx.CWE_TAXONOMY_PROMPT))
        graded = set(re.findall(r"CWE-\d+", tx.SEVERITY_RULES_PROMPT))
        # CWE-290 appears only in a "do not use this" note.
        listed.discard("CWE-290")
        assert listed <= graded, f"defined but ungraded: {sorted(listed - graded)}"
