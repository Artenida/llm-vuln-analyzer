"""
Tests for Sprint 3 — patch generation & validation.

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_patching.py -v
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.results.patch_generator import PatchGenerator
from src.results.patch_validator import PatchValidator


# ── PatchValidator ──────────────────────────────────────────────────────────

PY_ORIGINAL = '''\
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return db.execute(query)
'''

PY_DIFF_VALID = '''\
--- a/get_user
+++ b/get_user
@@ -1,3 +1,3 @@
 def get_user(user_id):
-    query = "SELECT * FROM users WHERE id = " + user_id
-    return db.execute(query)
+    query = "SELECT * FROM users WHERE id = ?"
+    return db.execute(query, (user_id,))
'''

# context lines shifted / reformatted slightly — should still resolve via fuzzy match
PY_DIFF_DRIFTED = '''\
--- a/get_user
+++ b/get_user
@@ -1,3 +1,3 @@
 def get_user(user_id):
-   query = "SELECT * FROM users WHERE id = " + user_id
-   return db.execute(query)
+   query = "SELECT * FROM users WHERE id = ?"
+   return db.execute(query, (user_id,))
'''

PY_DIFF_BROKEN_SYNTAX = '''\
--- a/get_user
+++ b/get_user
@@ -1,3 +1,3 @@
 def get_user(user_id):
-    query = "SELECT * FROM users WHERE id = " + user_id
+    query = "SELECT * FROM users WHERE id = ?
     return db.execute(query)
'''


def test_validator_applies_clean_diff():
    validator = PatchValidator()
    result = validator.validate(PY_ORIGINAL, PY_DIFF_VALID, "python")

    assert result.valid is True
    assert result.error is None
    assert "?" in result.patched_code
    assert "db.execute(query, (user_id,))" in result.patched_code


def test_validator_tolerates_context_drift_via_fuzzy_match():
    validator = PatchValidator()
    result = validator.validate(PY_ORIGINAL, PY_DIFF_DRIFTED, "python")

    assert result.valid is True
    assert "db.execute(query, (user_id,))" in result.patched_code


def test_validator_rejects_empty_diff():
    validator = PatchValidator()
    result = validator.validate(PY_ORIGINAL, "", "python")

    assert result.valid is False
    assert result.error == "empty_diff"


def test_validator_rejects_unresolvable_hunk():
    validator = PatchValidator()
    bogus_diff = (
        "--- a/x\n+++ b/x\n@@ -1,2 +1,2 @@\n"
        " this line does not exist anywhere\n-neither does this\n+nor this\n"
    )
    result = validator.validate(PY_ORIGINAL, bogus_diff, "python")

    assert result.valid is False
    assert result.error == "hunk_context_not_found"


def test_validator_flags_syntax_error_after_patch():
    validator = PatchValidator()
    result = validator.validate(PY_ORIGINAL, PY_DIFF_BROKEN_SYNTAX, "python")

    assert result.valid is False
    assert result.error == "syntax_error_after_patch"
    assert result.patched_code is not None  # patch applied, but produced invalid syntax


def test_validator_never_touches_original_string():
    # the in-memory original_code argument must not be mutated
    original_copy = PY_ORIGINAL
    validator = PatchValidator()
    validator.validate(PY_ORIGINAL, PY_DIFF_VALID, "python")

    assert PY_ORIGINAL == original_copy


# ── PatchGenerator (mocked LLM client) ──────────────────────────────────────

def _make_generator_with_response(content: str) -> PatchGenerator:
    generator = PatchGenerator(api_key="test-key", model="test-model")
    mock_response = MagicMock()
    mock_response.choices = [MagicMock(message=MagicMock(content=content))]
    generator.client.chat.completions.create = MagicMock(return_value=mock_response)
    return generator


def test_generator_strips_markdown_fences():
    generator = _make_generator_with_response(f"```diff\n{PY_DIFF_VALID}\n```")

    result = generator.generate(
        code=PY_ORIGINAL,
        explanation="SQL injection via string concatenation",
        cwe_id="CWE-89",
        function_name="get_user",
        language="python",
    )

    assert result.error is None
    assert not result.unified_diff.startswith("```")
    assert "db.execute(query, (user_id,))" in result.unified_diff


def test_generator_flags_empty_response():
    generator = _make_generator_with_response("   ")

    result = generator.generate(
        code=PY_ORIGINAL,
        explanation="SQL injection",
        cwe_id="CWE-89",
        function_name="get_user",
        language="python",
    )

    assert result.unified_diff == ""
    assert result.error == "empty_llm_response"


def test_generator_requires_api_key():
    with pytest.raises(EnvironmentError):
        PatchGenerator(api_key="")
