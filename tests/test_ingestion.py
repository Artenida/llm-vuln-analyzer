"""
Tests for Phase 1 — ingestion layer.

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_ingestion.py -v
"""
import sys
from pathlib import Path

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.ingestion.parser import TreeSitterParser
from src.ingestion.extractor import CodeExtractor
from src.models import Language


# ── fixtures ──────────────────────────────────────────────────────────────────

PYTHON_CODE = '''\
def add(a, b):
    return a + b

async def fetch_data(url):
    response = await client.get(url)
    return response.json()

class MyClass:
    def method(self):
        pass
'''

JS_CODE = '''\
function greet(name) {
    return "Hello " + name;
}

const getUserById = (id) => {
    return db.query("SELECT * FROM users WHERE id = ?", [id]);
};

function buildQuery(username) {
    return "SELECT * FROM users WHERE name = '" + username + "'";
}
'''

C_CODE = '''\
int add(int a, int b) {
    return a + b;
}

void process(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}
'''

MALFORMED_CODE = "def broken( this is not valid python !!!"


# ── parser tests ──────────────────────────────────────────────────────────────

class TestTreeSitterParser:

    def setup_method(self):
        self.parser = TreeSitterParser(max_function_lines=200)

    def test_parse_python_returns_tree(self):
        tree = self.parser.parse(PYTHON_CODE, "python")
        assert tree is not None
        assert tree.root_node.type == "module"

    def test_parse_javascript_returns_tree(self):
        tree = self.parser.parse(JS_CODE, "javascript")
        assert tree is not None
        assert tree.root_node.type == "program"

    def test_parse_c_returns_tree(self):
        tree = self.parser.parse(C_CODE, "c")
        assert tree is not None

    def test_parse_unknown_language_returns_none(self):
        tree = self.parser.parse("some code", "cobol")
        assert tree is None

    def test_extract_python_functions(self):
        fns = self.parser.extract_functions(PYTHON_CODE, "python")
        names = [f.name for f in fns]
        assert "add" in names
        assert "fetch_data" in names
        # class method should NOT appear at top level in our extractor
        # (we only extract top-level functions)

    def test_extract_javascript_functions(self):
        fns = self.parser.extract_functions(JS_CODE, "javascript")
        names = [f.name for f in fns]
        assert "greet" in names
        assert "buildQuery" in names

    def test_extract_c_functions(self):
        fns = self.parser.extract_functions(C_CODE, "c")
        names = [f.name for f in fns]
        assert "add" in names
        assert "process" in names

    def test_function_body_contains_code(self):
        fns = self.parser.extract_functions(PYTHON_CODE, "python")
        add_fn = next(f for f in fns if f.name == "add")
        assert "return a + b" in add_fn.body

    def test_start_and_end_lines_are_set(self):
        fns = self.parser.extract_functions(PYTHON_CODE, "python")
        for fn in fns:
            assert fn.start_line >= 1
            assert fn.end_line >= fn.start_line

    def test_malformed_python_returns_empty_not_crash(self):
        fns = self.parser.extract_functions(MALFORMED_CODE, "python")
        # may return empty list or partial — must not raise
        assert isinstance(fns, list)

    def test_max_function_lines_respected(self):
        long_fn = "def long_function():\n" + "    pass\n" * 300
        parser = TreeSitterParser(max_function_lines=50)
        fns = parser.extract_functions(long_fn, "python")
        assert len(fns) == 0, "Function over line limit should be skipped"

    def test_empty_file_returns_empty_list(self):
        fns = self.parser.extract_functions("", "python")
        assert fns == []

    def test_supported_languages_not_empty(self):
        assert len(self.parser.supported_languages) > 0


# ── extractor tests ───────────────────────────────────────────────────────────

class TestCodeExtractor:

    def setup_method(self):
        self.extractor = CodeExtractor(max_function_lines=200)

    def test_from_snippet_python(self):
        samples = self.extractor.from_snippet(PYTHON_CODE, "python")
        assert len(samples) >= 2
        names = [s.function_name for s in samples]
        assert "add" in names

    def test_from_snippet_javascript(self):
        samples = self.extractor.from_snippet(JS_CODE, "javascript")
        assert len(samples) >= 2
        names = [s.function_name for s in samples]
        assert "greet" in names

    def test_from_snippet_unknown_language_returns_empty(self):
        samples = self.extractor.from_snippet("some code", "cobol")
        assert samples == []

    def test_from_snippet_sets_language(self):
        samples = self.extractor.from_snippet(PYTHON_CODE, "python")
        for s in samples:
            assert s.language == Language.PYTHON

    def test_from_snippet_sets_file_path(self):
        samples = self.extractor.from_snippet(PYTHON_CODE, "python")
        for s in samples:
            assert s.file_path == "<snippet>"

    def test_from_file_python(self, tmp_path):
        f = tmp_path / "example.py"
        f.write_text(PYTHON_CODE)
        samples = self.extractor.from_path(f)
        assert len(samples) >= 2
        assert samples[0].language == Language.PYTHON
        assert samples[0].file_path == str(f)

    def test_from_file_javascript(self, tmp_path):
        f = tmp_path / "example.js"
        f.write_text(JS_CODE)
        samples = self.extractor.from_path(f)
        names = [s.function_name for s in samples]
        assert "greet" in names

    def test_from_directory_walks_all_files(self, tmp_path):
        (tmp_path / "a.py").write_text(PYTHON_CODE)
        (tmp_path / "b.js").write_text(JS_CODE)
        samples = self.extractor.from_path(tmp_path)
        languages = {s.language for s in samples}
        assert Language.PYTHON in languages
        assert Language.JAVASCRIPT in languages

    def test_from_directory_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules"
        nm.mkdir()
        (nm / "lib.js").write_text(JS_CODE)
        (tmp_path / "main.js").write_text(JS_CODE)
        samples = self.extractor.from_path(tmp_path)
        for s in samples:
            assert "node_modules" not in (s.file_path or "")

    def test_from_directory_skips_unknown_extensions(self, tmp_path):
        (tmp_path / "readme.md").write_text("# nothing")
        (tmp_path / "app.py").write_text(PYTHON_CODE)
        samples = self.extractor.from_path(tmp_path)
        for s in samples:
            assert s.language != Language.UNKNOWN

    def test_nonexistent_path_raises(self):
        with pytest.raises(FileNotFoundError):
            self.extractor.from_path("/nonexistent/path/file.py")

    def test_samples_have_line_numbers(self, tmp_path):
        f = tmp_path / "code.py"
        f.write_text(PYTHON_CODE)
        samples = self.extractor.from_path(f)
        for s in samples:
            assert s.start_line is not None
            assert s.end_line is not None
            assert s.end_line >= s.start_line


# ── integration: auth service ────────────────────────────────────────────────

class TestAuthServiceExtraction:
    """
    Tests against the real test_apps/auth_service fixture.
    These confirm the extractor works on the actual files we will analyze.
    """

    def setup_method(self):
        self.extractor = CodeExtractor()
        self.auth_path = (
            Path(__file__).parent.parent
            / "test_apps" / "auth_service" / "auth_service.js"
        )

    def test_auth_file_exists(self):
        if not self.auth_path.exists():
            pytest.skip(f"Auth service fixture not found: {self.auth_path}")

    def test_extracts_expected_functions(self):
        if not self.auth_path.exists():
            pytest.skip("auth_service.js not found")
        samples = self.extractor.from_path(self.auth_path)
        names = [s.function_name for s in samples]
        expected = [
            "getUserByUsername", "generateToken", "verifyPassword",
            "getAdminData", "loginError", "getUserById",
        ]
        for name in expected:
            assert name in names, f"Expected function '{name}' not found. Got: {names}"

    def test_extracts_correct_count(self):
        if not self.auth_path.exists():
            pytest.skip("auth_service.js not found")
        samples = self.extractor.from_path(self.auth_path)
        assert len(samples) == 6, f"Expected 6 functions, got {len(samples)}"

    def test_function_bodies_not_empty(self):
        if not self.auth_path.exists():
            pytest.skip("auth_service.js not found")
        samples = self.extractor.from_path(self.auth_path)
        for s in samples:
            assert len(s.code.strip()) > 0


# ── integration: billing service ─────────────────────────────────────────────

class TestBillingServiceExtraction:

    def setup_method(self):
        self.extractor = CodeExtractor()
        self.billing_path = (
            Path(__file__).parent.parent
            / "test_apps" / "billing_service" / "billing_service.js"
        )

    def test_billing_file_exists(self):
        if not self.billing_path.exists():
            pytest.skip(f"Billing service fixture not found: {self.billing_path}")

    def test_extracts_expected_functions(self):
        if not self.billing_path.exists():
            pytest.skip("billing_service.js not found")
        samples = self.extractor.from_path(self.billing_path)
        names = [s.function_name for s in samples]
        expected = [
            "getInvoiceFile", "getInvoice", "applyDiscount",
            "getTransactionsByUser", "getPaymentDetails", "applyValidatedDiscount",
        ]
        for name in expected:
            assert name in names, f"Expected '{name}' not found. Got: {names}"

    def test_extracts_correct_count(self):
        if not self.billing_path.exists():
            pytest.skip("billing_service.js not found")
        samples = self.extractor.from_path(self.billing_path)
        assert len(samples) == 6