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
        """Over the limit, the function is no longer analysed whole — it is
        sliced. Nothing named `long_function` itself is returned."""
        long_fn = "def long_function():\n" + "    pass\n" * 300
        parser = TreeSitterParser(max_function_lines=50)
        fns = parser.extract_functions(long_fn, "python")
        assert "long_function" not in [f.name for f in fns]
        assert all(f.chunk_of == "long_function" for f in fns)
        assert parser.last_skipped[0].chunked

    def test_chunking_can_be_turned_off(self):
        """The previous behaviour stays one setting away, so the two are
        directly comparable."""
        long_fn = "def long_function():\n" + "    pass\n" * 300
        parser = TreeSitterParser(max_function_lines=50, chunk_oversized=False)
        fns = parser.extract_functions(long_fn, "python")
        assert len(fns) == 0
        assert parser.last_skipped[0].chunked is False

    def test_oversized_function_is_reported_not_silently_dropped(self):
        """An unreported skip shrinks the denominator of every coverage and
        recall number, without anything in the output saying so."""
        long_fn = "def long_function():\n" + "    pass\n" * 300
        parser = TreeSitterParser(max_function_lines=50)
        parser.extract_functions(long_fn, "python")

        assert len(parser.last_skipped) == 1
        sk = parser.last_skipped[0]
        assert sk.name == "long_function"
        assert sk.line_count == 301

    def test_last_skipped_resets_between_calls(self):
        long_fn = "def long_function():\n" + "    pass\n" * 300
        parser = TreeSitterParser(max_function_lines=50)
        parser.extract_functions(long_fn, "python")
        parser.extract_functions("def small():\n    return 1\n", "python")

        assert parser.last_skipped == [], "stale skips must not leak into the next file"

    def test_empty_file_returns_empty_list(self):
        fns = self.parser.extract_functions("", "python")
        assert fns == []

    def test_supported_languages_not_empty(self):
        assert len(self.parser.supported_languages) > 0

    # ── nested-method masking (constructor/factory wrapper attribution fix) ──

    NESTED_WRAPPER_JS = '''\
var AllocationsDAO = function(db) {
    this.getByUserIdAndThreshold = function(userId, threshold, callback) {
        var searchCriteria = function() {
            return { $where: "this.userId == " + userId + " && this.stocks > " + threshold };
        };
        var criteria = searchCriteria();
        db.collection("allocations").find(criteria).toArray(callback);
    };

    this.update = function(userId, stocks, callback) {
        db.collection("allocations").update({userId: userId}, {$set: stocks}, callback);
    };
};
'''

    def test_wrapper_body_masks_nested_method_source(self):
        fns = self.parser.extract_functions(self.NESTED_WRAPPER_JS, "javascript")
        by_name = {f.name: f for f in fns}

        assert "AllocationsDAO" in by_name
        wrapper_body = by_name["AllocationsDAO"].body
        assert "$where" not in wrapper_body
        assert "nested method 'this.getByUserIdAndThreshold' analyzed separately" in wrapper_body
        assert "nested method 'this.update' analyzed separately" in wrapper_body

    def test_nested_method_keeps_its_own_full_source(self):
        fns = self.parser.extract_functions(self.NESTED_WRAPPER_JS, "javascript")
        by_name = {f.name: f for f in fns}

        assert "$where" in by_name["searchCriteria"].body
        # the direct caller sees its own logic, but not the deeper nested builder's internals
        caller_body = by_name["this.getByUserIdAndThreshold"].body
        assert "searchCriteria()" in caller_body
        assert "$where" not in caller_body
        assert "nested method 'searchCriteria' analyzed separately" in caller_body

    def test_masking_preserves_line_numbers(self):
        fns = self.parser.extract_functions(self.NESTED_WRAPPER_JS, "javascript")
        by_name = {f.name: f for f in fns}

        wrapper = by_name["AllocationsDAO"]
        assert wrapper.body.count("\n") == wrapper.end_line - wrapper.start_line
        # sibling `this.update` (not itself nested-in-nested) is untouched by masking
        assert "$set" in by_name["this.update"].body


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

    def test_skipped_functions_exposed_with_file_path(self, tmp_path):
        f = tmp_path / "big.py"
        f.write_text("def small():\n    return 1\n\n"
                     "def big():\n" + "    pass\n" * 300)
        extractor = CodeExtractor(max_function_lines=50, chunk_oversized=False)
        samples = extractor.from_path(f)

        assert [s.function_name for s in samples] == ["small"]
        assert len(extractor.skipped_functions) == 1
        sk = extractor.skipped_functions[0]
        assert sk.name == "big"
        assert sk.file_path.endswith("big.py"), "skips must be attributable to a file"

    def test_skipped_functions_reset_between_runs(self, tmp_path):
        big = tmp_path / "big.py"
        big.write_text("def big():\n" + "    pass\n" * 300)
        clean = tmp_path / "clean.py"
        clean.write_text("def small():\n    return 1\n")

        extractor = CodeExtractor(max_function_lines=50)
        extractor.from_path(big)
        extractor.from_path(clean)

        assert extractor.skipped_functions == []


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

# ── route extraction ──────────────────────────────────────────────────────────

from src.ingestion.route_extractor import RouteExtractor  # noqa: E402


EXPRESS_CODE = '''\
function configureApp (app) {
  app.use(compression())
  app.use('/rest/basket/:id', security.isAuthorized())
  app.get('/api/Addresss', security.appendUserId(), utils.asyncHandler(address.getAddress()))
  app.delete('/api/Addresss/:id', security.appendUserId(), utils.asyncHandler(address.delAddressById()))
  app.post('/file-upload', ensureFileIsPassed, checkFileType, handleXmlUpload)
  app.get(['/.well-known/security.txt', '/security.txt'], verify.accessControlChallenges())
  app.use('/api/Quantitys/:id', security.isAccounting(), IpFilter(['123.456.789'], { mode: 'allow' }))
  app.use((req, res, next) => { next() })
  router.get('/legacy', legacyHandler)
  swaggerUi.serve(somethingElse)
  helmet.frameguard()
}
'''


class TestRouteExtraction:

    def setup_method(self):
        self.rx = RouteExtractor()
        self.routes = self.rx.extract(EXPRESS_CODE, "typescript")

    def _by_path(self, path, method=None):
        return [
            r for r in self.routes
            if r.path == path and (method is None or r.method == method)
        ]

    def test_extracts_app_registrations_not_just_router(self):
        """The old regex only matched `router.` — juice-shop registers 171
        routes as `app.`, so the route table came out empty."""
        methods = {(r.method, r.path) for r in self.routes}
        assert ("GET", "/api/Addresss") in methods
        assert ("GET", "/legacy") in methods

    def test_handler_order_is_preserved(self):
        """Order is the point: a guard registered before a handler has already
        run by the time the handler sees the request."""
        route = self._by_path("/api/Addresss", "GET")[0]
        assert route.handlers == [
            "security.appendUserId()",
            "utils.asyncHandler(address.getAddress())",
        ]
        assert route.middleware == ["security.appendUserId()"]

    def test_wrapped_handler_name_is_recovered(self):
        """`utils.asyncHandler(address.getAddress())` must resolve to getAddress,
        or the registration can never be matched to the function it invokes."""
        route = self._by_path("/api/Addresss", "GET")[0]
        assert route.handler_names == ["appendUserId", "asyncHandler", "getAddress"]

    def test_receiver_is_not_mistaken_for_a_handler(self):
        """`address` in `address.getAddress()` is a module object, not a handler."""
        route = self._by_path("/api/Addresss", "GET")[0]
        assert "address" not in route.handler_names
        assert "security" not in route.handler_names
        assert "utils" not in route.handler_names

    def test_comma_inside_an_argument_does_not_split_a_handler(self):
        """The old `args.split(',')` broke on any comma inside a call argument."""
        route = self._by_path("/api/Quantitys/:id", "USE")[0]
        assert route.handlers == [
            "security.isAccounting()",
            "IpFilter(['123.456.789'], { mode: 'allow' })",
        ]

    def test_bare_identifier_handlers(self):
        route = self._by_path("/file-upload", "POST")[0]
        assert route.handlers == ["ensureFileIsPassed", "checkFileType", "handleXmlUpload"]
        assert route.handler_names == ["ensureFileIsPassed", "checkFileType", "handleXmlUpload"]

    def test_prefix_guard_detection(self):
        guard = self._by_path("/rest/basket/:id", "USE")[0]
        assert guard.is_prefix_guard
        assert guard.middleware == ["security.isAuthorized()"]

        endpoint = self._by_path("/api/Addresss", "GET")[0]
        assert not endpoint.is_prefix_guard

    def test_global_middleware_has_no_path(self):
        globals_ = [r for r in self.routes if r.method == "USE" and not r.path]
        raws = [h for r in globals_ for h in r.handlers]
        assert "compression()" in raws
        # A registration with no mount path guards everything, so it is not a
        # prefix guard and must not be reported as one.
        assert all(not r.is_prefix_guard for r in globals_)

    def test_array_of_paths(self):
        route = [r for r in self.routes if "security.txt" in r.path][0]
        assert route.path == "/.well-known/security.txt, /security.txt"
        assert route.handler_names == ["accessControlChallenges"]

    def test_inline_middleware_is_collapsed_but_kept(self):
        """An anonymous arrow occupies a position in the chain; keeping it keeps
        the positions honest, collapsing it keeps it out of the prompt."""
        inline = [r for r in self.routes if "<inline middleware>" in r.handlers]
        assert len(inline) == 1

    def test_non_router_objects_are_ignored(self):
        objects_seen = {r.path for r in self.routes}
        assert not any("somethingElse" in p for p in objects_seen)
        raws = [h for r in self.routes for h in r.handlers]
        assert "somethingElse" not in raws

    def test_source_line_recorded(self):
        route = self._by_path("/api/Addresss", "GET")[0]
        assert EXPRESS_CODE.splitlines()[route.source_line - 1].strip().startswith(
            "app.get('/api/Addresss'"
        )

    def test_non_js_language_yields_nothing(self):
        assert self.rx.extract(EXPRESS_CODE, "c") == []

    def test_routes_survive_an_oversized_enclosing_function(self):
        """The whole point of Stage 1: juice-shop's route table lives inside a
        514-line function that the extractor skips, so routes must come from raw
        content rather than from extracted function bodies."""
        extractor = CodeExtractor(max_function_lines=2)
        samples = extractor.from_snippet(EXPRESS_CODE, Language.TYPESCRIPT)
        assert samples == [] or all(s.function_name != "configureApp" for s in samples)
        assert len(extractor.all_routes) >= 8


# ── chunking of oversized functions ───────────────────────────────────────────

EXPRESS_BIG = "function configureApp (app) {\n" + "".join(
    f"  app.get('/r{i}', handler{i})\n" for i in range(60)
) + "}\n"


class TestChunking:
    """juice-shop's server.ts::configureApp is 514 lines, over the limit, and
    holds the whole route table plus five project-marked vulnerable lines. It was
    the one function the extractor dropped."""

    def _chunks(self, max_lines=20):
        parser = TreeSitterParser(max_function_lines=max_lines)
        return parser, parser.extract_functions(EXPRESS_BIG, "typescript")

    def test_oversized_function_is_sliced(self):
        _, fns = self._chunks()
        assert len(fns) > 1
        assert all(f.chunk_of == "configureApp" for f in fns)

    def test_every_chunk_is_within_the_limit(self):
        _, fns = self._chunks(max_lines=20)
        for f in fns:
            assert f.end_line - f.start_line + 1 <= 20

    def test_chunks_are_numbered_and_know_the_total(self):
        _, fns = self._chunks()
        assert [f.chunk_index for f in fns] == list(range(1, len(fns) + 1))
        assert all(f.chunk_total == len(fns) for f in fns)

    def test_line_numbers_stay_file_relative(self):
        """run_saver clamps affected_lines to a sample's own range, so a chunk
        whose line numbers were relative to itself would have every finding
        clamped away."""
        _, fns = self._chunks()
        lines = EXPRESS_BIG.splitlines()
        for f in fns:
            assert lines[f.start_line - 1].strip() == f.body.splitlines()[0].strip()

    def test_chunks_do_not_overlap_and_stay_in_order(self):
        _, fns = self._chunks()
        for a, b in zip(fns, fns[1:]):
            assert a.end_line < b.start_line

    def test_chunks_carry_no_ast_node(self):
        """A chunk is a prompt unit, not a semantic function — it must not become
        a call-graph node asserting edges the source does not have."""
        _, fns = self._chunks()
        assert all(f.ast_node is None for f in fns)

    def test_skip_record_says_it_was_covered(self):
        parser, _ = self._chunks()
        sk = parser.last_skipped[0]
        assert sk.chunked is True
        assert sk.chunk_count > 1

    def test_a_body_with_one_huge_statement_is_left_skipped(self):
        """Nothing to split on. Emitting a single chunk identical to the function
        we already declined to analyse would just relabel the problem."""
        code = "function f () {\n  const x = {\n" + "    a: 1,\n" * 300 + "  }\n}\n"
        parser = TreeSitterParser(max_function_lines=20)
        fns = parser.extract_functions(code, "typescript")
        assert [f for f in fns if f.chunk_of] == []
        assert parser.last_skipped[0].chunked is False

    def test_chunks_reach_the_extractor_as_samples(self):
        extractor = CodeExtractor(max_function_lines=20)
        samples = extractor.from_snippet(EXPRESS_BIG, Language.TYPESCRIPT)
        chunks = [s for s in samples if s.is_chunk]
        assert chunks
        assert all(s.chunk_of == "configureApp" for s in chunks)

    def test_chunks_are_not_call_graph_nodes(self):
        from src.context.call_graph import CallGraphBuilder

        extractor = CodeExtractor(max_function_lines=20)
        samples = extractor.from_snippet(EXPRESS_BIG, Language.TYPESCRIPT)
        graph, _ = CallGraphBuilder().build(samples, routes=[])
        assert not any("#" in node_id for node_id in graph)

    def test_prompt_tells_the_model_it_is_seeing_a_part(self):
        from src.context.route_context import format_chunk_note

        extractor = CodeExtractor(max_function_lines=20)
        samples = extractor.from_snippet(EXPRESS_BIG, Language.TYPESCRIPT)
        chunk = next(s for s in samples if s.is_chunk)
        note = format_chunk_note(chunk)

        assert "PART OF A LARGER FUNCTION" in note
        assert f"part {chunk.chunk_index} of {chunk.chunk_total}" in note
        # The risk this stage introduces: a guard in chunk 1 protecting a route
        # in chunk 2 looks missing.
        assert "still in effect" in note

    def test_no_note_for_a_normal_function(self):
        from src.context.route_context import format_chunk_note

        extractor = CodeExtractor()
        sample = extractor.from_snippet(JS_CODE, Language.JAVASCRIPT)[0]
        assert format_chunk_note(sample) == ""
