"""
Tests for applying a generated patch to the analysed project from the web UI.

This is the only code path in the tool that writes into a file the user did not
ask it to write, so the tests are weighted towards the refusals rather than the
happy path: a wrong write here silently corrupts someone's source tree, and the
corruption would look like a successful "fix".

Covered:
  * the happy path, byte for byte, leaving the rest of the file untouched
  * refusing a patch that failed the syntax check
  * refusing when the file changed after extraction (stale line numbers)
  * surviving line drift when an earlier patch moved the function
  * refusing a target outside the analysed project
  * indentation and CRLF preservation
  * revert restoring the original bytes
  * double-apply being rejected

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_patch_apply.py -v
"""
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.web import patch_apply  # noqa: E402
from src.web.patch_apply import ApplyError  # noqa: E402

ORIGINAL_FN = """function getOrder(req, res) {
  const order = db.find(req.params.id);
  res.json(order);
}"""

PATCHED_FN = """function getOrder(req, res) {
  const order = db.find(req.params.id);
  if (order.userId !== req.user.id) return res.sendStatus(403);
  res.json(order);
}"""

# A whole file, so the tests can assert that everything around the patched
# function is left exactly as it was.
FILE_BEFORE = f"""const db = require("./db");

{ORIGINAL_FN}

module.exports = {{ getOrder }};
"""

FUNCTION_START_LINE = 3


def write_exact(path: Path, text: str) -> None:
    """Write without newline translation.

    `Path.write_text` turns every `\\n` into `\\r\\n` on Windows, which would
    make the LF and CRLF cases below the same test on this platform and hide
    whichever one is broken.
    """
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def read_exact(path: Path) -> str:
    with open(path, "r", encoding="utf-8", newline="") as handle:
        return handle.read()


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    """A source project, a result bundle scoring it, and a throwaway UI state."""
    monkeypatch.setenv("VULN_ANALYZER_UI_STATE", str(tmp_path / "uistate"))

    source = tmp_path / "project"
    (source / "routes").mkdir(parents=True)
    target = source / "routes" / "orders.js"
    write_exact(target, FILE_BEFORE)

    run_dir = tmp_path / "results" / "run-1"
    run_dir.mkdir(parents=True)

    (run_dir / "analysis.json").write_text(json.dumps({
        "run_id": "run-1",
        "source_path": str(source),
        "findings": [],
    }), encoding="utf-8")

    (run_dir / "extraction.json").write_text(json.dumps({
        "metadata": {"source_path": str(source)},
        "results": [{
            "file_path": str(target),
            "function_name": "getOrder",
            "start_line": FUNCTION_START_LINE,
            "end_line": FUNCTION_START_LINE + 3,
            "language": "javascript",
            "code": ORIGINAL_FN,
        }],
    }), encoding="utf-8")

    (run_dir / "run-1_patches.json").write_text(json.dumps({
        "run_id": "run-1",
        "source_path": str(source),
        "patches": [{
            "function_name": "getOrder",
            "file_path": str(target),
            "cwe_id": "CWE-639",
            "severity": "high",
            "start_line": FUNCTION_START_LINE,
            "end_line": FUNCTION_START_LINE + 3,
            "unified_diff": "--- a\n+++ b\n",
            "patch_valid": True,
            "patch_error": None,
            "patched_code": PATCHED_FN,
        }],
    }), encoding="utf-8")

    return run_dir, target


def _apply(run_dir, target):
    return patch_apply.apply_patch(run_dir, str(target), "getOrder")


def _patch_doc(run_dir):
    return run_dir / "run-1_patches.json"


def _edit_patch(run_dir, **changes):
    path = _patch_doc(run_dir)
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["patches"][0].update(changes)
    path.write_text(json.dumps(doc), encoding="utf-8")


# ── the happy path ────────────────────────────────────────────────────────────


def test_apply_replaces_only_the_function(workspace):
    run_dir, target = workspace
    entry = _apply(run_dir, target)

    after = read_exact(target)
    assert after == FILE_BEFORE.replace(ORIGINAL_FN, PATCHED_FN)
    # Everything around the function survives untouched.
    assert after.startswith('const db = require("./db");')
    assert after.endswith("module.exports = { getOrder };\n")
    assert entry["state"] == "applied"
    assert entry["line"] == FUNCTION_START_LINE


def test_apply_is_journalled_for_the_ui(workspace):
    run_dir, target = workspace
    _apply(run_dir, target)

    status = patch_apply.status(run_dir)
    assert status["applied_count"] == 1
    assert status["entries"][0]["function_name"] == "getOrder"
    # The bytes on both sides are kept — that is what makes revert possible.
    assert status["entries"][0]["original_code"] == ORIGINAL_FN


def test_applying_twice_is_refused(workspace):
    run_dir, target = workspace
    _apply(run_dir, target)
    with pytest.raises(ApplyError, match="already patched"):
        _apply(run_dir, target)


# ── refusals ──────────────────────────────────────────────────────────────────


def test_an_invalid_patch_is_never_written(workspace):
    """`patch_valid` is the tree-sitter parse check — a diff that never parsed
    must not reach the user's file, whatever the UI sends."""
    run_dir, target = workspace
    _edit_patch(run_dir, patch_valid=False, patch_error="syntax error after patch")

    with pytest.raises(ApplyError, match="syntax check"):
        _apply(run_dir, target)
    assert read_exact(target) == FILE_BEFORE


def test_a_file_edited_since_the_run_is_refused(workspace):
    """The recorded line range would still point somewhere — at the wrong code."""
    run_dir, target = workspace
    write_exact(target, FILE_BEFORE.replace(
        "const order = db.find(req.params.id);",
        "const order = db.findOrFail(req.params.id);",
    ))
    before = read_exact(target)

    with pytest.raises(ApplyError, match="no longer matches"):
        _apply(run_dir, target)
    assert read_exact(target) == before


def test_a_target_outside_the_analysed_project_is_refused(workspace, tmp_path):
    """`file_path` reaches the request layer, so containment is not optional."""
    run_dir, target = workspace
    outsider = tmp_path / "elsewhere.js"
    write_exact(outsider, FILE_BEFORE)
    _edit_patch(run_dir, file_path=str(outsider))

    with pytest.raises(ApplyError, match="outside the analysed project"):
        patch_apply.apply_patch(run_dir, str(outsider), "getOrder")
    assert read_exact(outsider) == FILE_BEFORE


def test_an_unknown_function_is_refused(workspace):
    run_dir, target = workspace
    with pytest.raises(ApplyError, match="No generated patch"):
        patch_apply.apply_patch(run_dir, str(target), "noSuchFunction")


def test_an_ambiguous_body_is_refused_rather_than_guessed(workspace):
    """Two identical copies and a hint line that no longer matches either: there
    is no single correct place to write, so nothing is written."""
    run_dir, target = workspace
    target.write_text(f"// header\n{ORIGINAL_FN}\n\n{ORIGINAL_FN}\n", encoding="utf-8")
    before = read_exact(target)

    with pytest.raises(ApplyError, match="appears 2 times"):
        _apply(run_dir, target)
    assert read_exact(target) == before


# ── the awkward files ─────────────────────────────────────────────────────────


def test_line_drift_from_an_earlier_patch_is_absorbed(workspace):
    """Applying a patch above this one shifts every recorded line below it. The
    function is found by content, so the second apply still lands correctly."""
    run_dir, target = workspace
    write_exact(target, "// a new banner\n// added after extraction\n" + FILE_BEFORE)

    entry = _apply(run_dir, target)

    assert PATCHED_FN in read_exact(target)
    assert entry["line"] == FUNCTION_START_LINE + 2  # found where it actually is


def test_indentation_of_the_first_line_is_preserved(workspace):
    """tree-sitter records a node from its first column, so an indented method's
    extracted source has no leading indent on line one while the file does.
    Losing that indent would break the enclosing block — fatal in Python."""
    run_dir, target = workspace
    indented = f"class Orders {{\n  {ORIGINAL_FN}\n}}\n"
    write_exact(target, indented)
    _edit_patch(run_dir, start_line=2)

    _apply(run_dir, target)

    after = read_exact(target)
    assert after == f"class Orders {{\n  {PATCHED_FN}\n}}\n"
    assert after.startswith("class Orders {\n  function getOrder")


def test_crlf_files_do_not_become_mixed(workspace):
    """A CRLF file spliced with LF-only patched code shows up as a whole-file
    diff in the user's editor, burying the one change actually made."""
    run_dir, target = workspace
    with open(target, "w", encoding="utf-8", newline="") as handle:
        handle.write(FILE_BEFORE.replace("\n", "\r\n"))
    _edit_patch(run_dir, patched_code=PATCHED_FN)  # LF, as the model returns it

    doc = json.loads((run_dir / "extraction.json").read_text(encoding="utf-8"))
    doc["results"][0]["code"] = ORIGINAL_FN.replace("\n", "\r\n")
    (run_dir / "extraction.json").write_text(json.dumps(doc), encoding="utf-8")

    _apply(run_dir, target)

    after = read_exact(target)
    assert "\r\n" in after
    assert after.replace("\r\n", "\n").count("\n") == after.count("\r\n")


# ── revert ────────────────────────────────────────────────────────────────────


def test_revert_restores_the_original_bytes(workspace):
    run_dir, target = workspace
    _apply(run_dir, target)
    patch_apply.revert_patch(run_dir, str(target), "getOrder")

    assert read_exact(target) == FILE_BEFORE
    status = patch_apply.status(run_dir)
    assert status["applied_count"] == 0
    # Kept, not deleted: "applied and undone" is not the same as "never applied".
    assert status["entries"][0]["state"] == "reverted"


def test_revert_then_apply_again_works(workspace):
    run_dir, target = workspace
    _apply(run_dir, target)
    patch_apply.revert_patch(run_dir, str(target), "getOrder")
    _apply(run_dir, target)

    assert PATCHED_FN in read_exact(target)
    assert patch_apply.status(run_dir)["applied_count"] == 1


def test_reverting_something_never_applied_is_refused(workspace):
    run_dir, target = workspace
    with pytest.raises(ApplyError, match="not currently patched"):
        patch_apply.revert_patch(run_dir, str(target), "getOrder")


# ── through the API ───────────────────────────────────────────────────────────


@pytest.fixture()
def client(workspace, tmp_path, monkeypatch):
    monkeypatch.setenv("VULN_ANALYZER_EXPERIMENTS", str(tmp_path / "experiments"))
    from src.web import paths
    from src.web.app import create_app

    run_dir, target = workspace
    paths.register_root(run_dir)
    return TestClient(create_app()), run_dir, target


def test_endpoint_applies_and_reports_state(client):
    api, run_dir, target = client
    body = {"path": str(run_dir), "file_path": str(target), "function_name": "getOrder"}

    assert api.get("/api/results/patches/applied",
                   params={"path": str(run_dir)}).json()["applied_count"] == 0

    response = api.post("/api/results/patches/apply", json=body)
    assert response.status_code == 200
    assert response.json()["state"] == "applied"
    assert PATCHED_FN in read_exact(target)

    assert api.get("/api/results/patches/applied",
                   params={"path": str(run_dir)}).json()["applied_count"] == 1

    assert api.post("/api/results/patches/revert", json=body).status_code == 200
    assert read_exact(target) == FILE_BEFORE


def test_endpoint_reports_a_refusal_as_409_not_500(client):
    """A refusal is an answer, not a crash — the UI shows the reason verbatim."""
    api, run_dir, target = client
    response = api.post("/api/results/patches/apply", json={
        "path": str(run_dir), "file_path": str(target), "function_name": "ghost",
    })
    assert response.status_code == 409
    assert "No generated patch" in response.json()["detail"]


def test_endpoint_refuses_an_unregistered_result_directory(client, tmp_path):
    api, _, target = client
    response = api.post("/api/results/patches/apply", json={
        "path": str(tmp_path / "project"),
        "file_path": str(target),
        "function_name": "getOrder",
    })
    assert response.status_code == 400
    assert read_exact(target) == FILE_BEFORE
