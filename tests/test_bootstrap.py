"""
Tests for ground-truth scaffolding (src/evaluation/bootstrap.py).

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_bootstrap.py -v
"""
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.evaluation.bootstrap import (
    UNREVIEWED,
    build_ground_truth,
    changed_pre_image_ranges,
    save_ground_truth_skeleton,
)
from src.evaluation.ground_truth import load_ground_truth
from src.ingestion.extractor import CodeExtractor


PY_APP = '''\
def login(user, pw):
    return db.execute("SELECT * FROM u WHERE n='" + user + "'")


def helper(x):
    return x + 1
'''


def _extract(tmp_path):
    (tmp_path / "app.py").write_text(PY_APP, encoding="utf-8")
    extractor = CodeExtractor()
    samples = extractor.from_path(tmp_path)
    return samples, extractor.skipped_functions


# ── skeleton shape ───────────────────────────────────────────────────────────

def test_every_function_gets_a_row_defaulted_clean(tmp_path):
    """Precision is uncomputable unless clean functions are labelled too —
    findings with no ground truth row are excluded from the confusion matrix."""
    samples, skipped = _extract(tmp_path)
    payload = build_ground_truth(samples, skipped, tmp_path, "demo", str(tmp_path))

    names = {f["function_name"] for f in payload["functions"]}
    assert names == {"login", "helper"}
    assert all(f["vulnerable"] is False for f in payload["functions"])
    assert all(f["notes"] == UNREVIEWED for f in payload["functions"])


def test_cwe_and_severity_are_never_guessed(tmp_path):
    samples, skipped = _extract(tmp_path)
    payload = build_ground_truth(samples, skipped, tmp_path, "demo", str(tmp_path))

    for f in payload["functions"]:
        assert f["cwe_id"] is None
        assert f["severity"] is None


def test_paths_are_repo_relative(tmp_path):
    """The evaluator matches a finding by `finding.file_path.endswith(gt.file)`,
    so an absolute path here would never match."""
    samples, skipped = _extract(tmp_path)
    payload = build_ground_truth(samples, skipped, tmp_path, "demo", str(tmp_path))

    for f in payload["functions"]:
        assert f["file"] == "app.py"


def test_skeleton_is_loadable_by_the_evaluator(tmp_path):
    samples, skipped = _extract(tmp_path)
    payload = build_ground_truth(samples, skipped, tmp_path, "demo", str(tmp_path))
    out = tmp_path / "ground_truth.json"
    save_ground_truth_skeleton(payload, out)

    gt = load_ground_truth(out)
    assert gt.dataset == "demo"
    assert len(gt.entries) == 2
    assert gt.needs_curation is True, "an uncurated skeleton must announce itself"


def test_curated_file_is_not_flagged(tmp_path):
    samples, skipped = _extract(tmp_path)
    payload = build_ground_truth(samples, skipped, tmp_path, "demo", str(tmp_path))
    payload["curation_status"]["reviewed"] = True
    out = tmp_path / "ground_truth.json"
    save_ground_truth_skeleton(payload, out)

    assert load_ground_truth(out).needs_curation is False


def test_hand_written_ground_truth_has_no_curation_status(tmp_path):
    """Existing datasets predate this scaffolding and carry no curation_status —
    they must not be reported as needing curation."""
    out = tmp_path / "gt.json"
    out.write_text(json.dumps({
        "dataset": "legacy", "source_path": "x",
        "functions": [{"function_name": "f", "file": "a.py", "vulnerable": True}],
    }), encoding="utf-8")

    assert load_ground_truth(out).needs_curation is False


# ── overwrite protection ─────────────────────────────────────────────────────

def test_refuses_to_clobber_curated_labels(tmp_path):
    samples, skipped = _extract(tmp_path)
    payload = build_ground_truth(samples, skipped, tmp_path, "demo", str(tmp_path))
    out = tmp_path / "ground_truth.json"
    save_ground_truth_skeleton(payload, out)

    with pytest.raises(FileExistsError):
        save_ground_truth_skeleton(payload, out)

    save_ground_truth_skeleton(payload, out, force=True)  # explicit opt-in works


# ── coverage carried through ─────────────────────────────────────────────────

def test_oversized_functions_recorded_as_outside_metrics(tmp_path):
    (tmp_path / "big.py").write_text(
        "def small():\n    return 1\n\ndef big():\n" + "    pass\n" * 300,
        encoding="utf-8",
    )
    extractor = CodeExtractor(max_function_lines=50, chunk_oversized=False)
    samples = extractor.from_path(tmp_path)
    payload = build_ground_truth(
        samples, extractor.skipped_functions, tmp_path, "demo", str(tmp_path)
    )

    cov = payload["coverage"]
    assert cov["functions_skipped_oversized"] == 1
    assert cov["coverage"] == 0.5
    assert cov["skipped_oversized"][0]["function_name"] == "big"
    # and it must NOT appear as a scoreable row
    assert "big" not in {f["function_name"] for f in payload["functions"]}


def test_chunks_never_become_ground_truth_rows(tmp_path):
    """A skeleton row defaults to clean. Auto-generating rows for chunks would
    turn any finding inside one into a false positive against a label nobody
    read — the exact failure the full verification pass had to undo."""
    (tmp_path / "big.py").write_text(
        "def small():\n    return 1\n\ndef big():\n" + "    pass\n" * 300,
        encoding="utf-8",
    )
    extractor = CodeExtractor(max_function_lines=50)
    samples = extractor.from_path(tmp_path)
    payload = build_ground_truth(
        samples, extractor.skipped_functions, tmp_path, "demo", str(tmp_path)
    )

    names = {f["function_name"] for f in payload["functions"]}
    assert names == {"small"}
    assert not any("#" in n for n in names)

    cov = payload["coverage"]
    assert cov["functions_covered_as_chunks"] == 1
    assert cov["chunks_produced"] > 1
    # Coverage counts rows, so analysing a function as chunks must not raise it.
    assert cov["coverage"] == 0.5
    assert cov["skipped_oversized"][0]["chunked"] is True


# ── fix-commit pre-marking ───────────────────────────────────────────────────

def _git(repo: Path, *args: str):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


@pytest.fixture
def git_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "t@t.t")
    _git(repo, "config", "user.name", "t")
    (repo / "app.py").write_text(PY_APP, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "vulnerable")
    return repo


def test_fix_commit_pre_marks_only_the_touched_function(git_repo):
    # fix only the `login` function, leave `helper` untouched
    fixed = PY_APP.replace(
        'return db.execute("SELECT * FROM u WHERE n=\'" + user + "\'")',
        'return db.execute("SELECT * FROM u WHERE n=?", (user,))',
    )
    (git_repo / "app.py").write_text(fixed, encoding="utf-8")
    _git(git_repo, "commit", "-q", "-am", "fix sqli")
    sha = subprocess.run(["git", "-C", str(git_repo), "rev-parse", "HEAD"],
                         capture_output=True, text=True, check=True).stdout.strip()
    _git(git_repo, "checkout", "-q", "HEAD~1")   # back to the vulnerable state

    extractor = CodeExtractor()
    samples = extractor.from_path(git_repo)
    payload = build_ground_truth(
        samples, extractor.skipped_functions, git_repo, "demo", str(git_repo),
        fix_commits=[sha],
    )

    rows = {f["function_name"]: f for f in payload["functions"]}
    assert rows["login"]["vulnerable"] is True
    assert "REVIEW REQUIRED" in rows["login"]["notes"]
    assert rows["helper"]["vulnerable"] is False, "untouched function must stay clean"
    assert payload["curation_status"]["functions_prefilled_vulnerable"] == 1


def test_unknown_commit_degrades_to_all_clean(git_repo):
    extractor = CodeExtractor()
    samples = extractor.from_path(git_repo)
    payload = build_ground_truth(
        samples, extractor.skipped_functions, git_repo, "demo", str(git_repo),
        fix_commits=["deadbeefdeadbeef"],
    )
    assert all(f["vulnerable"] is False for f in payload["functions"])


def test_changed_pre_image_ranges_ignores_pure_insertions(git_repo):
    """A hunk that only adds lines has no pre-image range to blame."""
    (git_repo / "app.py").write_text(PY_APP + "\n\ndef added():\n    return 2\n",
                                     encoding="utf-8")
    _git(git_repo, "commit", "-q", "-am", "add function")
    sha = subprocess.run(["git", "-C", str(git_repo), "rev-parse", "HEAD"],
                         capture_output=True, text=True, check=True).stdout.strip()

    ranges = changed_pre_image_ranges(git_repo, sha)
    assert ranges.get("app.py", []) == []
