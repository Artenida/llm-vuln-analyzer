"""Ground-truth `summary` blocks must agree with their own rows.

The summary is hand-maintained while the rows are edited constantly, so it drifts
silently - juice-shop's read `vulnerable: 47` against 55 actual rows for months
after the verification pass. No metric depends on it (the evaluator reads
`functions[]`), but it is what gets quoted into a write-up, so a stale one is
worse than none.

Run with:
    python -m pytest tests/test_gt_summary.py -v
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from src.evaluation.ground_truth import compute_summary, recompute_present_keys

# `experiments/` is gitignored, so on a fresh clone there are no datasets to
# check. The derivation tests below still run; the drift guard has nothing to
# guard and skips.
DATASETS_DIR = Path(__file__).parent.parent / "experiments" / "datasets"


def _dataset_files() -> list:
    if not DATASETS_DIR.exists():
        return []
    return sorted(DATASETS_DIR.glob("*/ground_truth.json"))


# ── drift guard over the real datasets ────────────────────────────────────────

@pytest.mark.skipif(
    not _dataset_files(),
    reason="no datasets present (experiments/ is gitignored)",
)
@pytest.mark.parametrize(
    "gt_path", _dataset_files(), ids=lambda p: p.parent.name
)
def test_summary_matches_rows(gt_path):
    with open(gt_path, encoding="utf-8") as f:
        data = json.load(f)

    stored = data.get("summary")
    if not stored:
        pytest.skip(f"{gt_path.parent.name} has no summary block")

    updated, _unknown = recompute_present_keys(stored, data.get("functions", []))

    drifted = {
        key: {"stored": stored[key], "recomputed": updated[key]}
        for key in stored
        if stored[key] != updated[key]
    }
    assert not drifted, (
        f"{gt_path.parent.name}/ground_truth.json summary is stale:\n"
        + json.dumps(drifted, indent=2)
        + "\n\nRegenerate with:\n"
        f"  python experiments/scripts/regen_gt_summary.py {gt_path} --write"
    )


# ── the derivations themselves ────────────────────────────────────────────────

def test_compute_summary_counts_and_dedups():
    functions = [
        {"function_name": "a", "file": "x.ts", "vulnerable": True, "cwe_id": "CWE-89",
         "severity": "high", "source_lines": [1, 5], "taxonomy_scope": "in_scope"},
        # Same logical bug planted twice - collapses to one unique instance.
        {"function_name": "b", "file": "y.ts", "vulnerable": True, "cwe_id": "CWE-89",
         "severity": "high", "source_lines": [1, 5], "taxonomy_scope": "in_scope",
         "duplicate_of": "x.ts::a@1-5"},
        {"function_name": "c", "file": "z.ts", "vulnerable": True, "cwe_id": "CWE-22",
         "severity": "medium", "source_lines": [9, 12], "taxonomy_scope": "out_of_scope"},
        {"function_name": "d", "file": "z.ts", "vulnerable": False,
         "verification_status": "VERIFIED_CLEAN"},
        {"function_name": "e", "file": "z.ts", "vulnerable": False},
    ]

    s = compute_summary(functions)

    assert s["total_functions"] == 5
    assert s["vulnerable"] == 3
    assert s["clean"] == 2
    assert s["vulnerable_in_scope"] == 2
    assert s["vulnerable_out_of_scope"] == 1
    assert s["unique_cwe_instances"] == 2      # the duplicate collapsed
    assert s["duplicate_findings"] == 1
    assert s["by_cwe"] == {"CWE-22": 1, "CWE-89": 2}
    assert s["severity_distribution"] == {"high": 2, "medium": 1, "low": 0}


def test_scope_tagged_clean_rows_count_as_verified():
    """A row read, judged clean, then scope-tagged was still read. Counting only
    an exact "VERIFIED_CLEAN" would report the eight ctf_integrity rows as unread."""
    functions = [
        {"function_name": "a", "file": "x.ts", "vulnerable": False,
         "verification_status": "VERIFIED_CLEAN"},
        {"function_name": "b", "file": "x.ts", "vulnerable": False,
         "verification_status": "VERIFIED_CLEAN_OUT_OF_SCOPE_CTF"},
        {"function_name": "c", "file": "x.ts", "vulnerable": False,
         "verification_status": "BORDERLINE_PENDING_AUTHOR"},
        {"function_name": "d", "file": "x.ts", "vulnerable": False},
    ]

    assert compute_summary(functions)["clean_verified"] == 2


def test_recompute_leaves_unknown_keys_alone():
    """Datasets do not share a summary schema. A key this script cannot derive
    must survive untouched rather than be dropped or guessed."""
    stored = {"total_functions": 999, "note": "hand-written context", "custom_metric": 3}
    functions = [{"function_name": "a", "file": "x.ts", "vulnerable": False}]

    updated, unknown = recompute_present_keys(stored, functions)

    assert updated["total_functions"] == 1              # derived, corrected
    assert updated["note"] == "hand-written context"    # preserved
    assert updated["custom_metric"] == 3                # preserved
    assert set(unknown) == {"note", "custom_metric"}
    assert list(updated) == list(stored)                # key order preserved


def test_recompute_never_invents_keys():
    """Only keys already in the file are written back - otherwise a --write would
    silently impose juice-shop's schema on every other dataset."""
    stored = {"vulnerable": 0}
    functions = [{"function_name": "a", "file": "x.ts", "vulnerable": True, "cwe_id": "CWE-89"}]

    updated, _ = recompute_present_keys(stored, functions)

    assert updated == {"vulnerable": 1}
