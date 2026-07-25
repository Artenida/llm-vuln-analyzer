"""
Tests for the automated evaluation harness (Sprint 5 — Evaluation).

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_evaluation.py -v
"""
import json
import sys
from pathlib import Path

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.evaluation import (
    evaluate_run, load_ground_truth, save_evaluation_report,
    save_comparison_report, comparison_table,
)


def _write(tmp_path, name, payload):
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


GT_PAYLOAD = {
    "schema_version": "1.0",
    "dataset": "toy-service",
    "description": "synthetic dataset for evaluator tests",
    "source_path": "app-test/toy-service",
    "functions": [
        {"function_name": "login", "file": "controllers/auth.js",
         "vulnerable": True, "cwe_id": "CWE-89", "severity": "high"},
        {"function_name": "register", "file": "controllers/auth.js",
         "vulnerable": False, "cwe_id": None, "severity": None},
        {"function_name": "rateLimiter", "file": "middleware/rl.js",
         "vulnerable": True, "cwe_id": "CWE-20", "severity": "medium"},
        {"function_name": "rateLimiter", "file": "routes/routes.js",
         "vulnerable": True, "cwe_id": "CWE-20", "severity": "medium",
         "duplicate_of": "middleware/rl.js::rateLimiter"},
        {"function_name": "getOrder", "file": "services/orders.js",
         "vulnerable": True, "cwe_id": "CWE-639", "severity": "high"},
    ],
}


def _finding(function_name, file_path, vulnerability_found, cwe_id=None,
             hallucination_flag=False, analysis_mode="react_loop"):
    return {
        "function_name": function_name,
        "file_path": file_path,
        "vulnerability_found": vulnerability_found,
        "cwe_id": cwe_id,
        "severity": "high" if vulnerability_found else None,
        "confidence": 0.9,
        "hallucination_flag": hallucination_flag,
        "analysis_mode": analysis_mode,
        "error": None,
    }


def test_perfect_run_scores_full_precision_recall(tmp_path):
    gt_path = _write(tmp_path, "gt.json", GT_PAYLOAD)
    run_path = _write(tmp_path, "run.json", {
        "run_id": "run_perfect",
        "model": "test-model",
        "source_path": "/app-test/toy-service",
        "findings": [
            _finding("login", "/app-test/toy-service/controllers/auth.js", True, "CWE-89"),
            _finding("register", "/app-test/toy-service/controllers/auth.js", False),
            _finding("rateLimiter", "/app-test/toy-service/middleware/rl.js", True, "CWE-20"),
            _finding("rateLimiter", "/app-test/toy-service/routes/routes.js", True, "CWE-20"),
            _finding("getOrder", "/app-test/toy-service/services/orders.js", True, "CWE-639"),
        ],
    })

    report, gt = evaluate_run(run_path, gt_path)
    m = report.detection_metrics()

    assert (m.tp, m.fp, m.fn, m.tn) == (4, 0, 0, 1)
    assert m.precision == 1.0
    assert m.recall == 1.0
    assert report.cwe_accuracy() == 1.0

    ur = report.unique_recall(gt)
    assert ur == {"planted": 3, "detected": 3, "recall": 1.0}


def test_false_negative_and_false_positive(tmp_path):
    gt_path = _write(tmp_path, "gt.json", GT_PAYLOAD)
    run_path = _write(tmp_path, "run.json", {
        "run_id": "run_mixed",
        "model": "test-model",
        "source_path": "/app-test/toy-service",
        "findings": [
            _finding("login", "/app-test/toy-service/controllers/auth.js", False),  # FN
            _finding("register", "/app-test/toy-service/controllers/auth.js", True, "CWE-798"),  # FP
            _finding("rateLimiter", "/app-test/toy-service/middleware/rl.js", True, "CWE-20"),
            _finding("rateLimiter", "/app-test/toy-service/routes/routes.js", False),  # dup instance missed
            _finding("getOrder", "/app-test/toy-service/services/orders.js", True, "CWE-862"),  # wrong CWE
        ],
    })

    report, gt = evaluate_run(run_path, gt_path)
    m = report.detection_metrics()

    assert m.tp == 2  # rateLimiter@middleware, getOrder
    assert m.fp == 1  # register
    assert m.fn == 2  # login, rateLimiter@routes

    # getOrder was detected but with the wrong CWE
    tp_instances = [i for i in report.instances if i.outcome == "TP"]
    order_tp = next(i for i in tp_instances if i.function_name == "getOrder")
    assert order_tp.cwe_correct is False

    # dedup recall: rateLimiter group still counted "detected" because one instance was a TP
    ur = report.unique_recall(gt)
    assert ur["planted"] == 3
    assert ur["detected"] == 2  # login group missed entirely; rateLimiter + getOrder detected


def test_same_function_name_disambiguated_by_file(tmp_path):
    gt_path = _write(tmp_path, "gt.json", GT_PAYLOAD)
    # Only the routes/routes.js rateLimiter finding is present; middleware one is unanalyzed.
    run_path = _write(tmp_path, "run.json", {
        "run_id": "run_partial",
        "model": "test-model",
        "source_path": "/app-test/toy-service",
        "findings": [
            _finding("login", "/app-test/toy-service/controllers/auth.js", True, "CWE-89"),
            _finding("register", "/app-test/toy-service/controllers/auth.js", False),
            _finding("rateLimiter", "/app-test/toy-service/routes/routes.js", True, "CWE-20"),
            _finding("getOrder", "/app-test/toy-service/services/orders.js", True, "CWE-639"),
        ],
    })

    report, gt = evaluate_run(run_path, gt_path)
    by_id = {i.instance_id: i for i in report.instances}

    assert by_id["middleware/rl.js::rateLimiter"].analyzed is False
    assert by_id["middleware/rl.js::rateLimiter"].outcome == "FN"
    assert by_id["routes/routes.js::rateLimiter"].outcome == "TP"


def test_unmatched_findings_not_in_ground_truth(tmp_path):
    gt_path = _write(tmp_path, "gt.json", GT_PAYLOAD)
    run_path = _write(tmp_path, "run.json", {
        "run_id": "run_extra",
        "model": "test-model",
        "source_path": "/app-test/toy-service",
        "findings": [
            _finding("login", "/app-test/toy-service/controllers/auth.js", True, "CWE-89"),
            _finding("register", "/app-test/toy-service/controllers/auth.js", False),
            _finding("rateLimiter", "/app-test/toy-service/middleware/rl.js", True, "CWE-20"),
            _finding("rateLimiter", "/app-test/toy-service/routes/routes.js", True, "CWE-20"),
            _finding("getOrder", "/app-test/toy-service/services/orders.js", True, "CWE-639"),
            _finding("<anonymous>", "/app-test/toy-service/server.js", False),
        ],
    })

    report, gt = evaluate_run(run_path, gt_path)

    assert len(report.unmatched_findings) == 1
    assert report.unmatched_findings[0]["function_name"] == "<anonymous>"
    # unmatched findings must not pollute the confusion matrix
    m = report.detection_metrics()
    assert (m.tp, m.fp, m.fn, m.tn) == (4, 0, 0, 1)


def test_hallucination_rate_only_counts_flagged_findings(tmp_path):
    gt_path = _write(tmp_path, "gt.json", GT_PAYLOAD)
    run_path = _write(tmp_path, "run.json", {
        "run_id": "run_halluc",
        "model": "test-model",
        "source_path": "/app-test/toy-service",
        "findings": [
            _finding("login", "/app-test/toy-service/controllers/auth.js", True, "CWE-89", hallucination_flag=True),
            _finding("register", "/app-test/toy-service/controllers/auth.js", False, hallucination_flag=True),
            _finding("rateLimiter", "/app-test/toy-service/middleware/rl.js", True, "CWE-20"),
            _finding("rateLimiter", "/app-test/toy-service/routes/routes.js", True, "CWE-20"),
            _finding("getOrder", "/app-test/toy-service/services/orders.js", True, "CWE-639"),
        ],
    })

    report, gt = evaluate_run(run_path, gt_path)
    # 4 flagged (vulnerable=True) findings, 1 of which is hallucinated (register is clean+halluc, excluded)
    assert report.hallucination_rate() == 0.25


def test_save_evaluation_report_writes_valid_json(tmp_path):
    gt_path = _write(tmp_path, "gt.json", GT_PAYLOAD)
    run_path = _write(tmp_path, "run.json", {
        "run_id": "run_perfect",
        "model": "test-model",
        "source_path": "/app-test/toy-service",
        "findings": [
            _finding("login", "/app-test/toy-service/controllers/auth.js", True, "CWE-89"),
            _finding("register", "/app-test/toy-service/controllers/auth.js", False),
            _finding("rateLimiter", "/app-test/toy-service/middleware/rl.js", True, "CWE-20"),
            _finding("rateLimiter", "/app-test/toy-service/routes/routes.js", True, "CWE-20"),
            _finding("getOrder", "/app-test/toy-service/services/orders.js", True, "CWE-639"),
        ],
    })

    report, gt = evaluate_run(run_path, gt_path)
    out_path = save_evaluation_report(report, gt, output_folder=str(tmp_path / "out"))

    assert out_path.exists()
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["run_id"] == "run_perfect"
    assert data["detection_metrics"]["precision"] == 1.0
    assert len(data["instances"]) == 5


def test_comparison_table_lists_all_runs(tmp_path):
    gt_path = _write(tmp_path, "gt.json", GT_PAYLOAD)
    run_a = _write(tmp_path, "run_a.json", {
        "run_id": "run_a", "model": "m1", "source_path": "x",
        "findings": [_finding("login", "controllers/auth.js", True, "CWE-89", analysis_mode="call_graph_context")],
    })
    run_b = _write(tmp_path, "run_b.json", {
        "run_id": "run_b", "model": "m2", "source_path": "x",
        "findings": [_finding("login", "controllers/auth.js", True, "CWE-89", analysis_mode="react_loop")],
    })

    r_a, gt_a = evaluate_run(run_a, gt_path)
    r_b, gt_b = evaluate_run(run_b, gt_path)

    table = comparison_table([(r_a, gt_a), (r_b, gt_b)])
    assert "run_a" in table
    assert "run_b" in table
    assert "call_graph_context" in table
    assert "react_loop" in table


def test_save_comparison_report_writes_markdown_with_every_run(tmp_path):
    """The per-run JSON was always saved; the cross-run comparison — the one
    output putting accuracy and cost per mode on the same row — was printed and
    then lost with the terminal scrollback."""
    gt_path = _write(tmp_path, "gt.json", GT_PAYLOAD)
    run_a = _write(tmp_path, "run_a.json", {
        "run_id": "run_a", "model": "m1", "source_path": "x",
        "summary": {"total_cost_usd": 0.25, "total_tokens": 1000},
        "findings": [_finding("login", "controllers/auth.js", True, "CWE-89", analysis_mode="call_graph_context")],
    })
    run_b = _write(tmp_path, "run_b.json", {
        "run_id": "run_b", "model": "m2", "source_path": "x",
        "summary": {"total_cost_usd": 0.75, "total_tokens": 3000},
        "findings": [_finding("login", "controllers/auth.js", True, "CWE-89", analysis_mode="react_loop")],
    })

    reports = [evaluate_run(run_a, gt_path), evaluate_run(run_b, gt_path)]
    out = save_comparison_report(reports, output_folder=str(tmp_path))
    body = out.read_text(encoding="utf-8")

    assert out.exists() and out.suffix == ".md"
    assert "run_a" in body and "run_b" in body
    assert "call_graph_context" in body and "react_loop" in body
    assert "$0.2500" in body and "$0.7500" in body      # cost travels with the table
    assert "Precision" in body


def test_saved_comparison_carries_the_uncurated_warning(tmp_path):
    """A saved table outlives the terminal warning printed beside it, so the
    caveat has to live inside the artifact or it reads as a valid result."""
    payload = dict(GT_PAYLOAD)
    payload["curation_status"] = {"reviewed": False, "functions_unreviewed": 7,
                                  "functions_prefilled_vulnerable": 2}
    gt_path = _write(tmp_path, "gt_uncurated.json", payload)
    run_a = _write(tmp_path, "run_a.json", {
        "run_id": "run_a", "model": "m1", "source_path": "x",
        "findings": [_finding("login", "controllers/auth.js", True, "CWE-89")],
    })

    reports = [evaluate_run(run_a, gt_path)]
    body = save_comparison_report(reports, output_folder=str(tmp_path)).read_text(encoding="utf-8")

    assert "not valid" in body.lower()
    assert "7" in body


# ── same function name, same file: real code does this ───────────────────────
# Juice Shop has four Sequelize setters called `set` in models/user.ts. Keyed
# on file+name alone, one finding is scored against every one of them.

COLLIDING_GT = {
    "schema_version": "1.0",
    "dataset": "collide",
    "description": "two same-named setters in one file",
    "source_path": "app",
    "functions": [
        {"function_name": "set", "file": "models/user.js", "source_lines": [10, 20],
         "vulnerable": True, "cwe_id": "CWE-79", "severity": "medium"},
        {"function_name": "set", "file": "models/user.js", "source_lines": [30, 40],
         "vulnerable": False, "cwe_id": None, "severity": None},
    ],
}


def test_colliding_rows_are_separated_by_line_overlap(tmp_path):
    """The vulnerable setter is at 10-20 and the clean one at 30-40; the run
    flagged only the second. Without line matching both rows see the same
    finding: one bogus TP and one bogus FP."""
    gt_path = _write(tmp_path, "gt.json", COLLIDING_GT)
    run = _write(tmp_path, "run.json", {
        "run_id": "r", "model": "m", "source_path": "app",
        "findings": [
            {"function_name": "set", "file_path": "app/models/user.js",
             "vulnerability_found": False, "cwe_id": None, "affected_lines": [],
             "analysis_mode": "react_loop"},
            {"function_name": "set", "file_path": "app/models/user.js",
             "vulnerability_found": True, "cwe_id": "CWE-79", "affected_lines": [35],
             "analysis_mode": "react_loop"},
        ],
    })

    report, gt = evaluate_run(run, gt_path)
    m = report.detection_metrics()

    # the flagged finding sits at line 35, inside the CLEAN row (30-40)
    assert m.fp == 1        # flagged a clean function
    assert m.fn == 1        # missed the vulnerable one
    assert m.tp == 0


def test_each_finding_is_claimed_by_only_one_row(tmp_path):
    """One detection must not become several true positives."""
    gt_path = _write(tmp_path, "gt.json", COLLIDING_GT)
    run = _write(tmp_path, "run.json", {
        "run_id": "r", "model": "m", "source_path": "app",
        "findings": [
            {"function_name": "set", "file_path": "app/models/user.js",
             "vulnerability_found": True, "cwe_id": "CWE-79", "affected_lines": [15],
             "analysis_mode": "react_loop"},
        ],
    })

    report, gt = evaluate_run(run, gt_path)
    m = report.detection_metrics()

    assert m.tp == 1        # matched the row covering line 15
    assert m.fp == 0        # and NOT also charged against the clean row
    assert m.tn == 1


def test_rows_without_source_lines_keep_the_old_behaviour(tmp_path):
    """Datasets written before source_lines existed must score exactly as they
    did — auth-service and nodegoat depend on it."""
    gt_path = _write(tmp_path, "gt.json", GT_PAYLOAD)
    run = _write(tmp_path, "run.json", {
        "run_id": "r", "model": "m", "source_path": "x",
        "findings": [_finding("login", "controllers/auth.js", True, "CWE-89")],
    })

    report, _ = evaluate_run(run, gt_path)
    m = report.detection_metrics()

    assert m.tp == 1
    assert m.fp == 0


def test_instance_id_is_unique_per_row_when_lines_are_known(tmp_path):
    gt = load_ground_truth(_write(tmp_path, "gt.json", COLLIDING_GT))

    ids = [e.instance_id for e in gt.entries]

    assert len(set(ids)) == 2
    assert "@10-20" in ids[0] and "@30-40" in ids[1]


def test_unseparable_rows_are_reported_as_ambiguous(tmp_path):
    """When a finding carries no lines there is nothing to match on. Pair by
    order, but say so rather than presenting a guess as a verdict."""
    gt_path = _write(tmp_path, "gt.json", COLLIDING_GT)
    run = _write(tmp_path, "run.json", {
        "run_id": "r", "model": "m", "source_path": "app",
        "findings": [
            {"function_name": "set", "file_path": "app/models/user.js",
             "vulnerability_found": True, "cwe_id": "CWE-79", "affected_lines": [],
             "analysis_mode": "react_loop"},
        ],
    })

    report, _ = evaluate_run(run, gt_path)

    assert len(report.unresolved_findings) >= 1
