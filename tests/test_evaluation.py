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

from src.evaluation import evaluate_run, load_ground_truth, save_evaluation_report, comparison_table


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
