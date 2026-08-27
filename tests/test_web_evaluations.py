"""
Tests for the web layer's evaluation endpoints (Sprint 6 — web UI).

The API exposes evaluation reports, which live outside a run's output directory
and have run-id-derived filenames, so they cannot use the run-artifact
whitelist. These tests pin the rule that replaces it, and pin the numbers the
API reports to the ones the evaluator produces — a dashboard that disagreed
with `evaluate` would be worse than no dashboard.

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_web_evaluations.py -v
"""
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

GT_PAYLOAD = {
    "schema_version": "1.0",
    "dataset": "toy-service",
    "description": "synthetic dataset for web evaluation tests",
    "source_path": "app-test/toy-service",
    "functions": [
        {"function_name": "login", "file": "controllers/auth.js",
         "vulnerable": True, "cwe_id": "CWE-89", "severity": "high"},
        {"function_name": "register", "file": "controllers/auth.js",
         "vulnerable": False, "cwe_id": None, "severity": None},
        {"function_name": "getOrder", "file": "services/orders.js",
         "vulnerable": True, "cwe_id": "CWE-639", "severity": "high"},
    ],
}

ANALYSIS_PAYLOAD = {
    "run_id": "analysis_test_20260101_000000",
    "model": "o4-mini",
    "source_path": "app-test/toy-service",
    "summary": {"total_cost_usd": 0.25, "total_tokens": 1000},
    "findings": [
        {"function_name": "login", "file_path": "controllers/auth.js",
         "vulnerability_found": True, "cwe_id": "CWE-89", "severity": "high",
         "analysis_mode": "react_loop"},
        {"function_name": "register", "file_path": "controllers/auth.js",
         "vulnerability_found": False, "cwe_id": None,
         "analysis_mode": "react_loop"},
        {"function_name": "getOrder", "file_path": "services/orders.js",
         "vulnerability_found": False, "cwe_id": None,
         "analysis_mode": "react_loop"},
    ],
}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """An app whose experiments tree and UI state are both throwaway.

    Overriding both is the point: a test must never read a real report or write
    into the user's run history.
    """
    experiments = tmp_path / "experiments"
    dataset = experiments / "datasets" / "toy-service"
    (dataset / "runs" / "run-1").mkdir(parents=True)

    (dataset / "ground_truth.json").write_text(
        json.dumps(GT_PAYLOAD), encoding="utf-8"
    )
    (dataset / "runs" / "run-1" / "analysis.json").write_text(
        json.dumps(ANALYSIS_PAYLOAD), encoding="utf-8"
    )

    monkeypatch.setenv("VULN_ANALYZER_EXPERIMENTS", str(experiments))
    monkeypatch.setenv("VULN_ANALYZER_UI_STATE", str(tmp_path / "uistate"))

    from src.web.app import create_app

    return TestClient(create_app()), tmp_path


def _run_dir(tmp_path):
    return tmp_path / "experiments" / "datasets" / "toy-service" / "runs" / "run-1"


def _ground_truth(tmp_path):
    return tmp_path / "experiments" / "datasets" / "toy-service" / "ground_truth.json"


def test_listing_is_empty_before_anything_is_scored(client):
    api, _ = client
    body = api.get("/api/evaluations").json()
    assert body == {"reports": [], "comparisons": []}


def test_datasets_are_offered_with_their_counts(client):
    api, _ = client
    datasets = api.get("/api/evaluations/datasets").json()
    assert len(datasets) == 1
    assert datasets[0]["name"] == "toy-service"
    assert datasets[0]["function_count"] == 3
    assert datasets[0]["vulnerable_count"] == 2


def test_scoring_a_run_matches_the_evaluator(client):
    api, tmp_path = client
    response = api.post("/api/evaluations/run", json={
        "path": str(_run_dir(tmp_path)),
        "ground_truth": str(_ground_truth(tmp_path)),
    })
    assert response.status_code == 200
    report = response.json()

    # login flagged correctly, getOrder missed, register correctly clean.
    assert report["detection_metrics"] == {
        "tp": 1, "fp": 0, "fn": 1, "tn": 1,
        "precision": 1.0, "recall": 0.5, "f1": 0.6667,
        # A point estimate off one flagged row and two vulnerable rows carries
        # almost no information, and the bands say so: the API has to serve them
        # with the estimate, or the UI shows 1.00 precision from a single row.
        "precision_interval": {
            "point": 1.0, "low": 0.2065, "high": 1.0, "n": 1, "method": "wilson_95",
        },
        "recall_interval": {
            "point": 0.5, "low": 0.0945, "high": 0.9055, "n": 2, "method": "wilson_95",
        },
    }
    assert report["run_id"] == ANALYSIS_PAYLOAD["run_id"]
    assert report["cost_per_tp_usd"] == pytest.approx(0.25)

    # Written where `evaluate` writes it, so the CLI and the UI never disagree
    # about where a run's report lives.
    written = Path(report["path"])
    assert written.parent == _ground_truth(tmp_path).parent / "evaluations"
    assert written.name == f"eval_{ANALYSIS_PAYLOAD['run_id']}.json"

    listed = api.get("/api/evaluations").json()["reports"]
    assert [r["path"] for r in listed] == [str(written)]
    assert api.get("/api/evaluations/for-run",
                   params={"run_id": ANALYSIS_PAYLOAD["run_id"]}).json()[0]["path"] == str(written)


def test_a_run_without_analysis_is_rejected_not_scored_as_zero(client):
    api, tmp_path = client
    empty = _run_dir(tmp_path).parent / "run-2"
    empty.mkdir()
    (empty / "extraction.json").write_text("{}", encoding="utf-8")

    response = api.post("/api/evaluations/run", json={
        "path": str(empty),
        "ground_truth": str(_ground_truth(tmp_path)),
    })
    assert response.status_code == 422
    assert "analysis.json" in response.json()["detail"]


def test_uncurated_scaffold_is_flagged_on_the_report(client):
    api, tmp_path = client
    gt = json.loads(_ground_truth(tmp_path).read_text(encoding="utf-8"))
    gt["curation_status"] = {"reviewed": False, "functions_unreviewed": 3}
    _ground_truth(tmp_path).write_text(json.dumps(gt), encoding="utf-8")

    report = api.post("/api/evaluations/run", json={
        "path": str(_run_dir(tmp_path)),
        "ground_truth": str(_ground_truth(tmp_path)),
    }).json()
    assert report["curation"]["needs_curation"] is True
    assert report["curation"]["functions_unreviewed"] == 3


def test_hand_written_ground_truth_is_not_flagged(client):
    """No `curation_status` block means hand-authored, not unreviewed.

    Mirrors `GroundTruthDataset.needs_curation`. Flagging these would put a
    "these numbers are not valid" warning on every curated dataset.
    """
    api, tmp_path = client
    report = api.post("/api/evaluations/run", json={
        "path": str(_run_dir(tmp_path)),
        "ground_truth": str(_ground_truth(tmp_path)),
    }).json()
    assert report["curation"]["needs_curation"] is False
    assert report["curation"]["scaffolded"] is False


@pytest.mark.parametrize("bad", [
    "requirements.txt",                                    # outside a registered root
    "experiments/datasets/toy-service/ground_truth.json",  # not in evaluations/
])
def test_reports_are_only_readable_from_an_evaluations_directory(client, bad):
    api, _ = client
    assert api.get("/api/evaluations/report", params={"path": bad}).status_code == 400


def test_ground_truth_must_live_under_datasets(client, tmp_path):
    api, tmp = client
    stray = tmp / "elsewhere.json"
    stray.write_text(json.dumps(GT_PAYLOAD), encoding="utf-8")
    response = api.post("/api/evaluations/run", json={
        "path": str(_run_dir(tmp)),
        "ground_truth": str(stray),
    })
    assert response.status_code == 400


def test_unrelated_json_in_an_evaluations_directory_is_skipped(client):
    api, tmp_path = client
    api.post("/api/evaluations/run", json={
        "path": str(_run_dir(tmp_path)),
        "ground_truth": str(_ground_truth(tmp_path)),
    })
    evaluations_dir = _ground_truth(tmp_path).parent / "evaluations"
    (evaluations_dir / "notes.json").write_text('{"note": "not a report"}', encoding="utf-8")
    (evaluations_dir / "broken.json").write_text("{not json", encoding="utf-8")
    (evaluations_dir / "comparison_x.md").write_text("# table", encoding="utf-8")

    body = api.get("/api/evaluations").json()
    assert len(body["reports"]) == 1
    assert [c["name"] for c in body["comparisons"]] == ["comparison_x.md"]
    assert api.get("/api/evaluations/comparison",
                   params={"path": str(evaluations_dir / "comparison_x.md")}).text == "# table"
