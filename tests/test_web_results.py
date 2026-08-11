"""
Tests for the web layer's result-bundle reads (Sprint 6 — web UI).

Focused on the call-graph embed, which has two failure modes that both look
like "the graph is empty" from the browser and neither of which raises:

* a run that wrote only `call_graph_annotated.html` being reported as having no
  graph at all, so the UI never renders the iframe; and
* a stale copy in the browser cache surviving a re-run.

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_web_results.py -v
"""
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.web import results

GRAPH_HTML = """<html>
<head>
<script src="lib/bindings/utils.js"></script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/dist/vis-network.min.css" integrity="sha512-AAA==" crossorigin="anonymous" />
<script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/vis-network.min.js" integrity="sha512-BBB==" crossorigin="anonymous"></script>
</head>
<body><div id="mynetwork"></div><script>drawGraph();</script></body>
</html>"""


@pytest.fixture()
def bundle(tmp_path, monkeypatch):
    """A result directory inside a throwaway experiments tree."""
    experiments = tmp_path / "experiments"
    directory = experiments / "datasets" / "toy" / "runs" / "run-1"
    directory.mkdir(parents=True)
    (directory / "analysis.json").write_text(
        json.dumps({"run_id": "r1", "findings": [], "summary": {}}), encoding="utf-8"
    )

    monkeypatch.setenv("VULN_ANALYZER_EXPERIMENTS", str(experiments))
    monkeypatch.setenv("VULN_ANALYZER_UI_STATE", str(tmp_path / "uistate"))

    from src.web.app import create_app

    return TestClient(create_app()), directory


def test_a_run_with_only_the_annotated_graph_still_has_an_embed(bundle):
    """The regression this file exists for.

    `--annotate-graph` writes `call_graph_annotated.html` and no plain
    `call_graph.html`. Checking only the plain name reported those runs as
    having no graph, so the UI showed "no graph view" while the file sat in the
    directory and opened fine from disk.
    """
    api, directory = bundle
    (directory / "call_graph_annotated.html").write_text(GRAPH_HTML, encoding="utf-8")

    summary = api.get("/api/results", params={"path": str(directory)}).json()
    assert summary["has_graph_html"] is True
    assert summary["has_annotated_html"] is True
    assert summary["graph_html_version"] is not None


def test_a_run_with_no_graph_html_reports_none(bundle):
    api, directory = bundle
    summary = api.get("/api/results", params={"path": str(directory)}).json()
    assert summary["has_graph_html"] is False
    assert summary["graph_html_version"] is None
    assert api.get("/api/results/graph.html",
                   params={"path": str(directory)}).status_code == 404


def test_the_annotated_graph_wins_and_the_flag_can_flip_it(bundle):
    api, directory = bundle
    (directory / "call_graph.html").write_text(
        GRAPH_HTML.replace("drawGraph();", "plain();"), encoding="utf-8"
    )
    (directory / "call_graph_annotated.html").write_text(GRAPH_HTML, encoding="utf-8")

    assert results.graph_html_file(directory).name == "call_graph_annotated.html"
    assert results.graph_html_file(directory, annotated=False).name == "call_graph.html"
    assert "plain();" in api.get(
        "/api/results/graph.html", params={"path": str(directory), "annotated": False}
    ).text


def test_embed_is_rewritten_to_vendored_assets_and_never_cached(bundle):
    api, directory = bundle
    (directory / "call_graph_annotated.html").write_text(GRAPH_HTML, encoding="utf-8")

    response = api.get("/api/results/graph.html", params={"path": str(directory)})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"

    body = response.text
    assert "cdnjs.cloudflare.com" not in body
    assert "/vendor/vis-9.1.2/vis-network.min.js" in body
    assert "/vendor/bindings/utils.js" in body
    # The SRI hashes belong to the CDN copies; leaving them on a rewritten tag
    # makes the browser refuse the script and the graph renders empty.
    assert "integrity=" not in body
    # The graph itself must survive the rewriting untouched.
    assert "drawGraph();" in body


def test_embed_is_sized_to_its_frame(bundle):
    """pyvis hardcodes a pixel height on a white body; unpatched that shows as a
    white band above a clipped, separately-scrolling canvas inside the iframe."""
    api, directory = bundle
    (directory / "call_graph_annotated.html").write_text(GRAPH_HTML, encoding="utf-8")

    body = api.get("/api/results/graph.html", params={"path": str(directory)}).text
    assert "100vh" in body
    assert body.count("</head>") == 1


def test_embed_resizes_the_canvas_not_just_the_box(bundle):
    """The regression that made the graph look empty.

    Sizing the container to the frame is not enough: vis-network measures the
    container once, at construction, and a viewport-relative height is not final
    until the embedding frame settles. `redraw()` repaints at the size it already
    believes in — only `setSize` re-measures — so without it the nodes are drawn
    for a canvas that no longer exists and land outside the visible area.
    """
    api, directory = bundle
    (directory / "call_graph_annotated.html").write_text(GRAPH_HTML, encoding="utf-8")

    body = api.get("/api/results/graph.html", params={"path": str(directory)}).text
    assert "network.setSize(" in body
    assert "ResizeObserver" in body
    # Physics moves nodes after first paint, so the fit has to happen again once
    # stabilisation is done.
    assert "stabilizationIterationsDone" in body
    assert body.count("</body>") == 1


def test_version_changes_when_the_graph_is_rewritten(bundle):
    """A re-run into the same directory must produce a different embed URL."""
    api, directory = bundle
    target = directory / "call_graph_annotated.html"
    target.write_text(GRAPH_HTML, encoding="utf-8")

    first = api.get("/api/results", params={"path": str(directory)}).json()

    import os
    stamp = target.stat().st_mtime + 120
    os.utime(target, (stamp, stamp))

    second = api.get("/api/results", params={"path": str(directory)}).json()
    assert second["graph_html_version"] != first["graph_html_version"]
