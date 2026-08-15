"""
Tests for opening a results folder the UI did not produce.

Reads are confined to a registry of directories this tool has written to, so a
run from an earlier session, another machine, or a plain `analyze` on the
command line is unreadable until it is registered. `POST /api/results/open` is
the only way to widen that set from the browser, which makes it the one place
where getting the guards wrong turns a results reader into a file-read oracle.
The tests are weighted accordingly: what it refuses matters more than what it
opens.

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_web_open_results.py -v
"""
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture()
def elsewhere(tmp_path, monkeypatch):
    """A result directory outside every standing root, plus a bare client.

    `experiments/` and `results/` are always readable, so a run inside either
    would pass these tests without the registration doing anything. The point of
    the endpoint is the folder that is *not* covered — the one on a second drive,
    or copied off another machine.
    """
    monkeypatch.setenv("VULN_ANALYZER_EXPERIMENTS", str(tmp_path / "experiments"))
    monkeypatch.setenv("VULN_ANALYZER_UI_STATE", str(tmp_path / "uistate"))

    directory = tmp_path / "somewhere" / "run-1"
    directory.mkdir(parents=True)
    (directory / "analysis.json").write_text(
        json.dumps({"run_id": "r1", "findings": [], "summary": {}, "meta": {}}),
        encoding="utf-8",
    )

    from src.web.app import create_app

    return TestClient(create_app()), directory


def test_a_foreign_result_is_unreadable_until_it_is_opened(elsewhere):
    """The whole reason the endpoint exists."""
    api, directory = elsewhere

    before = api.get("/api/results", params={"path": str(directory)})
    assert before.status_code == 400

    opened = api.post("/api/results/open", json={"path": str(directory)})
    assert opened.status_code == 200
    assert opened.json()["output_dir"] == str(directory)

    after = api.get("/api/results", params={"path": str(directory)})
    assert after.status_code == 200
    assert after.json()["has_analysis"] is True


def test_opening_survives_a_restart(elsewhere):
    """The registration is on disk, not in the process — a run opened before a
    restart must still be readable after one."""
    api, directory = elsewhere
    assert api.post("/api/results/open", json={"path": str(directory)}).status_code == 200

    from src.web.app import create_app

    fresh = TestClient(create_app())
    assert fresh.get("/api/results", params={"path": str(directory)}).status_code == 200


def test_a_folder_with_no_run_artifacts_is_refused_and_not_registered(elsewhere):
    """The guard that keeps this from being a way to register anything at all.

    Without it, pointing the dialog at a home directory would authorise reads
    inside it — the refusal has to leave the registry untouched, not merely
    return an error.
    """
    api, directory = elsewhere
    ordinary = directory.parent / "not-a-run"
    ordinary.mkdir()
    (ordinary / "notes.txt").write_text("nothing to see", encoding="utf-8")

    refused = api.post("/api/results/open", json={"path": str(ordinary)})
    assert refused.status_code == 400
    assert "no analysis results" in refused.json()["detail"].lower()

    assert api.get("/api/results", params={"path": str(ordinary)}).status_code == 400


def test_opening_a_run_does_not_open_its_neighbours(elsewhere):
    """Registration is per-directory, not per-parent.

    Opening `…/somewhere/run-1` must not make the rest of `…/somewhere/`
    readable, even the parts of it that are themselves results.
    """
    api, directory = elsewhere
    sibling = directory.parent / "run-2"
    sibling.mkdir()
    (sibling / "analysis.json").write_text("{}", encoding="utf-8")

    assert api.post("/api/results/open", json={"path": str(directory)}).status_code == 200

    assert api.get("/api/results", params={"path": str(sibling)}).status_code == 400
    assert api.get("/api/results", params={"path": str(directory.parent)}).status_code == 400


def test_an_opened_folder_is_still_not_a_file_read_oracle(elsewhere):
    """Registering a directory authorises the run artifacts in it, nothing else.

    A results folder can sit anywhere the user likes, including beside files
    that are none of this tool's business. The Raw tab lists every file so the
    directory is never misrepresented — but only whitelisted names can be read,
    and the listing says which those are.
    """
    api, directory = elsewhere
    (directory / "secrets.env").write_text("OPENAI_API_KEY=sk-real", encoding="utf-8")

    assert api.post("/api/results/open", json={"path": str(directory)}).status_code == 200

    body = api.get(
        "/api/results/artifacts/secrets.env", params={"path": str(directory)}
    )
    assert body.status_code == 400
    assert "sk-real" not in body.text

    listed = {entry["name"]: entry["readable"] for entry
              in api.get("/api/results/artifacts", params={"path": str(directory)}).json()}
    assert listed["secrets.env"] is False
    assert listed["analysis.json"] is True


def test_a_missing_folder_is_a_404(elsewhere):
    api, directory = elsewhere
    missing = directory.parent / "no-such-run"
    assert api.post("/api/results/open", json={"path": str(missing)}).status_code == 404


def test_an_empty_path_is_refused(elsewhere):
    api, _ = elsewhere
    assert api.post("/api/results/open", json={"path": "   "}).status_code == 400


def test_the_picker_says_whether_the_folder_it_is_in_holds_results(elsewhere):
    """The dialog disables its confirm button on this flag, so a wrong folder is
    refused before the click rather than after it."""
    api, directory = elsewhere

    inside = api.get("/api/fs/list", params={"path": str(directory)}).json()
    assert inside["is_result_dir"] is True

    outside = api.get("/api/fs/list", params={"path": str(directory.parent)}).json()
    assert outside["is_result_dir"] is False
    assert [e["name"] for e in outside["entries"] if e["is_result_dir"]] == ["run-1"]
