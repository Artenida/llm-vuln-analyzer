"""
Tests for the analysis scope the web UI scans and runs under.

The bug these exist to prevent is a quiet one: `/fs/inspect` counting functions
under one config while `/jobs/analyze` runs under another. Nothing errors — you
are simply shown 382 functions, told a price for 382 functions, and charged for
2,696. So the assertions here are mostly about *agreement*: the same config
resolution feeding both endpoints, and the scan's numbers being labelled with
the scope they were taken under.

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_web_scope.py -v
"""
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.web import paths  # noqa: E402
from src.web.routers import configs as configs_router  # noqa: E402


WIDE = """\
description: "Everything."

ingestion:
  max_function_lines: 200
  skip_dirs:
    - node_modules
"""

NARROW = """\
description: "Server only."

ingestion:
  max_function_lines: 200
  skip_dirs:
    - node_modules
    - client
    - fixtures.js
"""


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A client whose config directory holds exactly two known scopes."""
    experiments = tmp_path / "experiments"
    (experiments / "configs").mkdir(parents=True)
    (experiments / "configs" / "default.yaml").write_text(WIDE, encoding="utf-8")
    (experiments / "configs" / "server-only.yaml").write_text(NARROW, encoding="utf-8")

    monkeypatch.setenv("VULN_ANALYZER_EXPERIMENTS", str(experiments))
    monkeypatch.setenv("VULN_ANALYZER_UI_STATE", str(tmp_path / "uistate"))

    from src.web.app import create_app

    return TestClient(create_app())


@pytest.fixture()
def project(tmp_path):
    """Two functions in scope for both configs, two only for the wide one."""
    root = tmp_path / "project"
    (root / "server").mkdir(parents=True)
    (root / "client").mkdir(parents=True)
    (root / "server" / "routes.js").write_text(
        "function login(a) { return a; }\nfunction logout(b) { return b; }\n",
        encoding="utf-8",
    )
    (root / "client" / "widget.js").write_text(
        "function render(x) { return x; }\n", encoding="utf-8"
    )
    # A bare filename as a skip entry — the extractor matches any path part,
    # so a root-level file can be excluded without a directory to hide it in.
    (root / "fixtures.js").write_text("function seed(y) { return y; }\n", encoding="utf-8")
    return root


# ── the config list ───────────────────────────────────────────────────────────


def test_lists_configs_with_the_default_first(client):
    configs = client.get("/api/configs").json()
    assert [c["name"] for c in configs] == ["default", "server-only"]
    assert configs[0]["is_default"] is True
    # The description is what names the scope in the picker; a config without
    # one would appear as a bare filename.
    assert configs[1]["description"] == "Server only."


def test_a_config_outside_the_configs_directory_is_refused(client, tmp_path):
    planted = tmp_path / "elsewhere.yaml"
    planted.write_text(WIDE, encoding="utf-8")
    # This path reaches a subprocess argv. "Run the analyzer against that YAML
    # over there" is not a capability the browser is given.
    with pytest.raises(paths.UnsafePathError):
        configs_router.resolve(str(planted))


def test_a_bare_name_resolves_to_the_configs_directory(client):
    assert configs_router.resolve("server-only").name == "server-only.yaml"
    assert configs_router.resolve("server-only.yaml").name == "server-only.yaml"
    assert configs_router.resolve(None).name == "default.yaml"


# ── scanning under a scope ────────────────────────────────────────────────────


def test_inspect_counts_only_what_the_chosen_config_keeps(client, project):
    wide = client.post("/api/fs/inspect", json={"path": str(project)}).json()
    narrow = client.post(
        "/api/fs/inspect",
        json={"path": str(project), "config_path": "server-only"},
    ).json()

    assert wide["functions"] == 4
    assert wide["source_files_excluded"] == 0

    # The two files the narrow scope drops, and only those.
    assert narrow["functions"] == 2
    assert narrow["source_files"] == 1
    assert narrow["excluded"] == {"client": 1, "fixtures.js": 1}
    assert narrow["source_files_excluded"] == 2


def test_a_scan_says_which_scope_produced_it(client, project):
    result = client.post(
        "/api/fs/inspect",
        json={"path": str(project), "config_path": "server-only"},
    ).json()
    # Without this the frontend cannot tell a fresh count from one taken before
    # the scope was changed, which is the whole of the stale-scan guard.
    assert result["config_name"] == "server-only"
    assert result["config_path"].endswith("server-only.yaml")
    assert result["config_description"] == "Server only."


def test_omitting_the_config_scans_under_the_default(client, project):
    result = client.post("/api/fs/inspect", json={"path": str(project)}).json()
    assert result["config_name"] == "default"


def test_an_unknown_config_is_refused_rather_than_silently_defaulted(client, project):
    response = client.post(
        "/api/fs/inspect", json={"path": str(project), "config_path": "no-such-scope"}
    )
    # Falling back to the default here would scan a wider tree than the caller
    # asked for and report the count as if it were theirs.
    assert response.status_code == 400


# ── running under the same scope ──────────────────────────────────────────────


def test_the_run_command_names_the_scope_it_was_given(client, project, tmp_path):
    from src.web import jobs as job_module

    argv = job_module.build_analyze_argv(
        source_path=str(project),
        output_dir=str(tmp_path / "out"),
        react=False,
        visualize=False,
        dry_run=True,
        resume=False,
        config_path=str(configs_router.resolve("server-only")),
        budget_usd=None,
        api_key_alias="default",
    )
    assert "--config" in argv
    assert argv[argv.index("--config") + 1].endswith("server-only.yaml")


def test_starting_a_run_threads_the_chosen_scope_into_the_command(
    client, project, tmp_path, monkeypatch
):
    """The endpoint the Analyze button calls, with the subprocess stubbed out.

    `build_analyze_argv` being correct is not enough on its own — the whole
    failure mode is a request that scans under one config and runs under
    another, and only the router sees both halves.
    """
    captured: dict = {}

    class FakeJob:
        def public(self):
            return {"id": "job-1", "output_dir": captured.get("output_dir")}

    def fake_start(kind, argv, **kwargs):
        captured["argv"] = argv
        captured["output_dir"] = kwargs.get("output_dir")
        return FakeJob()

    from src.web.routers import jobs as jobs_router

    monkeypatch.setattr(jobs_router.manager, "start", fake_start)

    response = client.post(
        "/api/jobs/analyze",
        json={
            "source_path": str(project),
            "output_dir": str(tmp_path / "out"),
            "react": False,
            "visualize": False,
            "dry_run": True,      # no key needed, and nothing is spent
            "resume": False,
            "config_path": "server-only",
        },
    )
    assert response.status_code == 200
    argv = captured["argv"]
    assert argv[argv.index("--config") + 1].endswith("server-only.yaml")


def test_a_run_with_no_config_still_states_one(client, project, tmp_path, monkeypatch):
    captured: dict = {}

    class FakeJob:
        def public(self):
            return {"id": "job-2", "output_dir": None}

    from src.web.routers import jobs as jobs_router

    monkeypatch.setattr(
        jobs_router.manager, "start",
        lambda kind, argv, **kw: (captured.update(argv=argv), FakeJob())[1],
    )

    client.post(
        "/api/jobs/analyze",
        json={
            "source_path": str(project),
            "output_dir": str(tmp_path / "out2"),
            "react": False, "visualize": False, "dry_run": True, "resume": False,
        },
    )
    # Explicit rather than implicit: the scope then appears in the command the
    # progress panel shows, so a finished run can be checked against it.
    argv = captured["argv"]
    assert argv[argv.index("--config") + 1].endswith("default.yaml")


# ── chunking: the count the ground truth can be compared to ───────────────────


OVERSIZED = "function huge(a) {\n" + "  a = a + 1;\n" * 40 + "  return a;\n}\n"


@pytest.fixture()
def with_oversized(project):
    """The project plus one function over a 10-line limit."""
    (project / "server" / "big.js").write_text(OVERSIZED, encoding="utf-8")
    return project


@pytest.fixture()
def small_limit(tmp_path):
    """A config whose line limit the oversized function exceeds."""
    path = tmp_path / "experiments" / "configs" / "tiny.yaml"
    path.write_text(
        'description: "Tiny limit."\n\n'
        "ingestion:\n  max_function_lines: 10\n  skip_dirs:\n    - node_modules\n    - client\n",
        encoding="utf-8",
    )
    return path


def test_chunking_off_drops_the_oversized_function_from_the_count(
    client, with_oversized, small_limit
):
    on = client.post("/api/fs/inspect", json={
        "path": str(with_oversized), "config_path": "tiny", "chunk_oversized": True,
    }).json()
    off = client.post("/api/fs/inspect", json={
        "path": str(with_oversized), "config_path": "tiny", "chunk_oversized": False,
    }).json()

    # Both see the same oversized function; they disagree on what to do with it.
    assert on["functions_skipped"] == 1
    assert off["functions_skipped"] == 1
    # Chunking adds analysis units without adding whole functions, which is the
    # entire reason both numbers are reported.
    assert on["functions"] > off["functions"]
    assert on["whole_functions"] == off["functions"] == off["whole_functions"]
    assert on["chunk_oversized"] is True and off["chunk_oversized"] is False


def test_the_scan_reports_the_chunking_it_used(client, project):
    result = client.post("/api/fs/inspect", json={"path": str(project)}).json()
    # Same contract as the config: a count that does not say how oversized
    # functions were treated cannot be compared with a ground truth.
    assert "chunk_oversized" in result
    assert result["whole_functions"] == result["functions"]  # nothing oversized here


def test_the_run_carries_the_chunking_choice(client, project, tmp_path, monkeypatch):
    captured: dict = {}

    class FakeJob:
        def public(self):
            return {"id": "job-3", "output_dir": None}

    from src.web.routers import jobs as jobs_router

    monkeypatch.setattr(
        jobs_router.manager, "start",
        lambda kind, argv, **kw: (captured.update(argv=argv), FakeJob())[1],
    )

    for value, expected in ((False, "--no-chunk-oversized"), (True, "--chunk-oversized")):
        client.post("/api/jobs/analyze", json={
            "source_path": str(project),
            "output_dir": str(tmp_path / f"out-{expected}"),
            "react": False, "visualize": False, "dry_run": True, "resume": False,
            "chunk_oversized": value,
        })
        assert expected in captured["argv"]


def test_omitting_the_choice_leaves_the_config_alone(client, project, tmp_path, monkeypatch):
    captured: dict = {}

    class FakeJob:
        def public(self):
            return {"id": "job-4", "output_dir": None}

    from src.web.routers import jobs as jobs_router

    monkeypatch.setattr(
        jobs_router.manager, "start",
        lambda kind, argv, **kw: (captured.update(argv=argv), FakeJob())[1],
    )

    client.post("/api/jobs/analyze", json={
        "source_path": str(project),
        "output_dir": str(tmp_path / "out-none"),
        "react": False, "visualize": False, "dry_run": True, "resume": False,
    })
    # A caller that never touched the control must not silently override every
    # config file's own setting.
    argv = captured["argv"]
    assert "--chunk-oversized" not in argv and "--no-chunk-oversized" not in argv
