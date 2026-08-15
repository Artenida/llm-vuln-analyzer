"""
Tests for the single-instance guard on `python -m src.cli ui`.

The regression: nothing stopped a second UI server from starting, so seventeen
of them accumulated on ports 8123-8162 in one evening. None of them spent money
by itself, but each could still launch a paid analysis job, and one such job
outlived every window that could have stopped it.

The interesting cases are the two ways to get this wrong: refusing to start
because of a lock left behind by a server that has since died, and failing to
notice a server that is genuinely up.

Run with:
    cd llm-vuln-analyzer
    python -m pytest tests/test_instance_lock.py -v
"""
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

# allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.web import instance_lock, paths


@pytest.fixture()
def state(tmp_path, monkeypatch):
    """UI state in a throwaway directory — never the user's real lock."""
    monkeypatch.setenv("VULN_ANALYZER_UI_STATE", str(tmp_path / "uistate"))
    instance_lock.release()
    yield tmp_path
    instance_lock.release()


@pytest.fixture()
def held_port():
    """A real listening socket, so port_in_use is tested against a real port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    yield sock.getsockname()[1]
    sock.close()


@pytest.fixture()
def sleeper():
    """A live process to point a lock at, and its pid after it is gone."""
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    yield proc
    if proc.poll() is None:
        proc.kill()
        proc.wait(timeout=10)


# ── liveness primitives ───────────────────────────────────────────────────────


def test_pid_alive_tracks_a_real_process(sleeper):
    """os.kill(pid, 0) is the POSIX idiom for this and on Windows it would
    *terminate* the process being asked about. The point of this test is that
    asking does not kill."""
    assert instance_lock.pid_alive(sleeper.pid) is True

    time.sleep(0.2)
    assert sleeper.poll() is None, "asking whether it is alive must not kill it"

    sleeper.kill()
    sleeper.wait(timeout=10)
    assert instance_lock.pid_alive(sleeper.pid) is False


def test_pid_alive_is_false_for_nonsense():
    assert instance_lock.pid_alive(0) is False
    assert instance_lock.pid_alive(-1) is False


def test_port_in_use_tracks_a_real_socket(held_port):
    assert instance_lock.port_in_use("127.0.0.1", held_port) is True


def test_an_unbound_port_is_free():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    free = sock.getsockname()[1]
    sock.close()
    assert instance_lock.port_in_use("127.0.0.1", free) is False


# ── the lock ──────────────────────────────────────────────────────────────────


def test_no_lock_means_nothing_is_running(state):
    assert instance_lock.running_instance() is None


def test_a_live_server_is_detected(state, sleeper, held_port):
    """Both signals present: the pid is alive and its port is bound."""
    paths.write_json(instance_lock.lock_file(), {
        "pid": sleeper.pid, "host": "127.0.0.1",
        "port": held_port, "started_at": "2026-08-15T09:29:30",
    })

    found = instance_lock.running_instance()
    assert found is not None
    assert found.pid == sleeper.pid
    assert found.port == held_port
    assert found.url == f"http://localhost:{held_port}"


def test_a_lock_from_a_dead_server_does_not_block_a_start(state, held_port, sleeper):
    """The failure mode that would make this guard worse than none.

    A server killed without releasing its lock must not lock the user out of
    ever starting another — which is exactly the state their machine was in
    after seventeen servers were force-killed.
    """
    sleeper.kill()
    sleeper.wait(timeout=10)

    paths.write_json(instance_lock.lock_file(), {
        "pid": sleeper.pid, "host": "127.0.0.1",
        "port": held_port, "started_at": "2026-08-01T18:38:59",
    })

    assert instance_lock.running_instance() is None
    assert not instance_lock.lock_file().exists(), "a stale lock must be cleared"


def test_a_live_pid_on_a_dead_port_is_stale(state, sleeper):
    """Pids are recycled. A lock naming a pid that now belongs to something else
    would otherwise block every future start, so the port has to agree."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    free = sock.getsockname()[1]
    sock.close()

    paths.write_json(instance_lock.lock_file(), {
        "pid": sleeper.pid, "host": "127.0.0.1",
        "port": free, "started_at": "2026-08-01T18:38:59",
    })

    assert instance_lock.running_instance() is None


def test_a_corrupt_lock_is_discarded_not_fatal(state):
    paths.write_json(instance_lock.lock_file(), {"nonsense": True})
    assert instance_lock.running_instance() is None

    instance_lock.lock_file().write_text("{not json", encoding="utf-8")
    assert instance_lock.running_instance() is None


def test_our_own_lock_is_not_a_conflict(state, held_port):
    """uvicorn's reloader re-enters this process; it must not refuse itself."""
    paths.write_json(instance_lock.lock_file(), {
        "pid": os.getpid(), "host": "127.0.0.1",
        "port": held_port, "started_at": "2026-08-15T09:29:30",
    })
    assert instance_lock.running_instance() is None


def test_acquire_then_release(state):
    instance_lock.acquire("127.0.0.1", 8000)
    written = paths.read_json(instance_lock.lock_file())
    assert written["pid"] == os.getpid()
    assert written["port"] == 8000

    instance_lock.release()
    assert not instance_lock.lock_file().exists()
    instance_lock.release()  # releasing twice must not raise


def test_the_lock_lives_with_the_ui_state_not_the_project(state):
    """VULN_ANALYZER_UI_STATE is what keeps tests off the user's real lock."""
    assert instance_lock.lock_file().parent == paths.ui_state_dir()
    assert "uistate" in str(instance_lock.lock_file())
