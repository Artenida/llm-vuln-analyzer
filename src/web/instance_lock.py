"""
Single-instance guard for `python -m src.cli ui`.

Nothing stopped a second UI server from starting, so every restart that did not
cleanly shut down left the old one alive. Seventeen of them accumulated on ports
8123-8162 over a single evening, each holding a port and able to launch paid
analysis jobs long after the window that started it was closed.

The guard is a lock file holding the pid, host and port of the running server.
It is checked on startup and refuses rather than adding to the pile.

**Two signals, both required**, because either alone is wrong:

* the *pid* alone would refuse forever if the server died without releasing the
  lock, and pids are recycled — a stale entry eventually names something else;
* the *port* alone would miss precisely the case that caused this, since those
  seventeen servers were each on a different port.

A lock whose pid is alive *and* whose port is still bound is a running server.
Anything else is stale and gets cleared.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.web import paths

logger = logging.getLogger(__name__)

# Windows: STILL_ACTIVE, the exit code of a process that has not exited.
_STILL_ACTIVE = 259


@dataclass
class RunningInstance:
    pid: int
    host: str
    port: int
    started_at: str

    @property
    def url(self) -> str:
        display = "localhost" if self.host in ("127.0.0.1", "0.0.0.0") else self.host
        return f"http://{display}:{self.port}"


def lock_file() -> Path:
    return paths.ui_state_dir() / "ui.lock"


# ── liveness ──────────────────────────────────────────────────────────────────


def pid_alive(pid: int) -> bool:
    """Whether a process with this pid exists.

    Deliberately not `os.kill(pid, 0)`: that is the POSIX idiom, but on Windows
    `os.kill` maps onto TerminateProcess and would *kill* the very process this
    is only supposed to ask about.
    """
    if pid <= 0:
        return False

    if os.name == "nt":
        import ctypes
        from ctypes import wintypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return False
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == _STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    return True


def port_in_use(host: str, port: int) -> bool:
    """Whether something is already listening on this address."""
    probe_host = "127.0.0.1" if host == "0.0.0.0" else host
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.4)
        return sock.connect_ex((probe_host, port)) == 0


def terminate(pid: int) -> bool:
    """Stop a process by pid. Used only by `ui --replace`."""
    if not pid_alive(pid):
        return True
    try:
        if os.name == "nt":
            import ctypes

            PROCESS_TERMINATE = 0x0001
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
            if not handle:
                return False
            try:
                return bool(kernel32.TerminateProcess(handle, 1))
            finally:
                kernel32.CloseHandle(handle)
        import signal

        os.kill(pid, signal.SIGTERM)
        return True
    except OSError as exc:
        logger.warning("Could not stop pid %s: %s", pid, exc)
        return False


# ── the lock ──────────────────────────────────────────────────────────────────


def running_instance() -> Optional[RunningInstance]:
    """The UI server already running, or None.

    A lock that fails either test is stale and removed, so a crashed server
    never blocks the next start.
    """
    data = paths.read_json(lock_file())
    if not isinstance(data, dict):
        return None

    try:
        instance = RunningInstance(
            pid=int(data["pid"]),
            host=str(data["host"]),
            port=int(data["port"]),
            started_at=str(data.get("started_at", "unknown")),
        )
    except (KeyError, TypeError, ValueError):
        release()
        return None

    if instance.pid == os.getpid():
        return None  # our own lock, from a reload

    if pid_alive(instance.pid) and port_in_use(instance.host, instance.port):
        return instance

    release()
    return None


def acquire(host: str, port: int) -> None:
    """Record this process as the running UI server."""
    paths.write_json(lock_file(), {
        "pid": os.getpid(),
        "host": host,
        "port": port,
        "started_at": datetime.now().isoformat(timespec="seconds"),
        "argv": " ".join(sys.argv),
    })


def release() -> None:
    """Drop the lock. Safe to call when there is none."""
    try:
        lock_file().unlink()
    except (FileNotFoundError, OSError):
        pass
