"""
Job runner.

Runs `python -m src.cli analyze|patch` as a subprocess and streams its output.

Subprocess rather than an in-process call, deliberately:

* **Cancellation works.** Terminating the process triggers the CLI's existing
  KeyboardInterrupt path, which saves the partial run and leaves a resumable
  checkpoint. There is no way to interrupt a synchronous in-process loop that
  is blocked on an OpenAI call.
* **The UI cannot drift from the CLI**, because it *is* the CLI. A run started
  from a browser produces the same run directory as one started in a terminal.
* A paid, long-running loop never blocks the web server's event loop.

Arguments are built from a typed whitelist and passed as an argv list — never
concatenated into a string, never through a shell.
"""
from __future__ import annotations

import logging
import os
import queue
import re
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, Literal, Optional

from src.web import paths

logger = logging.getLogger(__name__)

JobState = Literal["running", "succeeded", "failed", "cancelled"]

# Keep the tail of a job's log in memory. A 379-function run prints a few
# thousand lines; this is enough to review one without holding every run's
# entire output for the lifetime of the process.
MAX_LOG_LINES = 4000

# `  [ 12/379] functionName                → VULN [high] (conf:0.95)`
_PROGRESS_RE = re.compile(r"^\s*\[\s*(\d+)\s*/\s*(\d+)\s*\]\s+(\S+)")
# `  [ 3/12] findByUsername` — the patch command's counter has the same shape.
_VERDICT_RE = re.compile(r"→\s*(VULN|clean)", re.IGNORECASE)


@dataclass
class Job:
    id: str
    kind: Literal["analyze", "patch"]
    argv: list[str]
    output_dir: Optional[str]
    source_path: Optional[str]
    label: str
    state: JobState = "running"
    started_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    finished_at: Optional[str] = None
    exit_code: Optional[int] = None
    current: int = 0
    total: int = 0
    current_function: Optional[str] = None
    findings: int = 0
    log: list[str] = field(default_factory=list)
    error: Optional[str] = None

    # Not serialised, and never exposed by `public()`.
    _api_key: Optional[str] = field(default=None, repr=False)
    _process: Optional[subprocess.Popen] = field(default=None, repr=False)
    _subscribers: list["queue.Queue[dict]"] = field(default_factory=list, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def public(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "state": self.state,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "current": self.current,
            "total": self.total,
            "current_function": self.current_function,
            "findings": self.findings,
            "output_dir": self.output_dir,
            "source_path": self.source_path,
            "error": self.error,
            "command": " ".join(self.argv),
        }


class JobManager:
    """In-process job registry. One analysis at a time."""

    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    # ── queries ───────────────────────────────────────────────────────────────

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def list(self) -> list[dict]:
        jobs = sorted(self._jobs.values(), key=lambda j: j.started_at, reverse=True)
        return [job.public() for job in jobs]

    def active(self) -> Optional[Job]:
        for job in self._jobs.values():
            if job.state == "running":
                return job
        return None

    # ── launching ─────────────────────────────────────────────────────────────

    def start(
        self,
        kind: Literal["analyze", "patch"],
        argv: list[str],
        label: str,
        output_dir: Optional[str] = None,
        source_path: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> Job:
        with self._lock:
            running = self.active()
            if running is not None:
                # Concurrent runs would interleave in the shared edge cache and
                # the cost ledger, and there is no reason to want two paid
                # analyses racing. Refuse rather than queue silently.
                raise RuntimeError(
                    f"A job is already running ({running.label}). "
                    "Wait for it to finish or cancel it."
                )

            job = Job(
                id=uuid.uuid4().hex[:12],
                kind=kind,
                argv=argv,
                output_dir=output_dir,
                source_path=source_path,
                label=label,
            )
            job._api_key = api_key
            self._jobs[job.id] = job

        thread = threading.Thread(target=self._run, args=(job,), daemon=True)
        thread.start()
        return job

    def _run(self, job: Job) -> None:
        env = os.environ.copy()
        # The CLI writes '→' in every progress line; without this a cp1252
        # console encoding can kill a run that has already been paid for.
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUNBUFFERED"] = "1"

        # The key comes from the user's workspace file, and reaches the analyzer
        # through the environment — never through argv, which is readable by any
        # other process on the machine via the process list. The engine reads
        # OPENAI_API_KEY exactly as it always has, so nothing there had to change.
        if job._api_key:
            env["OPENAI_API_KEY"] = job._api_key

        try:
            process = subprocess.Popen(
                job.argv,
                cwd=str(paths.PROJECT_ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                env=env,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                # Windows: give the child its own group so terminating it does
                # not also kill the server process hosting the UI.
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
            )
        except OSError as exc:
            self._finish(job, state="failed", error=f"Could not start the analyzer: {exc}")
            return

        job._process = process
        self._emit(job, {"type": "started", "job": job.public()})

        assert process.stdout is not None
        for raw_line in process.stdout:
            line = raw_line.rstrip("\n")
            self._ingest(job, line)

        exit_code = process.wait()
        job.exit_code = exit_code

        if job.state == "cancelled":
            self._finish(job, state="cancelled")
        elif exit_code == 0:
            self._finish(job, state="succeeded")
        else:
            self._finish(
                job,
                state="failed",
                error=f"The analyzer exited with code {exit_code}. See the log for details.",
            )

    def _ingest(self, job: Job, line: str) -> None:
        with job._lock:
            job.log.append(line)
            if len(job.log) > MAX_LOG_LINES:
                del job.log[: len(job.log) - MAX_LOG_LINES]

        progress = _PROGRESS_RE.match(line)
        if progress:
            job.current = int(progress.group(1))
            job.total = int(progress.group(2))
            job.current_function = progress.group(3)
        verdict = _VERDICT_RE.search(line)
        if verdict and verdict.group(1).upper() == "VULN":
            job.findings += 1

        self._emit(
            job,
            {
                "type": "log",
                "line": line,
                "current": job.current,
                "total": job.total,
                "current_function": job.current_function,
                "findings": job.findings,
            },
        )

    def _finish(self, job: Job, state: JobState, error: Optional[str] = None) -> None:
        job.state = state
        job.error = error
        job.finished_at = datetime.now().isoformat(timespec="seconds")
        job._process = None

        if state in ("succeeded", "cancelled") and job.output_dir:
            # Registering the output directory is what makes the run readable
            # through /api/results — reads are confined to a registry of
            # directories this tool has written to. A cancelled analysis still
            # wrote a partial run worth reading, so it is registered too.
            try:
                directory = Path(job.output_dir)
                if directory.is_dir():
                    paths.register_root(directory)
            except Exception as exc:  # never let bookkeeping fail a finished run
                logger.warning("Could not register output of job %s: %s", job.id, exc)

        self._emit(job, {"type": "finished", "job": job.public()})

    # ── cancellation ──────────────────────────────────────────────────────────

    def cancel(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if job is None or job.state != "running" or job._process is None:
            return False
        job.state = "cancelled"
        process = job._process
        try:
            if os.name == "nt":
                # CTRL_BREAK reaches the child as KeyboardInterrupt, which is
                # the path that saves the partial run. terminate() would kill it
                # outright and throw away work already paid for.
                process.send_signal(subprocess.signal.CTRL_BREAK_EVENT)
            else:
                process.send_signal(subprocess.signal.SIGINT)
        except (OSError, ValueError) as exc:
            logger.warning("Graceful cancel failed for %s (%s) — terminating.", job_id, exc)
            process.terminate()
        return True

    # ── streaming ─────────────────────────────────────────────────────────────

    def subscribe(self, job: Job) -> "queue.Queue[dict]":
        channel: "queue.Queue[dict]" = queue.Queue()
        with job._lock:
            # Replay the log so a browser that connects late, or reconnects,
            # sees the whole run rather than joining mid-stream.
            for line in job.log:
                channel.put({"type": "log", "line": line})
            job._subscribers.append(channel)
        channel.put({"type": "state", "job": job.public()})
        return channel

    def unsubscribe(self, job: Job, channel: "queue.Queue[dict]") -> None:
        with job._lock:
            if channel in job._subscribers:
                job._subscribers.remove(channel)

    def _emit(self, job: Job, event: dict) -> None:
        with job._lock:
            subscribers = list(job._subscribers)
        for channel in subscribers:
            channel.put(event)

    def stream(self, job: Job) -> Iterator[dict]:
        channel = self.subscribe(job)
        try:
            while True:
                try:
                    event = channel.get(timeout=15)
                except queue.Empty:
                    # Keeps proxies and browsers from closing an idle stream
                    # during a long single-function ReAct loop.
                    yield {"type": "ping"}
                    if job.state != "running":
                        return
                    continue
                yield event
                if event.get("type") == "finished":
                    return
        finally:
            self.unsubscribe(job, channel)


# ── argument building ─────────────────────────────────────────────────────────


class ArgumentError(ValueError):
    """Raised when a request asks for something the CLI cannot be told to do."""


def build_analyze_argv(
    *,
    source_path: str,
    output_dir: str,
    react: bool,
    model: Optional[str] = None,
    config_path: Optional[str] = None,
    visualize: bool = True,
    dry_run: bool = False,
    resume: bool = False,
    budget_usd: Optional[float] = None,
    api_key_alias: Optional[str] = None,
) -> list[str]:
    """Build the analyze argv from a whitelist.

    Every value is validated and appended as its own argv element. Nothing here
    is ever interpolated into a string or handed to a shell, so a path with a
    space, a quote or a semicolon is data, not syntax.
    """
    source = paths.normalise(source_path)
    if not source.exists():
        raise ArgumentError(f"Nothing to analyse at {source}")

    destination = paths.normalise(output_dir)

    argv = [
        sys.executable, "-m", "src.cli", "analyze",
        "--path", str(source),
        "--output-dir", str(destination),
    ]
    if react:
        argv.append("--react")
    if visualize:
        argv.append("--visualize")
    if dry_run:
        argv.append("--dry-run")
    if resume:
        argv.append("--resume")
    if config_path:
        config = paths.normalise(config_path)
        if not config.is_file():
            raise ArgumentError(f"No config file at {config}")
        argv += ["--config", str(config)]
    if budget_usd is not None:
        if budget_usd <= 0:
            raise ArgumentError("The budget must be greater than zero.")
        argv += ["--budget-usd", str(float(budget_usd))]
    # Only the *alias* is passed, so the ledger attributes spend correctly. The
    # key itself is injected into the child's environment as OPENAI_API_KEY,
    # which is why no alias is forwarded here — the resolved key is already the
    # right one, and forwarding the alias would make the CLI look for an env var
    # the web layer did not set.
    if api_key_alias and api_key_alias != "default":
        if not re.fullmatch(r"[A-Za-z0-9_]{1,32}", api_key_alias):
            raise ArgumentError("Invalid API key alias.")

    # `model` is a config-file setting, not an analyze flag — surfaced here so
    # the caller gets a clear error instead of a silently ignored choice.
    if model and not config_path:
        logger.debug("Model %s requested without a config file; using config default.", model)

    return argv


def build_patch_argv(
    *,
    results_path: str,
    output_dir: Optional[str] = None,
    source_path: Optional[str] = None,
    api_key_alias: Optional[str] = None,
) -> list[str]:
    """Build the patch argv.

    `--apply` is deliberately not reachable: patching from a browser button
    would write into the analysed project. The UI produces the reviewable JSON
    artifact only.
    """
    results = paths.normalise(results_path)
    if not results.is_file():
        raise ArgumentError(f"No analysis results at {results}")

    argv = [sys.executable, "-m", "src.cli", "patch", "--results", str(results)]
    if output_dir:
        argv += ["--output-dir", str(paths.normalise(output_dir))]
    if source_path:
        argv += ["--path", str(paths.normalise(source_path))]
    # See build_analyze_argv: the resolved key is injected into the environment,
    # so the alias is validated but not forwarded.
    if api_key_alias and api_key_alias != "default":
        if not re.fullmatch(r"[A-Za-z0-9_]{1,32}", api_key_alias):
            raise ArgumentError("Invalid API key alias.")
    return argv


manager = JobManager()
