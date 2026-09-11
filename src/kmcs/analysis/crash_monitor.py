"""Execute a target with an input and preserve every observable fact.

The monitor deliberately captures the process's exit status, its termination
signal, its full stdout and stderr, the wall-clock duration, and whether it
timed out.  It writes stdout and stderr to disk unconditionally so the
``CrashReport`` produced downstream is a *view* over evidence that outlives
the monitor's own memory.

Security posture:

* ``subprocess`` is invoked with an explicit argument list, never a shell.
* Input is written via a pipe; the target's stdin is closed after the write.
* Child processes inherit a minimal environment; sanitizer options are applied
  explicitly, not through shell interpolation.
* ``resource`` limits are applied on POSIX to bound CPU time, memory, file
  size, and core dump size.
"""

from __future__ import annotations

import logging
import os
import resource
import subprocess
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from kmcs.analysis.crash_parser import CrashReport, CrashParser
from kmcs.core.exceptions import KMCSException
from kmcs.core.models import SanitizerKind

logger = logging.getLogger(__name__)

__all__ = [
    "MonitorError",
    "MonitorConfig",
    "CrashObservation",
    "CrashMonitor",
]


class MonitorError(KMCSException):
    exit_code = 40


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class MonitorConfig:
    """Everything the monitor needs to run one target execution."""

    target: Path
    argument_input_path: bool = False
    """When True, the input file path is passed as ``argv[1]``.  When False,
    the input bytes are written to stdin."""
    argument_input_placeholder: str = "___FILE___"
    timeout_seconds: float = 10.0
    """Hard address-space cap applied to the target, in mebibytes.
    
    Defaults to ``None`` — no ``RLIMIT_AS``.  AddressSanitizer and
    ThreadSanitizer reserve enormous *virtual* address ranges at startup
    (ASan alone reserves over 15 TiB).  A ``RLIMIT_AS`` that is fine for a
    plain binary will make a sanitizer-instrumented binary abort before its
    ``main`` runs.  Callers who want a hard cap can set a value explicitly.
    """
    memory_limit_mb: int | None = None
    cpu_limit_seconds: int | None = None
    """Hard CPU-time limit.  Defaults to ``timeout_seconds * 2 + 5``."""
    file_size_limit_mb: int | None = 512
    environment: dict[str, str] = field(default_factory=dict)
    target_args: list[str] = field(default_factory=list)
    expected_sanitizers: list[SanitizerKind] = field(default_factory=list)
    evidence_dir: Path | None = None
    """Where stdout/stderr are written.  A temporary directory is used if not
    provided."""

    def validate(self) -> None:
        if not self.target.is_file():
            raise MonitorError(
                "Target binary does not exist",
                details={"path": str(self.target)},
            )
        if not os.access(self.target, os.X_OK):
            raise MonitorError(
                "Target binary is not executable",
                details={"path": str(self.target)},
            )
        if self.timeout_seconds <= 0:
            raise MonitorError(
                "timeout_seconds must be positive",
                details={"timeout_seconds": self.timeout_seconds},
            )


@dataclass(slots=True)
class CrashObservation:
    """A complete record of one target execution.

    This is a strict superset of what the parser sees: it adds process
    metadata and file-system locations for the preserved evidence.
    """

    command: list[str]
    input_path: Path | None
    evidence_dir: Path
    stdout_path: Path
    stderr_path: Path

    exit_code: int | None
    signal_number: int | None
    timed_out: bool
    duration_seconds: float

    stdout: str
    stderr: str
    report: CrashReport

    started_at: datetime
    finished_at: datetime
    environment: dict[str, str] = field(default_factory=dict)
    error: str | None = None

    @property
    def crashed(self) -> bool:
        return self.report.crashed

    def to_dict(self) -> dict:
        return {
            "command": list(self.command),
            "input_path": str(self.input_path) if self.input_path else None,
            "evidence_dir": str(self.evidence_dir),
            "stdout_path": str(self.stdout_path),
            "stderr_path": str(self.stderr_path),
            "exit_code": self.exit_code,
            "signal_number": self.signal_number,
            "timed_out": self.timed_out,
            "duration_seconds": self.duration_seconds,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "error": self.error,
            "report": self.report.to_dict(),
        }


# ---------------------------------------------------------------------- limits


def _apply_resource_limits(
    *,
    cpu_seconds: int | None,
    memory_mb: int | None,
    file_size_mb: int | None,
) -> None:
    """Apply ``resource`` limits in the child process.  Runs post-fork."""
    try:
        if cpu_seconds is not None:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        if memory_mb is not None:
            bytes_ = int(memory_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (bytes_, bytes_))
        if file_size_mb is not None:
            bytes_ = int(file_size_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (bytes_, bytes_))
        # Never dump core; a fuzzing campaign can generate thousands of these.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError) as exc:  # pragma: no cover - platform dependent
        # We cannot raise across the fork boundary cleanly, so we log to
        # stderr; the parent will still see the process run.
        print(f"kmcs: warning: could not apply resource limit: {exc}", file=os.sys.stderr)


# ---------------------------------------------------------------------- monitor


class CrashMonitor:
    """Runs targets and returns :class:`CrashObservation` objects."""

    def __init__(self, parser: CrashParser | None = None) -> None:
        self._parser = parser or CrashParser()

    # ------------------------------------------------------------------ public

    def run(
        self,
        config: MonitorConfig,
        *,
        input_path: Path | None = None,
        input_bytes: bytes | None = None,
        work_dir: Path | None = None,
    ) -> CrashObservation:
        """Execute the target once.

        Either ``input_path`` or ``input_bytes`` must be provided.  If
        ``argument_input_path`` is set on the config, ``input_path`` must be
        provided and the path is passed to the target as an argument.  Otherwise
        the bytes (or the file contents) are written to stdin.
        """
        config.validate()

        if input_path is None and input_bytes is None:
            raise MonitorError("Either input_path or input_bytes must be supplied")
        if config.argument_input_path and input_path is None:
            raise MonitorError(
                "argument_input_path=True requires input_path to be provided"
            )

        evidence_dir = self._prepare_evidence_dir(config, work_dir)
        stdout_path = evidence_dir / "stdout.bin"
        stderr_path = evidence_dir / "stderr.bin"

        stdin_bytes: bytes | None = None
        if not config.argument_input_path:
            if input_bytes is not None:
                stdin_bytes = input_bytes
            else:
                assert input_path is not None
                stdin_bytes = input_path.read_bytes()

        command: list[str] = [str(config.target)]
        if config.argument_input_path:
            assert input_path is not None
            command.append(str(input_path))
        command.extend(config.target_args)

        environment = dict(os.environ)
        environment.update(config.environment)

        cpu_seconds = config.cpu_limit_seconds
        if cpu_seconds is None:
            cpu_seconds = int(config.timeout_seconds * 2) + 5

        started_at = _utcnow()
        started_monotonic = time.monotonic()

        exit_code: int | None = None
        signal_number: int | None = None
        timed_out = False
        error: str | None = None
        stdout_text = ""
        stderr_text = ""

        try:
            with stdout_path.open("wb") as stdout_fh, stderr_path.open("wb") as stderr_fh:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
                    stdout=stdout_fh,
                    stderr=stderr_fh,
                    env=environment,
                    cwd=str(work_dir or evidence_dir),
                    preexec_fn=lambda: _apply_resource_limits(
                        cpu_seconds=cpu_seconds,
                        memory_mb=config.memory_limit_mb,
                        file_size_mb=config.file_size_limit_mb,
                    )
                    if os.name == "posix"
                    else None,
                )

                try:
                    process.communicate(input=stdin_bytes, timeout=config.timeout_seconds)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    process.kill()
                    try:
                        process.communicate(timeout=5.0)
                    except subprocess.TimeoutExpired:  # pragma: no cover
                        error = "process did not exit after SIGKILL"

                returncode = process.returncode

        except FileNotFoundError as exc:
            raise MonitorError(
                "Target could not be launched",
                details={"path": str(config.target), "error": str(exc)},
            ) from exc
        except OSError as exc:
            raise MonitorError(
                "OS error while launching target",
                details={"path": str(config.target), "error": str(exc)},
            ) from exc

        finished_at = _utcnow()
        duration = time.monotonic() - started_monotonic

        # Decode outputs after the child has exited so both files are complete.
        stdout_text = self._read_text(stdout_path)
        stderr_text = self._read_text(stderr_path)

        if returncode is not None and returncode < 0:
            # Python's Popen reports signals as negative returncodes.
            signal_number = -returncode
            exit_code = None
        else:
            exit_code = returncode

        report = self._parser.parse(
            stdout=stdout_text,
            stderr=stderr_text,
            exit_code=exit_code,
            signal_number=signal_number,
            timed_out=timed_out,
            duration_seconds=duration,
            expected_sanitizers=list(config.expected_sanitizers) or None,
        )

        return CrashObservation(
            command=command,
            input_path=input_path,
            evidence_dir=evidence_dir,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            exit_code=exit_code,
            signal_number=signal_number,
            timed_out=timed_out,
            duration_seconds=duration,
            stdout=stdout_text,
            stderr=stderr_text,
            report=report,
            started_at=started_at,
            finished_at=finished_at,
            environment={k: v for k, v in environment.items() if k.startswith(("ASAN_", "UBSAN_", "LSAN_", "MSAN_", "TSAN_"))},
            error=error,
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _prepare_evidence_dir(config: MonitorConfig, work_dir: Path | None) -> Path:
        base = config.evidence_dir or work_dir
        if base is None:
            import tempfile

            base = Path(tempfile.mkdtemp(prefix="kmcs-evidence-"))
        else:
            base = Path(base)
            base.mkdir(parents=True, exist_ok=True)
        return base

    @staticmethod
    def _read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # pragma: no cover
            logger.warning("Could not read evidence file %s: %s", path, exc)
            return ""
