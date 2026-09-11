"""Safe subprocess invocation.

Every external process KMCS launches — compilers, fuzzers, sanitized targets,
GDB, symbolizers — goes through :class:`SafeSubprocessRunner`.  The runner:

* accepts argv as a sequence, never a string,
* never uses ``shell=True``,
* applies an environment allowlist so secrets do not leak into fuzzers,
* applies POSIX resource limits,
* enforces a wall-clock timeout, killing the whole process group on expiry,
* writes stdout and stderr to files or memory, returning a structured result.

No caller should ever call :class:`subprocess.Popen` directly.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO

from kmcs.security.limits import ResourceLimits, apply_limits_in_child, limits_supported

logger = logging.getLogger(__name__)

__all__ = [
    "SafeSubprocessError",
    "SafeSubprocessResult",
    "SafeSubprocessRunner",
    "minimal_environment",
]


# Environment variables a fuzzer or target might legitimately need.  Anything
# outside this list must be passed explicitly by the caller.
_ENV_ALLOWLIST: frozenset[str] = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TZ",
        "TMPDIR",
        "TERM",
        # Sanitizer runtimes
        "ASAN_OPTIONS",
        "UBSAN_OPTIONS",
        "LSAN_OPTIONS",
        "MSAN_OPTIONS",
        "TSAN_OPTIONS",
        # AFL++
        "AFL_NO_UI",
        "AFL_SKIP_CPUFREQ",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES",
        "AFL_USE_ASAN",
        "AFL_USE_UBSAN",
        "AFL_USE_LSAN",
        "AFL_USE_MSAN",
        "AFL_USE_TSAN",
        "AFL_PATH",
    }
)


def minimal_environment(
    base: Mapping[str, str] | None = None,
    *,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return an environment filtered to the allowlist, plus explicit extras.

    ``base`` defaults to ``os.environ``.  When ``extra`` is provided, its
    entries override the filtered environment (explicit wins over implicit).
    """
    source = dict(os.environ if base is None else base)
    filtered = {k: v for k, v in source.items() if k in _ENV_ALLOWLIST}
    if extra:
        filtered.update(extra)
    return filtered


class SafeSubprocessError(Exception):
    """A subprocess could not be launched, or completed abnormally."""

    def __init__(
        self, message: str, *, details: dict[str, object] | None = None
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, object] = dict(details or {})


@dataclass(slots=True)
class SafeSubprocessResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool
    signal_number: int | None
    stdout_path: Path | None = None
    stderr_path: Path | None = None

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def to_dict(self) -> dict[str, object]:
        return {
            "argv": list(self.argv),
            "returncode": self.returncode,
            "duration_seconds": self.duration_seconds,
            "timed_out": self.timed_out,
            "signal_number": self.signal_number,
            "stdout_path": str(self.stdout_path) if self.stdout_path else None,
            "stderr_path": str(self.stderr_path) if self.stderr_path else None,
            "stdout_bytes": len(self.stdout.encode("utf-8")),
            "stderr_bytes": len(self.stderr.encode("utf-8")),
        }


class SafeSubprocessRunner:
    """Runs a subprocess under a fixed set of safety controls."""

    def __init__(
        self,
        *,
        limits: ResourceLimits | None = None,
        environment: Mapping[str, str] | None = None,
        environment_extra: Mapping[str, str] | None = None,
        working_directory: Path | None = None,
        new_session: bool = True,
    ) -> None:
        self._limits = limits
        self._environment = minimal_environment(
            environment, extra=environment_extra
        )
        self._cwd = working_directory
        self._new_session = new_session and os.name == "posix"

    # ------------------------------------------------------------------ public

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin_bytes: bytes | None = None,
        timeout_seconds: float = 60.0,
        capture_dir: Path | None = None,
        capture_names: tuple[str, str] = ("stdout.bin", "stderr.bin"),
    ) -> SafeSubprocessResult:
        if not argv:
            raise SafeSubprocessError("argv must not be empty")
        for index, token in enumerate(argv):
            if not isinstance(token, str):
                raise SafeSubprocessError(
                    "argv entries must be strings",
                    details={"index": index, "type": type(token).__name__},
                )
            if "\x00" in token:
                raise SafeSubprocessError(
                    "argv entry contains a NUL byte", details={"index": index}
                )

        if timeout_seconds <= 0:
            raise SafeSubprocessError(
                "timeout_seconds must be positive",
                details={"timeout_seconds": timeout_seconds},
            )

        if capture_dir is not None:
            capture_dir = Path(capture_dir)
            capture_dir.mkdir(parents=True, exist_ok=True)
            stdout_handle, stdout_path = self._open_capture(
                capture_dir / capture_names[0]
            )
            stderr_handle, stderr_path = self._open_capture(
                capture_dir / capture_names[1]
            )
        else:
            stdout_handle, stdout_path = None, None
            stderr_handle, stderr_path = None, None

        preexec = None
        if self._limits is not None and limits_supported():
            limits = self._limits
            preexec = lambda: apply_limits_in_child(limits)  # noqa: E731

        started_monotonic = time.monotonic()
        returncode = -1
        timed_out = False
        signal_number: int | None = None
        stdout_text = ""
        stderr_text = ""

        try:
            process = subprocess.Popen(
                list(argv),
                stdin=subprocess.PIPE if stdin_bytes is not None else subprocess.DEVNULL,
                stdout=stdout_handle or subprocess.PIPE,
                stderr=stderr_handle or subprocess.PIPE,
                cwd=str(self._cwd) if self._cwd else None,
                env=self._environment,
                preexec_fn=preexec,
                start_new_session=self._new_session,
            )
        except FileNotFoundError as exc:
            self._close(stdout_handle)
            self._close(stderr_handle)
            raise SafeSubprocessError(
                "Executable was not found",
                details={"argv": list(argv), "error": str(exc)},
            ) from exc
        except PermissionError as exc:
            self._close(stdout_handle)
            self._close(stderr_handle)
            raise SafeSubprocessError(
                "Executable is not permitted to run",
                details={"argv": list(argv), "error": str(exc)},
            ) from exc
        except OSError as exc:
            self._close(stdout_handle)
            self._close(stderr_handle)
            raise SafeSubprocessError(
                "OS error while launching subprocess",
                details={"argv": list(argv), "error": str(exc)},
            ) from exc

        try:
            stdout_bytes, stderr_bytes = process.communicate(
                input=stdin_bytes, timeout=timeout_seconds
            )
            returncode = process.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            self._terminate(process)
            try:
                stdout_bytes, stderr_bytes = process.communicate(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    stdout_bytes, stderr_bytes = process.communicate(timeout=5.0)
                except subprocess.TimeoutExpired:
                    stdout_bytes, stderr_bytes = b"", b""
            returncode = process.returncode

        duration = time.monotonic() - started_monotonic

        if capture_dir is not None:
            self._close(stdout_handle)
            self._close(stderr_handle)
            stdout_text = self._read_text(stdout_path)
            stderr_text = self._read_text(stderr_path)
        else:
            stdout_text = (stdout_bytes or b"").decode("utf-8", errors="replace")
            stderr_text = (stderr_bytes or b"").decode("utf-8", errors="replace")

        if returncode is not None and returncode < 0:
            signal_number = -returncode
            returncode = 128 + signal_number

        return SafeSubprocessResult(
            argv=tuple(argv),
            returncode=returncode,
            stdout=stdout_text,
            stderr=stderr_text,
            duration_seconds=duration,
            timed_out=timed_out,
            signal_number=signal_number,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _open_capture(path: Path) -> tuple[IO[bytes], Path]:
        handle = path.open("wb")
        return handle, path

    @staticmethod
    def _close(handle: IO[bytes] | None) -> None:
        if handle is None:
            return
        try:
            handle.close()
        except OSError:  # pragma: no cover
            pass

    @staticmethod
    def _read_text(path: Path | None) -> str:
        if path is None or not path.is_file():
            return ""
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:  # pragma: no cover
            return ""

    @staticmethod
    def _terminate(process: subprocess.Popen) -> None:
        """Terminate the process, then its whole group if it has one."""
        try:
            if os.name == "posix":
                # Kill the entire process group so that a hung fuzzer does not
                # leave orphaned sanitized targets behind.
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except (ProcessLookupError, PermissionError, OSError):
                    process.terminate()
            else:  # pragma: no cover - Windows
                process.terminate()
        except (ProcessLookupError, OSError):
            pass

    # ------------------------------------------------------------------ context

    def __enter__(self) -> "SafeSubprocessRunner":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


def _shell_free_repr(argv: Sequence[str]) -> str:
    """Human-readable argv for logs.  Never executed."""
    return " ".join(argv)


# Silence unused-import warning in strict linters.
_ = (sys, logging, field)
