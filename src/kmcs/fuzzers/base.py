"""Common fuzzer interface.

The interface is intentionally narrow:

* :meth:`check_availability` — a real system check
* :meth:`plan`               — build a command without running it
* :meth:`start` / :meth:`stop`
* :meth:`stats`              — the engine's *own* numbers, or nothing

Every numeric field on :class:`FuzzerStats` is ``Optional`` because KMCS refuses
to invent a value it did not read from the engine.
"""

from __future__ import annotations

import logging
import subprocess
import threading
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from kmcs.core.exceptions import KMCSException
from kmcs.core.models import FuzzerKind

if TYPE_CHECKING:  # pragma: no cover - typing only
    from kmcs.targets.detector import EnvironmentDetector

logger = logging.getLogger(__name__)

__all__ = [
    "FuzzerError",
    "FuzzerUnavailableError",
    "FuzzerStartError",
    "FuzzerStatus",
    "FuzzerAvailability",
    "FuzzerStats",
    "FuzzerConfig",
    "FuzzerAdapter",
]


class FuzzerError(KMCSException):
    exit_code = 20


class FuzzerUnavailableError(FuzzerError):
    exit_code = 21


class FuzzerStartError(FuzzerError):
    exit_code = 22


class FuzzerStatus(str, Enum):
    UNAVAILABLE = "unavailable"
    NOT_STARTED = "not-started"
    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class FuzzerAvailability:
    fuzzer: FuzzerKind
    available: bool
    binary: str | None = None
    version: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "fuzzer": self.fuzzer.value,
            "available": self.available,
            "binary": self.binary,
            "version": self.version,
            "reason": self.reason,
        }


@dataclass(slots=True)
class FuzzerStats:
    """Engine-reported metrics.

    ``source`` names the file or stream the numbers came from, so a human can
    check KMCS's work.  Fields left as ``None`` were not available in that
    source.  KMCS never fills in a plausible-looking default.
    """

    source: str
    collected_at: datetime = field(default_factory=_utcnow)
    runtime_seconds: float | None = None
    executions: int | None = None
    executions_per_second: float | None = None
    corpus_count: int | None = None
    crashes: int | None = None
    unique_crashes: int | None = None
    hangs: int | None = None
    coverage_percent: float | None = None
    cycles_done: int | None = None
    raw: dict[str, str] = field(default_factory=dict)

    @classmethod
    def unavailable(cls, source: str) -> "FuzzerStats":
        return cls(source=source)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "collected_at": self.collected_at.isoformat(),
            "runtime_seconds": self.runtime_seconds,
            "executions": self.executions,
            "executions_per_second": self.executions_per_second,
            "corpus_count": self.corpus_count,
            "crashes": self.crashes,
            "unique_crashes": self.unique_crashes,
            "hangs": self.hangs,
            "coverage_percent": self.coverage_percent,
            "cycles_done": self.cycles_done,
            "raw": dict(self.raw),
        }


@dataclass(slots=True)
class FuzzerConfig:
    """Everything an adapter needs to launch one fuzzer instance."""

    target_binary: Path
    input_dir: Path
    output_dir: Path
    duration_seconds: int | None = None
    workers: int = 1
    timeout_seconds: float = 5.0
    memory_limit_mb: int | None = None
    environment: dict[str, str] = field(default_factory=dict)
    target_args: list[str] = field(default_factory=list)
    extra_args: list[str] = field(default_factory=list)

    def validate(self) -> None:
        if not self.target_binary.is_file():
            raise FuzzerError(
                "Target binary does not exist",
                details={"path": str(self.target_binary)},
            )
        if not self.input_dir.is_dir():
            raise FuzzerError(
                "Input directory does not exist",
                details={"path": str(self.input_dir)},
            )
        if self.duration_seconds is not None and self.duration_seconds < 1:
            raise FuzzerError(
                "duration_seconds must be at least 1",
                details={"duration_seconds": self.duration_seconds},
            )
        if self.workers < 1:
            raise FuzzerError("workers must be at least 1")

    def ensure_output_dir(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)


class FuzzerAdapter(ABC):
    """Base class for every fuzzer adapter."""

    kind: ClassVar[FuzzerKind]

    def __init__(self, config: FuzzerConfig) -> None:
        self._config = config
        self._process: subprocess.Popen[bytes] | None = None
        self._log_handle: Any | None = None
        self._lock = threading.RLock()
        self._status: FuzzerStatus = FuzzerStatus.NOT_STARTED
        self._started_at: datetime | None = None
        self._stopped_at: datetime | None = None
        self._log_path: Path = config.output_dir / f"{self._slug()}.log"

    # ------------------------------------------------------------------ helpers

    def _slug(self) -> str:
        return self.kind.value.replace("+", "p").replace("/", "-")

    @property
    def config(self) -> FuzzerConfig:
        return self._config

    @property
    def log_path(self) -> Path:
        return self._log_path

    @property
    def started_at(self) -> datetime | None:
        return self._started_at

    @property
    def stopped_at(self) -> datetime | None:
        return self._stopped_at

    # ------------------------------------------------------------------ interface

    @classmethod
    @abstractmethod
    def check_availability(cls, detector: "EnvironmentDetector") -> FuzzerAvailability:
        """Return whether this engine is usable on the current system."""

    @abstractmethod
    def plan(self) -> tuple[list[str], dict[str, str]]:
        """Return ``(command, environment)`` without starting anything."""

    @abstractmethod
    def stats(self) -> FuzzerStats:
        """Read the engine's own statistics, or return ``unavailable()``."""

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        with self._lock:
            if self._status is FuzzerStatus.RUNNING:
                raise FuzzerStartError("Fuzzer is already running")

            self._config.validate()
            self._config.ensure_output_dir()
            command, environment = self.plan()

            logger.info("%s starting: %s", self.kind.value, " ".join(command))

            try:
                self._log_handle = self._log_path.open("wb")
                self._process = subprocess.Popen(
                    command,
                    stdout=self._log_handle,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    env=environment,
                    cwd=str(self._config.output_dir),
                )
            except (OSError, FileNotFoundError) as exc:
                self._status = FuzzerStatus.FAILED
                if self._log_handle is not None:
                    self._log_handle.close()
                    self._log_handle = None
                raise FuzzerStartError(
                    f"Failed to launch {self.kind.value}",
                    details={"error": str(exc), "command": command},
                ) from exc

            self._status = FuzzerStatus.RUNNING
            self._started_at = _utcnow()

    def stop(self, *, timeout: float = 10.0) -> None:
        with self._lock:
            process = self._process
            if process is None:
                return

            if process.poll() is None:
                try:
                    process.terminate()
                except (OSError, ValueError):  # pragma: no cover
                    pass
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    try:
                        process.wait(timeout=5.0)
                    except subprocess.TimeoutExpired:  # pragma: no cover
                        logger.warning(
                            "%s process did not exit after SIGKILL", self.kind.value
                        )

            self._stopped_at = _utcnow()
            if self._status is FuzzerStatus.RUNNING:
                returncode = process.returncode
                self._status = (
                    FuzzerStatus.STOPPED
                    if returncode in (0, None, -15, -9, -2)
                    else FuzzerStatus.FAILED
                )

            if self._log_handle is not None:
                self._log_handle.close()
                self._log_handle = None

    # ------------------------------------------------------------------ queries

    @property
    def returncode(self) -> int | None:
        if self._process is None:
            return None
        return self._process.poll()

    def is_running(self) -> bool:
        if self._process is None:
            return False
        return self._process.poll() is None

    @property
    def status(self) -> FuzzerStatus:
        with self._lock:
            if self._status is FuzzerStatus.RUNNING and not self.is_running():
                returncode = self.returncode
                self._status = (
                    FuzzerStatus.FAILED
                    if returncode not in (0, None, -15, -9, -2)
                    else FuzzerStatus.STOPPED
                )
            return self._status

    # ------------------------------------------------------------------ utilities

    def _read_log_text(self) -> str:
        """Return the fuzzer's captured stdout/stderr, or an empty string."""
        if not self._log_path.is_file():
            return ""
        try:
            return self._log_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:  # pragma: no cover
            logger.warning("Could not read %s: %s", self._log_path, exc)
            return ""

       # ------------------------------------------------------------------ artifacts

    def artifact_files(self) -> list[Path]:
        """Return fuzzer-written crash / hang / OOM artifacts.

        Implementations with a well-defined crash directory override this.
        The base class returns an empty list rather than guessing.
        """
        return []


    def _base_environment(self) -> dict[str, str]:
        import os

        env = dict(os.environ)
        env.update(self._config.environment)
        return env
