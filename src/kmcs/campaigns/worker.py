"""One fuzzer instance, plus crash collection.

A worker is responsible for exactly one external fuzzer process.  It:

1. validates its inputs (target binary, corpus directory, output directory),
2. launches the fuzzer via a :class:`~kmcs.fuzzers.base.FuzzerAdapter`,
3. polls the adapter for statistics and artifacts at a fixed interval,
4. re-runs each new artifact through a :class:`~kmcs.analysis.crash_detector.CrashDetector`,
5. publishes telemetry and, when a crash is confirmed, persists it,
6. shuts down cleanly on request.

Workers are designed to run in their own thread.  The class itself is *not*
thread-safe for concurrent method calls — the scheduler calls ``run()`` from
exactly one thread per worker and never touches other methods from elsewhere
except :meth:`request_stop`, which is safe.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from kmcs.analysis.crash_detector import CrashDetector
from kmcs.analysis.crash_monitor import MonitorConfig
from kmcs.campaigns.telemetry import TelemetryAggregator
from kmcs.core.events import EventBus, EventType
from kmcs.core.exceptions import KMCSException
from kmcs.core.models import FuzzerKind, SanitizerKind
from kmcs.database.database import Database
from kmcs.fuzzers.base import (
    FuzzerAdapter,
    FuzzerConfig,
    FuzzerError,
    FuzzerStats,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from kmcs.sanitizers.base import SanitizerAdapter

logger = logging.getLogger(__name__)

__all__ = [
    "WorkerError",
    "WorkerStatus",
    "WorkerConfig",
    "WorkerResult",
    "CampaignWorker",
]


class WorkerError(KMCSException):
    exit_code = 60


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class WorkerStatus(str, Enum):
    NOT_STARTED = "not-started"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass(slots=True)
class WorkerConfig:
    """Everything a worker needs to run one fuzzer instance."""

    campaign_id: str | None
    worker_index: int
    target_id: str | None
    target_binary: Path
    corpus_dir: Path
    output_dir: Path
    fuzzer: FuzzerKind
    sanitizers: list[SanitizerKind] = field(default_factory=list)
    duration_seconds: int | None = None
    timeout_seconds: float = 5.0
    memory_limit_mb: int | None = None
    poll_interval_seconds: float = 1.0
    environment: dict[str, str] = field(default_factory=dict)
    target_args: list[str] = field(default_factory=list)
    extra_fuzzer_args: list[str] = field(default_factory=list)


@dataclass(slots=True)
class WorkerResult:
    worker_index: int
    status: WorkerStatus
    started_at: datetime | None
    finished_at: datetime | None
    duration_seconds: float
    artifacts_seen: int
    crashes_recorded: int
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "worker_index": self.worker_index,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "artifacts_seen": self.artifacts_seen,
            "crashes_recorded": self.crashes_recorded,
            "error": self.error,
        }


class CampaignWorker:
    """Runs one fuzzer instance and collects its crashes."""

    def _fuzzer_environment(self) -> dict[str, str]:
        """Return the environment the fuzzer should see.

        AFL++ refuses to start when ``ASAN_OPTIONS`` contains ``symbolize=1``.
        We rewrite any ``*_OPTIONS`` variable so ``symbolize=0`` before the
        fuzzer is launched.  The detector, which re-runs crash artifacts,
        still gets the original environment with ``symbolize=1``.
        """
        env = dict(self._config.environment)
        for key in (
            "ASAN_OPTIONS",
            "UBSAN_OPTIONS",
            "LSAN_OPTIONS",
            "MSAN_OPTIONS",
            "TSAN_OPTIONS",
        ):
            if key not in env:
                continue
            parts = [
                piece
                for piece in env[key].split(":")
                if not piece.startswith("symbolize=")
            ]
            parts.append("symbolize=0")
            env[key] = ":".join(parts)
        return env

    def __init__(
        self,
        config: WorkerConfig,
        *,
        fuzzer: FuzzerAdapter,
        detector: CrashDetector,
        telemetry: TelemetryAggregator,
        database: Database | None = None,
        bus: EventBus | None = None,
        sanitizer_adapters: list[type["SanitizerAdapter"]] | None = None,
    ) -> None:
        self._config = config
        self._fuzzer = fuzzer
        self._detector = detector
        self._telemetry = telemetry
        self._database = database
        self._bus = bus
        self._sanitizer_adapters = sanitizer_adapters or []

        self._stop_event = threading.Event()
        self._status = WorkerStatus.NOT_STARTED
        self._seen_artifacts: set[Path] = set()
        self._artifacts_seen = 0
        self._crashes_recorded = 0

        # Each artifact is re-run through the detector with this monitor
        # configuration.  It mirrors the worker's own timeouts and resource
        # limits.
        self._evidence_root = config.output_dir / "evidence"
        self._evidence_root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ public

    @property
    def config(self) -> WorkerConfig:
        return self._config

    @property
    def status(self) -> WorkerStatus:
        return self._status

    @property
    def artifacts_seen(self) -> int:
        return self._artifacts_seen

    @property
    def crashes_recorded(self) -> int:
        return self._crashes_recorded

    def request_stop(self) -> None:
        """Signal the worker to finish.  Safe to call from any thread."""
        self._stop_event.set()

    def run(self) -> WorkerResult:
        """Run the worker until stopped or until its fuzzer exits."""
        started_at = _utcnow()
        started_monotonic = time.monotonic()
        error: str | None = None

        self._status = WorkerStatus.RUNNING
        self._telemetry.update(
            self._config.worker_index,
            status=self._status.value,
            started_at=started_at,
            last_stats_source=None,
            last_error=None,
        )
        self._publish(EventType.JOB_STARTED, {"worker_index": self._config.worker_index})

        try:
            self._fuzzer.start()
        except FuzzerError as exc:
            self._status = WorkerStatus.FAILED
            error = f"Failed to start fuzzer: {exc}"
            logger.error("Worker %d: %s", self._config.worker_index, error)
            self._telemetry.update(
                self._config.worker_index,
                status=self._status.value,
                last_error=error,
                finished_at=_utcnow(),
            )
            self._publish(EventType.JOB_FAILED, {"worker_index": self._config.worker_index})
            return self._finish(
                started_at, started_monotonic, WorkerStatus.FAILED, error
            )

        deadline = (
            time.monotonic() + self._config.duration_seconds
            if self._config.duration_seconds is not None
            else None
        )

        try:
            while not self._stop_event.is_set():
                if not self._fuzzer.is_running():
                    logger.info(
                        "Worker %d: fuzzer exited (returncode=%s)",
                        self._config.worker_index,
                        self._fuzzer.returncode,
                    )
                    break

                time.sleep(self._config.poll_interval_seconds)
                self._collect_stats()
                self._scan_for_crashes()

                if deadline is not None and time.monotonic() >= deadline:
                    logger.info(
                        "Worker %d: duration reached", self._config.worker_index
                    )
                    break
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            error = f"{type(exc).__name__}: {exc}"
            logger.exception(
                "Worker %d: unexpected error in main loop",
                self._config.worker_index,
            )

        # One last collection pass before stopping, so we do not lose an
        # artifact written between the last poll and shutdown.
        self._status = WorkerStatus.STOPPING
        try:
            self._fuzzer.stop()
        except Exception as exc:  # noqa: BLE001 - best-effort cleanup
            logger.warning("Worker %d: error stopping fuzzer: %s",
                           self._config.worker_index, exc)

        self._collect_stats()
        self._scan_for_crashes()

        final_status = WorkerStatus.STOPPED if error is None else WorkerStatus.FAILED
        return self._finish(started_at, started_monotonic, final_status, error)

    # ------------------------------------------------------------------ stats

    def _collect_stats(self) -> None:
        try:
            stats = self._fuzzer.stats()
        except Exception as exc:  # noqa: BLE001 - never crash on stats
            logger.warning("Worker %d: stats() raised: %s",
                           self._config.worker_index, exc)
            return

        self._telemetry.update(
            self._config.worker_index,
            status=self._status.value,
            executions=stats.executions,
            executions_per_second=stats.executions_per_second,
            corpus_count=stats.corpus_count,
            crashes=stats.crashes,
            unique_crashes=stats.unique_crashes,
            hangs=stats.hangs,
            coverage_percent=stats.coverage_percent,
            cycles_done=stats.cycles_done,
            runtime_seconds=stats.runtime_seconds,
            last_stats_source=stats.source,
        )
        self._publish(
            EventType.JOB_PROGRESS,
            {
                "worker_index": self._config.worker_index,
                "executions": stats.executions,
                "crashes": stats.crashes,
                "source": stats.source,
            },
        )

    # ------------------------------------------------------------------ crashes

    def _scan_for_crashes(self) -> None:
        try:
            artifacts = self._fuzzer.artifact_files()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Worker %d: artifact_files() raised: %s",
                           self._config.worker_index, exc)
            return

        new_artifacts = [p for p in artifacts if p not in self._seen_artifacts]
        if not new_artifacts:
            return

        for artifact in new_artifacts:
            self._seen_artifacts.add(artifact)
            self._artifacts_seen += 1
            self._telemetry.increment(self._config.worker_index, "artifacts_seen")
            self._handle_artifact(artifact)

    def _handle_artifact(self, artifact: Path) -> None:
        try:
            payload = artifact.read_bytes()
        except OSError as exc:
            logger.warning("Worker %d: could not read artifact %s: %s",
                           self._config.worker_index, artifact, exc)
            return

        # Every artifact is re-run under the detector's controlled monitor so
        # that we get a clean sanitizer report — even if the fuzzer's own
        # crash output has been truncated or reformatted.
        evidence_dir = self._evidence_root / f"artifact-{self._artifacts_seen:08d}"
        monitor_config = MonitorConfig(
            target=self._config.target_binary,
            timeout_seconds=self._config.timeout_seconds,
            memory_limit_mb=self._config.memory_limit_mb,
            environment=dict(self._config.environment),
            expected_sanitizers=list(self._config.sanitizers),
            evidence_dir=evidence_dir,
        )

        try:
            result = self._detector.run_and_record(
                monitor_config,
                input_path=artifact,
                input_bytes=payload,
                campaign_id=self._config.campaign_id,
                target_id=self._config.target_id,
                persist=True,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Worker %d: detector failed on artifact %s: %s",
                self._config.worker_index,
                artifact,
                exc,
            )
            return

        if result.crash is None:
            logger.info(
                "Worker %d: artifact %s did not reproduce as a crash",
                self._config.worker_index,
                artifact,
            )
            return

        self._crashes_recorded += 1
        self._telemetry.increment(self._config.worker_index, "crashes_recorded")
        self._publish(
            EventType.CRASH_DETECTED,
            {
                "worker_index": self._config.worker_index,
                "crash_id": result.crash.id,
                "classification": result.crash.classification.value,
                "fingerprint": result.crash.fingerprint,
                "artifact": str(artifact),
            },
        )

    # ------------------------------------------------------------------ lifecycle

    def _finish(
        self,
        started_at: datetime,
        started_monotonic: float,
        status: WorkerStatus,
        error: str | None,
    ) -> WorkerResult:
        finished_at = _utcnow()
        duration = time.monotonic() - started_monotonic
        self._status = status
        self._telemetry.update(
            self._config.worker_index,
            status=status.value,
            finished_at=finished_at,
            runtime_seconds=duration,
            last_error=error,
        )
        self._publish(
            EventType.JOB_COMPLETED if status is WorkerStatus.STOPPED else EventType.JOB_FAILED,
            {"worker_index": self._config.worker_index, "error": error},
        )
        return WorkerResult(
            worker_index=self._config.worker_index,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration,
            artifacts_seen=self._artifacts_seen,
            crashes_recorded=self._crashes_recorded,
            error=error,
        )

    # ------------------------------------------------------------------ helpers

    def _publish(self, event_type: EventType, payload: dict[str, object]) -> None:
        if self._bus is None:
            return
        self._bus.emit(event_type, payload, source=f"worker:{self._config.worker_index}")
