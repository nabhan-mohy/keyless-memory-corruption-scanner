"""Coordinates N workers for one campaign.

The scheduler is the only component that knows about worker counts and
durations.  It:

1. prepares a shared output directory,
2. builds one :class:`CampaignWorker` per configured worker index,
3. runs them in threads,
4. stops every worker at the deadline or on request,
5. joins them and returns their results.

Threads are used rather than subprocesses because the heavy work happens
inside the fuzzer subprocesses that the workers themselves spawn.  A worker
thread is mostly blocked on ``time.sleep()`` and cheap file I/O.
"""

from __future__ import annotations

import logging
import shutil
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from kmcs.analysis.crash_detector import CrashDetector
from kmcs.campaigns.telemetry import TelemetryAggregator, TelemetrySnapshot
from kmcs.campaigns.worker import (
    CampaignWorker,
    WorkerConfig,
    WorkerResult,
    WorkerStatus,
)
from kmcs.core.events import EventBus, EventType
from kmcs.core.exceptions import KMCSException
from kmcs.core.models import FuzzerKind, SanitizerKind
from kmcs.database.database import Database
from kmcs.fuzzers import (
    AFLPlusPlusAdapter,
    FuzzerAdapter,
    FuzzerConfig,
    HonggfuzzAdapter,
    LibFuzzerAdapter,
)

logger = logging.getLogger(__name__)

__all__ = [
    "SchedulerError",
    "SchedulerConfig",
    "SchedulerResult",
    "CampaignScheduler",
]


class SchedulerError(KMCSException):
    exit_code = 61


_FUZZER_CLASSES: dict[FuzzerKind, type[FuzzerAdapter]] = {
    FuzzerKind.AFLPP: AFLPlusPlusAdapter,
    FuzzerKind.LIBFUZZER: LibFuzzerAdapter,
    FuzzerKind.HONGFUZZ: HonggfuzzAdapter,
}


class SchedulerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    campaign_id: str
    target_id: str | None = None
    target_binary: Path
    corpus_dir: Path
    output_root: Path
    fuzzer: FuzzerKind
    sanitizers: list[SanitizerKind] = Field(default_factory=list)
    workers: int = Field(default=1, ge=1, le=1024)
    duration_seconds: int | None = Field(default=None, ge=0)
    timeout_seconds: float = 5.0
    memory_limit_mb: int | None = None
    poll_interval_seconds: float = 1.0
    environment: dict[str, str] = Field(default_factory=dict)
    target_args: list[str] = Field(default_factory=list)
    extra_fuzzer_args: list[str] = Field(default_factory=list)
    clear_output_root: bool = False
    """When True, ``output_root`` is removed before the campaign starts.  Use
    with care: it deletes any previous campaign data in that directory."""

    def worker_output_dir(self, worker_index: int) -> Path:
        return Path(self.output_root) / f"worker-{worker_index:03d}"


@dataclass(slots=True)
class SchedulerResult:
    campaign_id: str
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    worker_results: list[WorkerResult] = field(default_factory=list)
    telemetry: TelemetrySnapshot | None = None
    cancelled: bool = False
    error: str | None = None

    @property
    def total_crashes_recorded(self) -> int:
        return sum(result.crashes_recorded for result in self.worker_results)

    def to_dict(self) -> dict[str, object]:
        return {
            "campaign_id": self.campaign_id,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_seconds": self.duration_seconds,
            "cancelled": self.cancelled,
            "error": self.error,
            "total_crashes_recorded": self.total_crashes_recorded,
            "worker_results": [r.to_dict() for r in self.worker_results],
            "telemetry": self.telemetry.to_dict() if self.telemetry else None,
        }


class CampaignScheduler:
    """Runs N workers in parallel and returns their combined results."""

    def __init__(
        self,
        config: SchedulerConfig,
        *,
        detector: CrashDetector,
        database: Database | None = None,
        bus: EventBus | None = None,
        telemetry: TelemetryAggregator | None = None,
    ) -> None:
        self._config = config
        self._detector = detector
        self._database = database
        self._bus = bus or EventBus()
        self._telemetry = telemetry or TelemetryAggregator(campaign_id=config.campaign_id)

        self._workers: list[CampaignWorker] = []
        self._threads: list[threading.Thread] = []
        self._results: list[WorkerResult | None] = [None] * config.workers
        self._cancel_event = threading.Event()
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ properties

    @property
    def telemetry(self) -> TelemetryAggregator:
        return self._telemetry

    # ------------------------------------------------------------------ lifecycle

    def prepare(self) -> None:
        """Create output directories and worker instances.

        Must be called before :meth:`run`.  Exposed separately so tests can
        inspect the worker list without launching anything.
        """
        output_root = Path(self._config.output_root)
        if self._config.clear_output_root and output_root.is_dir():
            shutil.rmtree(output_root)
        output_root.mkdir(parents=True, exist_ok=True)

        self._telemetry_snapshot_initial()

        for index in range(self._config.workers):
            worker_output = self._config.worker_output_dir(index)
            worker_output.mkdir(parents=True, exist_ok=True)

            worker_config = WorkerConfig(
                campaign_id=self._config.campaign_id,
                worker_index=index,
                target_id=self._config.target_id,
                target_binary=Path(self._config.target_binary),
                corpus_dir=Path(self._config.corpus_dir),
                output_dir=worker_output,
                fuzzer=self._config.fuzzer,
                sanitizers=list(self._config.sanitizers),
                duration_seconds=self._config.duration_seconds,
                timeout_seconds=self._config.timeout_seconds,
                memory_limit_mb=self._config.memory_limit_mb,
                poll_interval_seconds=self._config.poll_interval_seconds,
                environment=dict(self._config.environment),
                target_args=list(self._config.target_args),
                extra_fuzzer_args=list(self._config.extra_fuzzer_args),
            )

            fuzzer = self._build_fuzzer(worker_config)

            worker = CampaignWorker(
                worker_config,
                fuzzer=fuzzer,
                detector=self._detector,
                telemetry=self._telemetry,
                database=self._database,
                bus=self._bus,
            )
            self._workers.append(worker)

    def run(self) -> SchedulerResult:
        """Start every worker, wait for them, return the combined result."""
        if not self._workers:
            self.prepare()

        started_at = datetime.now(timezone.utc)
        started_monotonic = time.monotonic()

        self._bus.emit(
            EventType.CAMPAIGN_STARTED,
            {"campaign_id": self._config.campaign_id, "workers": self._config.workers},
            source="scheduler",
        )

        for index, worker in enumerate(self._workers):
            thread = threading.Thread(
                target=self._run_worker,
                args=(index, worker),
                name=f"kmcs-worker-{index}",
                daemon=False,
            )
            self._threads.append(thread)
            thread.start()

        for thread in self._threads:
            thread.join()

        finished_at = datetime.now(timezone.utc)
        duration = time.monotonic() - started_monotonic

        snapshot = self._telemetry.snapshot()
        self._bus.emit(
            EventType.CAMPAIGN_FINISHED,
            {
                "campaign_id": self._config.campaign_id,
                "duration_seconds": duration,
                "crashes_recorded": snapshot.total_crashes_recorded,
            },
            source="scheduler",
        )

        return SchedulerResult(
            campaign_id=self._config.campaign_id,
            started_at=started_at,
            finished_at=finished_at,
            duration_seconds=duration,
            worker_results=[r for r in self._results if r is not None],
            telemetry=snapshot,
            cancelled=self._cancel_event.is_set(),
        )

    def cancel(self) -> None:
        """Ask every worker to stop at its next poll."""
        self._cancel_event.set()
        for worker in self._workers:
            worker.request_stop()

    # ------------------------------------------------------------------ internals

    def _run_worker(self, index: int, worker: CampaignWorker) -> None:
        try:
            result = worker.run()
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            logger.exception("Worker %d raised", index)
            now = datetime.now(timezone.utc)
            result = WorkerResult(
                worker_index=index,
                status=WorkerStatus.FAILED,
                started_at=now,
                finished_at=now,
                duration_seconds=0.0,
                artifacts_seen=0,
                crashes_recorded=0,
                error=f"{type(exc).__name__}: {exc}",
            )
        with self._lock:
            self._results[index] = result

    def _build_fuzzer(self, worker_config: WorkerConfig) -> FuzzerAdapter:
        adapter_cls = _FUZZER_CLASSES.get(worker_config.fuzzer)
        if adapter_cls is None:
            raise SchedulerError(
                "No adapter is registered for this fuzzer",
                details={"fuzzer": worker_config.fuzzer.value},
            )

        fuzzer_config = FuzzerConfig(
            target_binary=worker_config.target_binary,
            input_dir=worker_config.corpus_dir,
            output_dir=worker_config.output_dir,
            duration_seconds=worker_config.duration_seconds,
            workers=1,
            timeout_seconds=worker_config.timeout_seconds,
            memory_limit_mb=worker_config.memory_limit_mb,
            environment=dict(worker_config.environment),
            target_args=list(worker_config.target_args),
            extra_args=list(worker_config.extra_fuzzer_args),
        )
        return adapter_cls(fuzzer_config)

    def _telemetry_snapshot_initial(self) -> None:
        for index in range(self._config.workers):
            self._telemetry.register_worker(index)
