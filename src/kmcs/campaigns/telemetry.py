"""Aggregation of real fuzzer statistics across workers.

Nothing here is synthesised.  Every field on :class:`WorkerTelemetry` comes
from one of:

* the fuzzer's own statistics source (AFL++ ``fuzzer_stats``,
  libFuzzer progress lines),
* the number of crash files KMCS has actually seen on disk,
* wall-clock time measured by the worker itself.

Fields for which the fuzzer has no source remain ``None``.  The aggregator
never fills them in.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "WorkerTelemetry",
    "TelemetrySnapshot",
    "TelemetryAggregator",
]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class WorkerTelemetry(BaseModel):
    """The latest known state of one worker."""

    model_config = ConfigDict(validate_assignment=True)

    worker_index: int = Field(ge=0)
    status: str = "not-started"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    runtime_seconds: float | None = None

    # Fuzzer-reported values.  Left as None when the fuzzer has no source.
    executions: int | None = None
    executions_per_second: float | None = None
    corpus_count: int | None = None
    crashes: int | None = None
    unique_crashes: int | None = None
    hangs: int | None = None
    coverage_percent: float | None = None
    cycles_done: int | None = None

    # KMCS-observed values.
    artifacts_seen: int = 0
    crashes_recorded: int = 0
    last_stats_source: str | None = None
    last_error: str | None = None
    updated_at: datetime = Field(default_factory=_utcnow)


class TelemetrySnapshot(BaseModel):
    """An aggregate view across every worker in a campaign."""

    model_config = ConfigDict(validate_assignment=True)

    campaign_id: str | None = None
    captured_at: datetime = Field(default_factory=_utcnow)
    workers: list[WorkerTelemetry] = Field(default_factory=list)

    # Aggregated values.  Totals are sums of the corresponding per-worker
    # values; per-second and coverage are the sums / simple means.
    total_executions: int | None = None
    total_executions_per_second: float | None = None
    total_corpus_count: int | None = None
    total_crashes: int | None = None
    total_unique_crashes: int | None = None
    total_hangs: int | None = None
    mean_coverage_percent: float | None = None
    total_artifacts_seen: int = 0
    total_crashes_recorded: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "campaign_id": self.campaign_id,
            "captured_at": self.captured_at.isoformat(),
            "workers": [w.model_dump(mode="json") for w in self.workers],
            "total_executions": self.total_executions,
            "total_executions_per_second": self.total_executions_per_second,
            "total_corpus_count": self.total_corpus_count,
            "total_crashes": self.total_crashes,
            "total_unique_crashes": self.total_unique_crashes,
            "total_hangs": self.total_hangs,
            "mean_coverage_percent": self.mean_coverage_percent,
            "total_artifacts_seen": self.total_artifacts_seen,
            "total_crashes_recorded": self.total_crashes_recorded,
        }


class TelemetryAggregator:
    """Thread-safe collector for per-worker telemetry."""

    def __init__(self, *, campaign_id: str | None = None) -> None:
        self._lock = threading.RLock()
        self._campaign_id = campaign_id
        self._workers: dict[int, WorkerTelemetry] = {}

    # ------------------------------------------------------------------ update

    def register_worker(self, worker_index: int) -> WorkerTelemetry:
        with self._lock:
            existing = self._workers.get(worker_index)
            if existing is not None:
                return existing
            record = WorkerTelemetry(worker_index=worker_index)
            self._workers[worker_index] = record
            return record

    def update(self, worker_index: int, **fields: object) -> WorkerTelemetry:
        with self._lock:
            record = self._workers.get(worker_index)
            if record is None:
                record = WorkerTelemetry(worker_index=worker_index)
                self._workers[worker_index] = record
            for key, value in fields.items():
                if not hasattr(record, key):
                    raise AttributeError(
                        f"WorkerTelemetry has no field {key!r}"
                    )
                setattr(record, key, value)
            record.updated_at = _utcnow()
            return record

    def increment(self, worker_index: int, field_name: str, amount: int = 1) -> None:
        if amount < 0:
            raise ValueError("increment amount must be non-negative")
        with self._lock:
            record = self._workers.get(worker_index)
            if record is None:
                record = WorkerTelemetry(worker_index=worker_index)
                self._workers[worker_index] = record
            current = getattr(record, field_name, None)
            if current is None:
                setattr(record, field_name, amount)
            else:
                setattr(record, field_name, current + amount)
            record.updated_at = _utcnow()

    # ------------------------------------------------------------------ read

    def worker(self, worker_index: int) -> WorkerTelemetry | None:
        with self._lock:
            return self._workers.get(worker_index)

    def snapshot(self) -> TelemetrySnapshot:
        with self._lock:
            workers = sorted(self._workers.values(), key=lambda w: w.worker_index)
            return TelemetrySnapshot(
                campaign_id=self._campaign_id,
                workers=workers,
                total_executions=_safe_sum(w.executions for w in workers),
                total_executions_per_second=_safe_sum(
                    w.executions_per_second for w in workers
                ),
                total_corpus_count=_safe_sum(w.corpus_count for w in workers),
                total_crashes=_safe_sum(w.crashes for w in workers),
                total_unique_crashes=_safe_sum(w.unique_crashes for w in workers),
                total_hangs=_safe_sum(w.hangs for w in workers),
                mean_coverage_percent=_safe_mean(
                    w.coverage_percent for w in workers
                ),
                total_artifacts_seen=sum(w.artifacts_seen for w in workers),
                total_crashes_recorded=sum(w.crashes_recorded for w in workers),
            )


def _safe_sum(values) -> int | float | None:
    present = [v for v in values if v is not None]
    if not present:
        return None
    total = sum(present)
    if all(isinstance(v, int) for v in present):
        return int(total)
    return float(total)


def _safe_mean(values) -> float | None:
    present = [v for v in values if v is not None]
    if not present:
        return None
    return sum(present) / len(present)
