"""Job abstraction and registry.

A *job* is the bookkeeping record for a long-running operation — building a target,
running a campaign, minimising a corpus, reproducing a crash, generating a report.

Phase 1 deliberately does not execute anything.  It provides the state machine and
the registry that later phases will drive from worker threads.
"""

from __future__ import annotations

import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from kmcs.core.events import EventBus, EventType
from kmcs.core.exceptions import InvalidJobTransitionError, JobError

__all__ = ["JobState", "TERMINAL_STATES", "Job", "JobManager"]


class JobState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATES: frozenset[JobState] = frozenset(
    {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED}
)

_ALLOWED_TRANSITIONS: dict[JobState, frozenset[JobState]] = {
    JobState.PENDING: frozenset({JobState.RUNNING, JobState.CANCELLED, JobState.FAILED}),
    JobState.RUNNING: frozenset(
        {JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED}
    ),
    JobState.COMPLETED: frozenset(),
    JobState.FAILED: frozenset(),
    JobState.CANCELLED: frozenset(),
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Job(BaseModel):
    """A single unit of long-running work."""

    model_config = ConfigDict(validate_assignment=True)

    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    name: str
    state: JobState = JobState.PENDING
    progress: float = 0.0
    message: str | None = None
    error: str | None = None
    result: dict[str, Any] | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @field_validator("name", mode="after")
    @classmethod
    def _normalise_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("job name must not be empty or whitespace-only")
        return cleaned

    @field_validator("progress", mode="after")
    @classmethod
    def _check_progress(cls, value: float) -> float:
        if not 0.0 <= value <= 1.0:
            raise ValueError("progress must be between 0.0 and 1.0")
        return float(value)

    # ------------------------------------------------------------------ queries

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def duration_seconds(self) -> float | None:
        """Elapsed seconds, or ``None`` if the job never started."""
        if self.started_at is None:
            return None
        end = self.finished_at or _utcnow()
        return (end - self.started_at).total_seconds()

    # ------------------------------------------------------------------ mutation

    def transition_to(
        self,
        state: JobState,
        *,
        message: str | None = None,
        error: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> None:
        """Move to ``state``, rejecting any illegal transition."""
        if not isinstance(state, JobState):
            raise InvalidJobTransitionError(f"Unknown job state: {state!r}")

        if state is self.state:
            raise InvalidJobTransitionError(
                f"Job is already in state {state.value}",
                details={"job_id": self.id, "state": state.value},
            )

        allowed = _ALLOWED_TRANSITIONS[self.state]
        if state not in allowed:
            raise InvalidJobTransitionError(
                f"Illegal job transition from {self.state.value} to {state.value}",
                details={
                    "job_id": self.id,
                    "from": self.state.value,
                    "to": state.value,
                    "allowed": sorted(item.value for item in allowed),
                },
            )

        self.state = state
        if message is not None:
            self.message = message
        if error is not None:
            self.error = error
        if result is not None:
            self.result = dict(result)

        if state is JobState.RUNNING:
            self.started_at = _utcnow()
            self.finished_at = None
        elif state in TERMINAL_STATES:
            self.finished_at = _utcnow()
            if state is JobState.COMPLETED:
                self.progress = 1.0

    def start(self, *, message: str | None = None) -> None:
        self.transition_to(JobState.RUNNING, message=message)

    def complete(
        self, *, result: dict[str, Any] | None = None, message: str | None = None
    ) -> None:
        self.transition_to(JobState.COMPLETED, result=result, message=message)

    def fail(self, error: str, *, message: str | None = None) -> None:
        self.transition_to(JobState.FAILED, error=str(error), message=message)

    def cancel(self, *, message: str | None = None) -> None:
        self.transition_to(JobState.CANCELLED, message=message)

    def set_progress(self, value: float, *, message: str | None = None) -> None:
        if self.is_terminal:
            raise JobError(
                "Cannot update the progress of a finished job",
                details={"job_id": self.id, "state": self.state.value},
            )
        if not 0.0 <= value <= 1.0:
            raise JobError(
                "Progress must be between 0.0 and 1.0", details={"value": value}
            )
        self.progress = float(value)
        if message is not None:
            self.message = message


class JobManager:
    """Thread-safe in-memory registry of :class:`Job` objects."""

    def __init__(self, bus: EventBus | None = None) -> None:
        self._lock = threading.RLock()
        self._jobs: dict[str, Job] = {}
        self._bus = bus

    # ------------------------------------------------------------------ registry

    def create(self, name: str, *, metadata: dict[str, Any] | None = None) -> Job:
        job = Job(name=name, metadata=dict(metadata or {}))
        with self._lock:
            self._jobs[job.id] = job
        self._publish(EventType.JOB_CREATED, job)
        return job

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def require(self, job_id: str) -> Job:
        job = self.get(job_id)
        if job is None:
            raise JobError("Unknown job", details={"job_id": job_id})
        return job

    def list(self, *, state: JobState | None = None) -> list[Job]:
        with self._lock:
            jobs = list(self._jobs.values())
        if state is None:
            return jobs
        return [job for job in jobs if job.state is state]

    def remove(self, job_id: str) -> bool:
        with self._lock:
            return self._jobs.pop(job_id, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._jobs.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._jobs)

    # ------------------------------------------------------------------ transitions

    def start(self, job_id: str, *, message: str | None = None) -> Job:
        job = self.require(job_id)
        job.start(message=message)
        self._publish(EventType.JOB_STARTED, job)
        return job

    def complete(
        self,
        job_id: str,
        *,
        result: dict[str, Any] | None = None,
        message: str | None = None,
    ) -> Job:
        job = self.require(job_id)
        job.complete(result=result, message=message)
        self._publish(EventType.JOB_COMPLETED, job)
        return job

    def fail(self, job_id: str, error: str, *, message: str | None = None) -> Job:
        job = self.require(job_id)
        job.fail(error, message=message)
        self._publish(EventType.JOB_FAILED, job)
        return job

    def cancel(self, job_id: str, *, message: str | None = None) -> Job:
        job = self.require(job_id)
        job.cancel(message=message)
        self._publish(EventType.JOB_CANCELLED, job)
        return job

    def report_progress(
        self, job_id: str, value: float, *, message: str | None = None
    ) -> Job:
        job = self.require(job_id)
        job.set_progress(value, message=message)
        self._publish(EventType.JOB_PROGRESS, job)
        return job

    # ------------------------------------------------------------------ internals

    def _publish(self, event_type: EventType, job: Job) -> None:
        if self._bus is None:
            return
        self._bus.emit(
            event_type,
            {
                "job_id": job.id,
                "name": job.name,
                "state": job.state.value,
                "progress": job.progress,
            },
        )
