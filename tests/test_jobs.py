"""Job state machine and registry."""

from __future__ import annotations

import pytest

from kmcs.core.events import Event, EventBus, EventType
from kmcs.core.exceptions import InvalidJobTransitionError, JobError
from kmcs.core.jobs import Job, JobManager, JobState


class TestJobStateMachine:
    def test_new_job_is_pending(self) -> None:
        job = Job(name="build target")
        assert job.state is JobState.PENDING
        assert job.started_at is None
        assert job.finished_at is None
        assert job.progress == 0.0
        assert job.is_terminal is False
        assert job.duration_seconds is None

    def test_happy_path(self) -> None:
        job = Job(name="fuzz libpng")
        job.start()
        assert job.state is JobState.RUNNING
        assert job.started_at is not None

        job.complete(result={"executions": 42})
        assert job.state is JobState.COMPLETED
        assert job.result == {"executions": 42}
        assert job.progress == 1.0
        assert job.finished_at is not None
        assert job.is_terminal is True
        assert job.duration_seconds is not None
        assert job.duration_seconds >= 0

    def test_cannot_complete_a_pending_job(self) -> None:
        job = Job(name="fuzz")
        with pytest.raises(InvalidJobTransitionError):
            job.complete()

    def test_cannot_restart_a_finished_job(self) -> None:
        job = Job(name="fuzz")
        job.start()
        job.complete()
        with pytest.raises(InvalidJobTransitionError):
            job.start()

    def test_failure_records_the_reason(self) -> None:
        job = Job(name="fuzz")
        job.start()
        job.fail("afl-fuzz exited with code 1")

        assert job.state is JobState.FAILED
        assert job.error == "afl-fuzz exited with code 1"
        assert job.is_terminal is True

    def test_cancel_from_pending(self) -> None:
        job = Job(name="fuzz")
        job.cancel()
        assert job.state is JobState.CANCELLED
        assert job.is_terminal is True

    def test_redundant_transition_is_rejected(self) -> None:
        job = Job(name="fuzz")
        job.start()
        with pytest.raises(InvalidJobTransitionError):
            job.start()

    def test_progress_is_validated(self) -> None:
        job = Job(name="fuzz")
        job.start()

        job.set_progress(0.5, message="halfway")
        assert job.progress == 0.5
        assert job.message == "halfway"

        with pytest.raises(JobError):
            job.set_progress(1.5)

    def test_progress_rejected_after_completion(self) -> None:
        job = Job(name="fuzz")
        job.start()
        job.complete()
        with pytest.raises(JobError):
            job.set_progress(0.2)

    def test_blank_name_is_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Job(name="   ")

    def test_name_is_trimmed(self) -> None:
        assert Job(name="  fuzz  ").name == "fuzz"


class TestJobManager:
    def test_tracks_jobs_and_publishes_events(self) -> None:
        bus = EventBus()
        received: list[Event] = []
        bus.subscribe_all(received.append)
        manager = JobManager(bus=bus)

        job = manager.create("reproduce crash")
        manager.start(job.id)
        manager.complete(job.id, result={"reproduced": True})

        assert manager.get(job.id) is job
        assert manager.require(job.id).state is JobState.COMPLETED
        assert [event.type for event in received] == [
            EventType.JOB_CREATED,
            EventType.JOB_STARTED,
            EventType.JOB_COMPLETED,
        ]

    def test_progress_event_is_published(self) -> None:
        bus = EventBus()
        received: list[Event] = []
        bus.subscribe(EventType.JOB_PROGRESS, received.append)
        manager = JobManager(bus=bus)

        job = manager.create("minimise corpus")
        manager.start(job.id)
        manager.report_progress(job.id, 0.25, message="quarter done")

        assert len(received) == 1
        assert received[0].payload["progress"] == 0.25

    def test_listing_by_state(self) -> None:
        manager = JobManager()
        first = manager.create("a")
        second = manager.create("b")
        manager.start(second.id)

        assert manager.list(state=JobState.PENDING) == [first]
        assert manager.list(state=JobState.RUNNING) == [second]
        assert len(manager.list()) == 2
        assert len(manager) == 2

    def test_unknown_job_raises(self) -> None:
        manager = JobManager()
        with pytest.raises(JobError):
            manager.require("does-not-exist")

    def test_remove(self) -> None:
        manager = JobManager()
        job = manager.create("a")
        assert manager.remove(job.id) is True
        assert manager.remove(job.id) is False

    def test_manager_without_bus_is_silent(self) -> None:
        manager = JobManager()
        job = manager.create("a")
        manager.start(job.id)
        assert manager.require(job.id).state is JobState.RUNNING
