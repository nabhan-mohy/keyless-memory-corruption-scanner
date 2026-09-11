"""Replay a saved crash input N times and classify the outcome.

The runner is deliberately simple: it invokes the same
:class:`~kmcs.analysis.crash_monitor.CrashMonitor` the detector uses, on the
same target, with the same input, the configured number of times.  It then
reduces the per-attempt results to a single :class:`ReproductionOutcome`.

The four outcomes match Phase 1's :class:`ReproductionStatus` values:

* ``REPRODUCED``       — every attempt crashed with the expected fingerprint
* ``NOT_REPRODUCED``   — no attempt crashed
* ``INTERMITTENT``     — some attempts crashed, some did not
* ``ERROR``            — no attempt could be completed (target missing, etc.)

A fifth, non-terminal outcome — ``FINGERPRINT_MISMATCH`` — is *not* reported
here; it is handled by :mod:`kmcs.reproduction.regression`, which compares
against an expected fingerprint.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from kmcs.analysis.classifier import CrashClassifier
from kmcs.analysis.crash_monitor import (
    CrashMonitor,
    CrashObservation,
    MonitorConfig,
)
from kmcs.analysis.fingerprint import CrashFingerprinter
from kmcs.core.exceptions import KMCSException
from kmcs.core.models import (
    Crash,
    ReproductionStatus,
    SanitizerKind,
)

logger = logging.getLogger(__name__)

__all__ = [
    "ReproductionError",
    "ReproductionOutcome",
    "AttemptResult",
    "ReproductionResult",
    "ReproductionRunner",
]


class ReproductionError(KMCSException):
    exit_code = 70


class ReproductionOutcome(str, Enum):
    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not-reproduced"
    INTERMITTENT = "intermittent"
    ERROR = "error"

    def to_status(self) -> ReproductionStatus:
        return ReproductionStatus(self.value)


@dataclass(slots=True)
class AttemptResult:
    attempt: int
    crashed: bool
    fingerprint: str | None
    classification: str | None
    exit_code: int | None
    signal: int | None
    duration_seconds: float
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "attempt": self.attempt,
            "crashed": self.crashed,
            "fingerprint": self.fingerprint,
            "classification": self.classification,
            "exit_code": self.exit_code,
            "signal": self.signal,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


@dataclass(slots=True)
class ReproductionResult:
    crash_id: str | None
    outcome: ReproductionOutcome
    attempts: list[AttemptResult] = field(default_factory=list)
    expected_fingerprint: str | None = None
    error: str | None = None

    @property
    def crashes(self) -> int:
        return sum(1 for a in self.attempts if a.crashed)

    @property
    def crash_rate(self) -> float:
        if not self.attempts:
            return 0.0
        return self.crashes / len(self.attempts)

    @property
    def status(self) -> ReproductionStatus:
        return self.outcome.to_status()

    def to_dict(self) -> dict[str, object]:
        return {
            "crash_id": self.crash_id,
            "outcome": self.outcome.value,
            "expected_fingerprint": self.expected_fingerprint,
            "attempts": [a.to_dict() for a in self.attempts],
            "crashes": self.crashes,
            "crash_rate": self.crash_rate,
            "error": self.error,
        }


class ReproductionRunner:
    """Replays a saved crash input and classifies the outcome."""

    def __init__(
        self,
        *,
        monitor: CrashMonitor | None = None,
        fingerprinter: CrashFingerprinter | None = None,
        classifier: CrashClassifier | None = None,
        attempts: int = 3,
    ) -> None:
        if attempts < 1:
            raise ReproductionError("attempts must be at least 1")
        self._monitor = monitor or CrashMonitor()
        self._fingerprinter = fingerprinter or CrashFingerprinter()
        self._classifier = classifier or CrashClassifier()
        self._attempts = attempts

    # ------------------------------------------------------------------ public

    def reproduce(
        self,
        *,
        target: Path,
        input_path: Path,
        timeout_seconds: float = 10.0,
        memory_limit_mb: int | None = 4096,
        environment: dict[str, str] | None = None,
        target_args: list[str] | None = None,
        expected_sanitizers: list[SanitizerKind] | None = None,
        crash_id: str | None = None,
        attempts: int | None = None,
        work_root: Path | None = None,
    ) -> ReproductionResult:
        n = attempts if attempts is not None else self._attempts
        if n < 1:
            raise ReproductionError("attempts must be at least 1")

        if not input_path.is_file():
            return ReproductionResult(
                crash_id=crash_id,
                outcome=ReproductionOutcome.ERROR,
                expected_fingerprint=None,
                error=f"Input file does not exist: {input_path}",
            )

        payload = input_path.read_bytes()

        results: list[AttemptResult] = []
        for attempt_index in range(n):
            evidence_dir = (
                (work_root / f"attempt-{attempt_index:02d}") if work_root else None
            )
            monitor_config = MonitorConfig(
                target=Path(target),
                timeout_seconds=timeout_seconds,
                memory_limit_mb=memory_limit_mb,
                environment=dict(environment or {}),
                target_args=list(target_args or []),
                expected_sanitizers=list(expected_sanitizers or []),
                evidence_dir=evidence_dir,
            )

            try:
                observation = self._monitor.run(
                    monitor_config, input_path=input_path, input_bytes=payload
                )
            except Exception as exc:  # noqa: BLE001 - reported, not raised
                results.append(
                    AttemptResult(
                        attempt=attempt_index,
                        crashed=False,
                        fingerprint=None,
                        classification=None,
                        exit_code=None,
                        signal=None,
                        duration_seconds=0.0,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
                continue

            results.append(self._attempt_result(attempt_index, observation))

        return self._classify(crash_id, results)

    # ------------------------------------------------------------------ helpers

    def _attempt_result(
        self, attempt_index: int, observation: CrashObservation
    ) -> AttemptResult:
        report = observation.report
        fingerprint_value: str | None = None
        classification: str | None = None

        if observation.crashed:
            fp = self._fingerprinter.fingerprint(report)
            fingerprint_value = fp.value
            cr = self._classifier.classify(report)
            classification = cr.classification.value

        return AttemptResult(
            attempt=attempt_index,
            crashed=observation.crashed,
            fingerprint=fingerprint_value,
            classification=classification,
            exit_code=observation.exit_code,
            signal=observation.signal_number,
            duration_seconds=observation.duration_seconds,
            error=observation.error,
        )

    @staticmethod
    def _classify(
        crash_id: str | None, results: list[AttemptResult]
    ) -> ReproductionResult:
        crashed = [r for r in results if r.crashed]
        errored = [r for r in results if r.error is not None and not r.crashed]

        if not results:
            return ReproductionResult(
                crash_id=crash_id,
                outcome=ReproductionOutcome.ERROR,
                attempts=results,
                error="No attempts were made",
            )

        if not crashed and errored and len(errored) == len(results):
            return ReproductionResult(
                crash_id=crash_id,
                outcome=ReproductionOutcome.ERROR,
                attempts=results,
                error=errored[0].error,
            )

        if not crashed:
            return ReproductionResult(
                crash_id=crash_id,
                outcome=ReproductionOutcome.NOT_REPRODUCED,
                attempts=results,
            )

        if len(crashed) == len(results):
            outcome = ReproductionOutcome.REPRODUCED
        else:
            outcome = ReproductionOutcome.INTERMITTENT

        # If every crashing attempt agreed on a fingerprint, record it.
        fingerprints = {r.fingerprint for r in crashed if r.fingerprint}
        expected = fingerprints.pop() if len(fingerprints) == 1 else None

        return ReproductionResult(
            crash_id=crash_id,
            outcome=outcome,
            attempts=results,
            expected_fingerprint=expected,
        )

    # ------------------------------------------------------------------ persistence

    @staticmethod
    def apply_to_crash(crash: Crash, result: ReproductionResult) -> Crash:
        """Return a copy of ``crash`` with its reproduction status updated.

        The original is not mutated; the caller decides whether to persist
        the update.
        """
        crash.reproduction_status = result.status
        crash.touch()
        crash.metadata["reproduction"] = result.to_dict()
        return crash
