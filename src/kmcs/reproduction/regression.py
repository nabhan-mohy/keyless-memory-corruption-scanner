"""Regression testing for confirmed crashes.

A regression test is the tuple:

    (target binary, input file, expected fingerprint)

The runner re-runs the input against the target and produces a
:class:`RegressionOutcome`:

* ``STILL_CRASHING``  — the target still crashes with the expected fingerprint
* ``FIXED``           — the target no longer crashes with this input
* ``DIFFERENT_CRASH`` — the target crashes, but with a different fingerprint
* ``ERROR``           — the input or target could not be evaluated
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
from kmcs.core.models import Crash, SanitizerKind

logger = logging.getLogger(__name__)

__all__ = [
    "RegressionError",
    "RegressionOutcome",
    "RegressionCaseResult",
    "RegressionResult",
    "RegressionRunner",
]


class RegressionError(KMCSException):
    exit_code = 71


class RegressionOutcome(str, Enum):
    STILL_CRASHING = "still-crashing"
    FIXED = "fixed"
    DIFFERENT_CRASH = "different-crash"
    ERROR = "error"


@dataclass(slots=True)
class RegressionCaseResult:
    crash_id: str
    input_path: Path
    expected_fingerprint: str | None
    observed_fingerprint: str | None
    outcome: RegressionOutcome
    duration_seconds: float
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "crash_id": self.crash_id,
            "input_path": str(self.input_path),
            "expected_fingerprint": self.expected_fingerprint,
            "observed_fingerprint": self.observed_fingerprint,
            "outcome": self.outcome.value,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


@dataclass(slots=True)
class RegressionResult:
    cases: list[RegressionCaseResult] = field(default_factory=list)

    @property
    def still_crashing(self) -> int:
        return sum(
            1 for c in self.cases if c.outcome is RegressionOutcome.STILL_CRASHING
        )

    @property
    def fixed(self) -> int:
        return sum(1 for c in self.cases if c.outcome is RegressionOutcome.FIXED)

    @property
    def different(self) -> int:
        return sum(
            1 for c in self.cases if c.outcome is RegressionOutcome.DIFFERENT_CRASH
        )

    @property
    def errored(self) -> int:
        return sum(1 for c in self.cases if c.outcome is RegressionOutcome.ERROR)

    @property
    def all_clear(self) -> bool:
        return all(
            c.outcome is RegressionOutcome.FIXED for c in self.cases
        ) and bool(self.cases)

    def to_dict(self) -> dict[str, object]:
        return {
            "cases": [c.to_dict() for c in self.cases],
            "still_crashing": self.still_crashing,
            "fixed": self.fixed,
            "different": self.different,
            "errored": self.errored,
            "all_clear": self.all_clear,
        }


class RegressionRunner:
    """Re-runs saved crashes against a rebuilt target."""

    def __init__(
        self,
        *,
        monitor: CrashMonitor | None = None,
        fingerprinter: CrashFingerprinter | None = None,
        classifier: CrashClassifier | None = None,
    ) -> None:
        self._monitor = monitor or CrashMonitor()
        self._fingerprinter = fingerprinter or CrashFingerprinter()
        self._classifier = classifier or CrashClassifier()

    # ------------------------------------------------------------------ public

    def run(
        self,
        cases: list[tuple[Crash, Path]],
        *,
        target: Path,
        timeout_seconds: float = 10.0,
        memory_limit_mb: int | None = 4096,
        environment: dict[str, str] | None = None,
        target_args: list[str] | None = None,
        expected_sanitizers: list[SanitizerKind] | None = None,
        work_root: Path | None = None,
    ) -> RegressionResult:
        """Run every ``(crash, input_path)`` case against ``target``.

        ``crash.fingerprint`` is used as the expected fingerprint; when it is
        ``None``, an observed crash is reported as ``DIFFERENT_CRASH`` rather
        than as ``STILL_CRASHING``.
        """
        result = RegressionResult()
        for case_index, (crash, input_path) in enumerate(cases):
            case_result = self._run_one(
                case_index=case_index,
                crash=crash,
                input_path=input_path,
                target=target,
                timeout_seconds=timeout_seconds,
                memory_limit_mb=memory_limit_mb,
                environment=environment,
                target_args=target_args,
                expected_sanitizers=expected_sanitizers,
                work_root=work_root,
            )
            result.cases.append(case_result)
        return result

    # ------------------------------------------------------------------ internals

    def _run_one(
        self,
        *,
        case_index: int,
        crash: Crash,
        input_path: Path,
        target: Path,
        timeout_seconds: float,
        memory_limit_mb: int | None,
        environment: dict[str, str] | None,
        target_args: list[str] | None,
        expected_sanitizers: list[SanitizerKind] | None,
        work_root: Path | None,
    ) -> RegressionCaseResult:
        if not input_path.is_file():
            return RegressionCaseResult(
                crash_id=crash.id,
                input_path=input_path,
                expected_fingerprint=crash.fingerprint,
                observed_fingerprint=None,
                outcome=RegressionOutcome.ERROR,
                duration_seconds=0.0,
                error=f"Input file does not exist: {input_path}",
            )

        payload = input_path.read_bytes()
        evidence_dir = (
            (work_root / f"case-{case_index:03d}") if work_root else None
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
            return RegressionCaseResult(
                crash_id=crash.id,
                input_path=input_path,
                expected_fingerprint=crash.fingerprint,
                observed_fingerprint=None,
                outcome=RegressionOutcome.ERROR,
                duration_seconds=0.0,
                error=f"{type(exc).__name__}: {exc}",
            )

        return self._classify(observation, crash, input_path)

    def _classify(
        self,
        observation: CrashObservation,
        crash: Crash,
        input_path: Path,
    ) -> RegressionCaseResult:
        if not observation.crashed:
            return RegressionCaseResult(
                crash_id=crash.id,
                input_path=input_path,
                expected_fingerprint=crash.fingerprint,
                observed_fingerprint=None,
                outcome=RegressionOutcome.FIXED,
                duration_seconds=observation.duration_seconds,
            )

        fingerprint = self._fingerprinter.fingerprint(observation.report)

        if crash.fingerprint and fingerprint.value == crash.fingerprint:
            outcome = RegressionOutcome.STILL_CRASHING
        else:
            outcome = RegressionOutcome.DIFFERENT_CRASH

        return RegressionCaseResult(
            crash_id=crash.id,
            input_path=input_path,
            expected_fingerprint=crash.fingerprint,
            observed_fingerprint=fingerprint.value,
            outcome=outcome,
            duration_seconds=observation.duration_seconds,
        )
