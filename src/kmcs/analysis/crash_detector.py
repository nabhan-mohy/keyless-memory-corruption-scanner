"""Combine monitoring, parsing, classification, fingerprinting, severity, and
persistence into one operation.

The :class:`CrashDetector` is the boundary Phase 5 will build on: it takes a
target, an input, and a monitor configuration, runs the target, and produces a
:class:`~kmcs.core.models.Crash` domain entity populated **only** with facts
observed during execution — plus the structured classification, fingerprint,
and severity that Phase 4's analysis layer computes from those facts.

Dependency injection is explicit so tests can swap in a fake monitor, a
shorter-depth fingerprinter, or a stricter classifier without subclassing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from kmcs.analysis.classifier import CrashClassifier
from kmcs.analysis.crash_monitor import (
    CrashMonitor,
    CrashObservation,
    MonitorConfig,
)
from kmcs.analysis.fingerprint import CrashFingerprinter
from kmcs.analysis.severity import SeverityAssessor
from kmcs.core import models
from kmcs.core.exceptions import KMCSException
from kmcs.database.database import Database
from kmcs.database.models import CrashRow

logger = logging.getLogger(__name__)

__all__ = [
    "DetectionError",
    "DetectionResult",
    "CrashDetector",
]


class DetectionError(KMCSException):
    exit_code = 41


@dataclass(slots=True)
class DetectionResult:
    """The outcome of one monitored execution.

    ``crash`` is ``None`` when the target did not crash; otherwise it is the
    fully-populated :class:`~kmcs.core.models.Crash`.  ``persisted`` records
    whether that crash was actually written to the database — it is ``False``
    when persistence was disabled or no database was supplied.
    """

    observation: CrashObservation
    crash: models.Crash | None
    persisted: bool

    @property
    def crashed(self) -> bool:
        return self.observation.report.crashed


class CrashDetector:
    """Runs targets and, on a crash, persists a :class:`Crash` record.

    Parameters
    ----------
    monitor:
        The runner used to execute targets.  Defaults to a fresh
        :class:`CrashMonitor`.
    database:
        Optional.  When supplied and ``persist=True`` is passed to
        :meth:`run_and_record`, the resulting :class:`Crash` is written to the
        ``crashes`` table.  When ``None``, the crash is returned but not stored.
    classifier, fingerprinter, severity_assessor:
        Optional overrides for the Phase 4 analysis components.  Defaults are
        the ones defined in :mod:`kmcs.analysis`.
    """

    def __init__(
        self,
        *,
        monitor: CrashMonitor | None = None,
        database: Database | None = None,
        classifier: CrashClassifier | None = None,
        fingerprinter: CrashFingerprinter | None = None,
        severity_assessor: SeverityAssessor | None = None,
    ) -> None:
        self._monitor = monitor or CrashMonitor()
        self._database = database
        self._classifier = classifier or CrashClassifier()
        self._fingerprinter = fingerprinter or CrashFingerprinter()
        self._severity = severity_assessor or SeverityAssessor()

    # ------------------------------------------------------------------ public

    def run_and_record(
        self,
        config: MonitorConfig,
        *,
        input_path: Path | None = None,
        input_bytes: bytes | None = None,
        campaign_id: str | None = None,
        target_id: str | None = None,
        persist: bool = True,
    ) -> DetectionResult:
        """Run the target once and record a crash if one occurred.

        Either ``input_path`` or ``input_bytes`` must be provided; the monitor
        enforces this and raises :class:`MonitorError` otherwise.
        """
        observation = self._monitor.run(
            config, input_path=input_path, input_bytes=input_bytes
        )

        if not observation.crashed:
            return DetectionResult(
                observation=observation, crash=None, persisted=False
            )

        crash = self._build_crash(
            observation, campaign_id=campaign_id, target_id=target_id
        )

        if persist and self._database is not None:
            with self._database.session() as session:
                session.add(CrashRow.from_domain(crash))
            logger.info(
                "Recorded crash %s "
                "(classification=%s, confidence=%s, severity=%s, "
                "signal=%s, fingerprint=%s)",
                crash.id,
                crash.classification.value,
                crash.metadata.get("classification_confidence", "unknown"),
                crash.severity.value,
                crash.signal,
                crash.fingerprint,
            )
            return DetectionResult(
                observation=observation, crash=crash, persisted=True
            )

        return DetectionResult(
            observation=observation, crash=crash, persisted=False
        )

    # ------------------------------------------------------------------ internals

    def _build_crash(
        self,
        observation: CrashObservation,
        *,
        campaign_id: str | None,
        target_id: str | None,
    ) -> models.Crash:
        report = observation.report

        # --- Phase 4 analysis ------------------------------------------------
        classification_result = self._classifier.classify(report)
        fingerprint = self._fingerprinter.fingerprint(report)
        severity_result = self._severity.assess(
            report, classification_result.classification
        )

        # --- raw fields ------------------------------------------------------
        primary = report.primary_report
        sanitizer_kind = primary.sanitizer if primary is not None else None

        description = "Crash detected"
        if primary is not None and primary.error_type:
            description = f"{primary.sanitizer.value}: {primary.error_type}"
        elif report.signal_name is not None:
            description = f"terminated by {report.signal_name}"

        stderr_excerpt = report.stderr[-4096:] if report.stderr else None
        stdout_excerpt = report.stdout[-4096:] if report.stdout else None

        stack_trace: str | None = None
        if report.stack_frames:
            stack_trace = "\n".join(frame.raw for frame in report.stack_frames)

        return models.Crash(
            campaign_id=campaign_id,
            target_id=target_id,
            description=description,
            input_path=observation.input_path,
            evidence_path=observation.stderr_path,
            signal=report.signal_number,
            exit_code=report.exit_code,
            sanitizer=sanitizer_kind,
            classification=classification_result.classification,
            severity=severity_result.severity,
            fingerprint=fingerprint.value,
            stack_trace=stack_trace,
            source_location=report.source_location,
            stdout_excerpt=stdout_excerpt,
            stderr_excerpt=stderr_excerpt,
            metadata={
                # --- raw evidence locations ---
                "evidence_dir": str(observation.evidence_dir),
                "stdout_path": str(observation.stdout_path),
                "duration_seconds": observation.duration_seconds,
                "timed_out": observation.timed_out,
                "sanitizer_options": observation.environment,
                # --- Phase 4 analysis provenance ---
                "classification_confidence": classification_result.confidence.value,
                "classification_sanitizer": (
                    classification_result.sanitizer.value
                    if classification_result.sanitizer is not None
                    else None
                ),
                "classification_source_report_index": (
                    classification_result.source_report_index
                ),
                "classification_evidence": list(classification_result.evidence),
                "severity_rationale": severity_result.rationale,
                "severity_factors": [
                    {"factor": k, "value": v} for k, v in severity_result.factors
                ],
                "fingerprint_canonical": fingerprint.canonical,
                "fingerprint_algorithm": fingerprint.algorithm,
            },
        )
