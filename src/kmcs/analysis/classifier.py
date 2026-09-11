"""Crash classification with evidence and confidence.

The Phase 3 parser assigns a classification to a :class:`CrashReport` by
examining **the first sanitizer report**.  That is a reasonable default, but it
is not enough when more than one sanitizer fires — a target built with both
AddressSanitizer and UndefinedBehaviorSanitizer can produce several reports in
a single execution, and the *most informative* one is what an analyst wants.

This module:

* classifies **each** sanitizer report independently,
* selects the report with the highest severity priority,
* returns classification, confidence, and the raw evidence that supported it.

Design constraints:

* No guessing.  A report whose ``error_type`` matches no known pattern yields
  :class:`CrashClassification.UNKNOWN` with :class:`Confidence.UNKNOWN`.
* The classifier does **not** mutate the :class:`CrashReport`.  Callers that
  want the classifier's result to be authoritative use the returned
  :class:`ClassificationResult`.
* Priority ordering is explicit and documented — ``heap-buffer-overflow``
  outranks ``signed integer overflow``, because memory corruption is the more
  serious finding and should drive the title and severity of the report.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import ClassVar

from kmcs.analysis.crash_parser import (
    CrashReport,
    SanitizerReport,
    classify_asan_error_type,
    classify_ubsan_message,
)
from kmcs.core.models import CrashClassification, SanitizerKind

__all__ = [
    "Confidence",
    "ClassificationResult",
    "CrashClassifier",
]


class Confidence(str, Enum):
    """How strongly the evidence supports the returned classification."""

    CERTAIN = "certain"
    """The sanitizer explicitly named an error type that maps to a known class."""

    PROBABLE = "probable"
    """A specific pattern matched, but with a small amount of inference."""

    POSSIBLE = "possible"
    """Only weak evidence was available; treat as a hint, not a diagnosis."""

    UNKNOWN = "unknown"
    """No evidence supports any classification."""


@dataclass(frozen=True, slots=True)
class ClassificationResult:
    classification: CrashClassification
    confidence: Confidence
    sanitizer: SanitizerKind | None
    """The sanitizer whose report produced this classification, if any."""
    source_report_index: int | None
    """Index into ``report.sanitizer_reports``, or ``None`` for signal-based
    or empty classifications."""
    evidence: tuple[str, ...]
    """Human-readable notes describing what was matched.  Never empty for a
    non-UNKNOWN classification."""

    def to_dict(self) -> dict[str, object]:
        return {
            "classification": self.classification.value,
            "confidence": self.confidence.value,
            "sanitizer": self.sanitizer.value if self.sanitizer else None,
            "source_report_index": self.source_report_index,
            "evidence": list(self.evidence),
        }


# Priority determines which report becomes the "primary" classification when
# several sanitizers have fired.  Higher is more informative / more serious.
_CLASSIFICATION_PRIORITY: dict[CrashClassification, int] = {
    CrashClassification.HEAP_BUFFER_OVERFLOW: 100,
    CrashClassification.STACK_BUFFER_OVERFLOW: 95,
    CrashClassification.USE_AFTER_FREE: 90,
    CrashClassification.DOUBLE_FREE: 85,
    CrashClassification.OUT_OF_BOUNDS_WRITE: 80,
    CrashClassification.INVALID_FREE: 78,
    CrashClassification.GLOBAL_BUFFER_OVERFLOW: 75,
    CrashClassification.OUT_OF_BOUNDS_READ: 70,
    CrashClassification.SEGMENTATION_FAULT: 65,
    CrashClassification.NULL_POINTER_DEREFERENCE: 60,
    CrashClassification.UNDEFINED_BEHAVIOR: 50,
    CrashClassification.MEMORY_LEAK: 30,
    CrashClassification.UNKNOWN: 0,
}


class CrashClassifier:
    """Classifies a :class:`CrashReport` with evidence and confidence."""

    _PRIORITY: ClassVar[dict[CrashClassification, int]] = _CLASSIFICATION_PRIORITY

    # ------------------------------------------------------------------ public

    def classify(self, report: CrashReport) -> ClassificationResult:
        """Return the classifier's verdict on ``report``."""
        if not report.sanitizer_reports:
            return self._classify_signal_only(report)

        candidates: list[tuple[int, int, ClassificationResult]] = []
        for index, sr in enumerate(report.sanitizer_reports):
            result = self._classify_report(sr, index)
            priority = self._PRIORITY.get(result.classification, 0)
            # Sort key: highest priority first, then earliest report wins.
            candidates.append((-priority, index, result))

        candidates.sort(key=lambda item: (item[0], item[1]))
        return candidates[0][2]

    # ------------------------------------------------------------------ signal

    def _classify_signal_only(self, report: CrashReport) -> ClassificationResult:
        """Classify a crash that produced no sanitizer report.

        Only SIGSEGV and SIGBUS are unambiguous enough to classify without a
        sanitizer: they almost always mean an invalid memory access.
        Everything else — SIGABRT, SIGILL, SIGFPE — is left as UNKNOWN because
        a plain signal alone cannot distinguish between a memory-safety bug, an
        assertion, and a deliberate abort.
        """
        number = report.signal_number
        if number in (11, 7):  # SIGSEGV, SIGBUS
            return ClassificationResult(
                classification=CrashClassification.SEGMENTATION_FAULT,
                confidence=Confidence.PROBABLE,
                sanitizer=None,
                source_report_index=None,
                evidence=(
                    f"Process terminated by {report.signal_name or f'signal {number}'} "
                    "with no sanitizer report",
                    "Signal alone cannot distinguish a null-pointer dereference "
                    "from a corrupted pointer",
                ),
            )

        return ClassificationResult(
            classification=CrashClassification.UNKNOWN,
            confidence=Confidence.UNKNOWN,
            sanitizer=None,
            source_report_index=None,
            evidence=(
                f"Terminated by {report.signal_name or 'unknown signal'} "
                "with no sanitizer report",
            ) if report.signal_number is not None else (),
        )

    # ------------------------------------------------------------------ per-report

    def _classify_report(
        self, sr: SanitizerReport, index: int
    ) -> ClassificationResult:
        if sr.sanitizer is SanitizerKind.ADDRESS:
            return self._classify_asan(sr, index)
        if sr.sanitizer is SanitizerKind.UNDEFINED:
            return self._classify_ubsan(sr, index)
        if sr.sanitizer is SanitizerKind.LEAK:
            return self._classify_lsan(sr, index)
        if sr.sanitizer is SanitizerKind.MEMORY:
            return self._classify_msan(sr, index)
        if sr.sanitizer is SanitizerKind.THREAD:
            return self._classify_tsan(sr, index)

        return ClassificationResult(
            classification=CrashClassification.UNKNOWN,
            confidence=Confidence.UNKNOWN,
            sanitizer=sr.sanitizer,
            source_report_index=index,
            evidence=(),
        )

    def _classify_asan(
        self, sr: SanitizerReport, index: int
    ) -> ClassificationResult:
        if sr.error_type is None:
            return ClassificationResult(
                classification=CrashClassification.UNKNOWN,
                confidence=Confidence.UNKNOWN,
                sanitizer=SanitizerKind.ADDRESS,
                source_report_index=index,
                evidence=("AddressSanitizer report has no error type",),
            )

        mapped = classify_asan_error_type(sr.error_type)
        if mapped is not None:
            return ClassificationResult(
                classification=mapped,
                confidence=Confidence.CERTAIN,
                sanitizer=SanitizerKind.ADDRESS,
                source_report_index=index,
                evidence=(
                    f"AddressSanitizer named error type '{sr.error_type}'",
                    f"Access type: {sr.access_type.value}",
                ),
            )

        return ClassificationResult(
            classification=CrashClassification.UNKNOWN,
            confidence=Confidence.POSSIBLE,
            sanitizer=SanitizerKind.ADDRESS,
            source_report_index=index,
            evidence=(
                f"AddressSanitizer reported an error type KMCS does not "
                f"recognise: '{sr.error_type}'",
            ),
        )

    def _classify_ubsan(
        self, sr: SanitizerReport, index: int
    ) -> ClassificationResult:
        message = sr.error_type or ""
        mapped = classify_ubsan_message(message)

        if mapped is not None:
            return ClassificationResult(
                classification=mapped,
                confidence=Confidence.CERTAIN,
                sanitizer=SanitizerKind.UNDEFINED,
                source_report_index=index,
                evidence=(
                    f"UndefinedBehaviorSanitizer message: '{message[:120]}'",
                ),
            )

        # UBSan fired but the specific message is not in our table.  The safe
        # fallback is UNDEFINED_BEHAVIOR, since that is precisely what UBSan
        # detects — but we mark it as probable, not certain.
        return ClassificationResult(
            classification=CrashClassification.UNDEFINED_BEHAVIOR,
            confidence=Confidence.PROBABLE,
            sanitizer=SanitizerKind.UNDEFINED,
            source_report_index=index,
            evidence=(
                f"UndefinedBehaviorSanitizer message not in KMCS table: "
                f"'{message[:120]}'",
                "Falling back to UNDEFINED_BEHAVIOR",
            ),
        )

    def _classify_lsan(
        self, sr: SanitizerReport, index: int
    ) -> ClassificationResult:
        return ClassificationResult(
            classification=CrashClassification.MEMORY_LEAK,
            confidence=Confidence.CERTAIN,
            sanitizer=SanitizerKind.LEAK,
            source_report_index=index,
            evidence=(
                f"LeakSanitizer reported: {sr.error_type or 'memory leak'}",
            ),
        )

    def _classify_msan(
        self, sr: SanitizerReport, index: int
    ) -> ClassificationResult:
        return ClassificationResult(
            classification=CrashClassification.UNDEFINED_BEHAVIOR,
            confidence=Confidence.CERTAIN,
            sanitizer=SanitizerKind.MEMORY,
            source_report_index=index,
            evidence=(
                "MemorySanitizer reported an uninitialized read",
                "Uninitialized reads are undefined behaviour, not memory "
                "corruption",
            ),
        )

    def _classify_tsan(
        self, sr: SanitizerReport, index: int
    ) -> ClassificationResult:
        kind = sr.error_type or "concurrency issue"
        return ClassificationResult(
            classification=CrashClassification.UNDEFINED_BEHAVIOR,
            confidence=Confidence.CERTAIN,
            sanitizer=SanitizerKind.THREAD,
            source_report_index=index,
            evidence=(
                f"ThreadSanitizer reported: {kind}",
                "ThreadSanitizer findings are concurrency issues, not "
                "single-threaded memory corruption",
            ),
        )
