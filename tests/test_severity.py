"""Severity assessor: evidence-based, no exploitability claims."""

from __future__ import annotations

from kmcs.analysis.crash_parser import (
    AccessType,
    CrashReport,
    SanitizerReport,
)
from kmcs.analysis.severity import SeverityAssessor
from kmcs.core.models import CrashClassification, SanitizerKind, Severity


def _report(
    *,
    classification: CrashClassification = CrashClassification.UNKNOWN,
    error_type: str | None = None,
    access: AccessType = AccessType.UNKNOWN,
    faulting_address: int | None = None,
    sanitizer: SanitizerKind = SanitizerKind.ADDRESS,
) -> CrashReport:
    primary = None
    if error_type is not None or faulting_address is not None:
        primary = SanitizerReport(
            sanitizer=sanitizer,
            error_type=error_type,
            access_type=access,
            faulting_address=faulting_address,
        )
    return CrashReport(
        sanitizer_reports=[primary] if primary else [],
        classification=classification,
    )


class TestBaseSeverity:
    def test_heap_buffer_overflow_is_high(self) -> None:
        r = SeverityAssessor().assess(
            _report(error_type="heap-buffer-overflow", access=AccessType.WRITE),
            CrashClassification.HEAP_BUFFER_OVERFLOW,
        )
        assert r.severity is Severity.HIGH
        assert r.factors

    def test_use_after_free_is_high(self) -> None:
        r = SeverityAssessor().assess(
            _report(error_type="heap-use-after-free"),
            CrashClassification.USE_AFTER_FREE,
        )
        assert r.severity is Severity.HIGH

    def test_memory_leak_is_info(self) -> None:
        r = SeverityAssessor().assess(
            _report(error_type="direct leak", sanitizer=SanitizerKind.LEAK),
            CrashClassification.MEMORY_LEAK,
        )
        assert r.severity is Severity.INFO

    def test_undefined_behavior_is_low(self) -> None:
        r = SeverityAssessor().assess(
            _report(error_type="signed integer overflow", sanitizer=SanitizerKind.UNDEFINED),
            CrashClassification.UNDEFINED_BEHAVIOR,
        )
        assert r.severity is Severity.LOW

    def test_null_pointer_is_low(self) -> None:
        r = SeverityAssessor().assess(
            _report(error_type="null pointer", sanitizer=SanitizerKind.UNDEFINED),
            CrashClassification.NULL_POINTER_DEREFERENCE,
        )
        assert r.severity is Severity.LOW


class TestAccessTypeAdjustment:
    def test_heap_buffer_overflow_read_is_medium(self) -> None:
        r = SeverityAssessor().assess(
            _report(error_type="heap-buffer-overflow", access=AccessType.READ),
            CrashClassification.HEAP_BUFFER_OVERFLOW,
        )
        assert r.severity is Severity.MEDIUM
        assert any("access_type" in factor for factor, _ in r.factors)

    def test_heap_buffer_overflow_write_remains_high(self) -> None:
        r = SeverityAssessor().assess(
            _report(error_type="heap-buffer-overflow", access=AccessType.WRITE),
            CrashClassification.HEAP_BUFFER_OVERFLOW,
        )
        assert r.severity is Severity.HIGH


class TestSegfaultHeuristic:
    def test_near_null_address_downgrades(self) -> None:
        r = SeverityAssessor().assess(
            _report(
                error_type="SEGV",
                faulting_address=0x0,
            ),
            CrashClassification.SEGMENTATION_FAULT,
        )
        assert r.severity is Severity.LOW
        assert "null" in r.rationale.lower()

    def test_non_null_segfault_remains_unknown(self) -> None:
        r = SeverityAssessor().assess(
            _report(error_type="SEGV", faulting_address=0xDEADBEEF),
            CrashClassification.SEGMENTATION_FAULT,
        )
        assert r.severity is Severity.UNKNOWN
        assert "manual review" in r.rationale.lower() or "cannot" in r.rationale.lower()

    def test_segfault_without_address_is_unknown(self) -> None:
        r = SeverityAssessor().assess(
            CrashReport(signal_number=11, signal_name="SIGSEGV"),
            CrashClassification.SEGMENTATION_FAULT,
        )
        assert r.severity is Severity.UNKNOWN


class TestHonesty:
    def test_never_returns_critical(self) -> None:
        assessor = SeverityAssessor()
        for classification in CrashClassification:
            report = _report(
                error_type="anything", access=AccessType.WRITE
            )
            result = assessor.assess(report, classification)
            assert result.severity is not Severity.CRITICAL

    def test_unknown_classification_yields_unknown_severity(self) -> None:
        r = SeverityAssessor().assess(
            CrashReport(), CrashClassification.UNKNOWN
        )
        assert r.severity is Severity.UNKNOWN

    def test_rationale_is_always_present(self) -> None:
        assessor = SeverityAssessor()
        for classification in CrashClassification:
            r = assessor.assess(CrashReport(), classification)
            assert r.rationale

    def test_result_is_serialisable(self) -> None:
        import json

        r = SeverityAssessor().assess(
            _report(error_type="heap-buffer-overflow", access=AccessType.WRITE),
            CrashClassification.HEAP_BUFFER_OVERFLOW,
        )
        json.dumps(r.to_dict())
