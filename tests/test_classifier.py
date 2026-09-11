"""Classifier: single-report, multi-report, and signal-only behaviour."""

from __future__ import annotations

from kmcs.analysis.classifier import Confidence, CrashClassifier
from kmcs.analysis.crash_parser import (
    AccessType,
    CrashReport,
    SanitizerReport,
    StackFrame,
)
from kmcs.core.models import CrashClassification, SanitizerKind


def _frame(idx: int = 0, func: str = "main", file: str = "/s/a.c", line: int = 1) -> StackFrame:
    return StackFrame(index=idx, raw=f"#{idx} {func} {file}:{line}", function=func, source_file=file, line=line)


class TestSingleReport:
    def test_asan_heap_buffer_overflow_is_certain(self) -> None:
        report = CrashReport(
            sanitizer_reports=[
                SanitizerReport(
                    sanitizer=SanitizerKind.ADDRESS,
                    error_type="heap-buffer-overflow",
                    access_type=AccessType.WRITE,
                )
            ]
        )
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.HEAP_BUFFER_OVERFLOW
        assert result.confidence is Confidence.CERTAIN
        assert result.sanitizer is SanitizerKind.ADDRESS
        assert result.source_report_index == 0
        assert result.evidence

    def test_asan_unknown_error_type_is_possible(self) -> None:
        report = CrashReport(
            sanitizer_reports=[
                SanitizerReport(
                    sanitizer=SanitizerKind.ADDRESS,
                    error_type="some-new-asan-error",
                )
            ]
        )
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.UNKNOWN
        assert result.confidence is Confidence.POSSIBLE

    def test_asan_attempting_free_is_invalid_free(self) -> None:
        report = CrashReport(
            sanitizer_reports=[
                SanitizerReport(
                    sanitizer=SanitizerKind.ADDRESS,
                    error_type="attempting free on address which was not malloc()-ed",
                )
            ]
        )
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.INVALID_FREE
        assert result.confidence is Confidence.CERTAIN

    def test_ubsan_signed_overflow(self) -> None:
        report = CrashReport(
            sanitizer_reports=[
                SanitizerReport(
                    sanitizer=SanitizerKind.UNDEFINED,
                    error_type="signed integer overflow: 2147483647 + 1 cannot be represented",
                )
            ]
        )
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.UNDEFINED_BEHAVIOR
        assert result.confidence is Confidence.CERTAIN

    def test_ubsan_null_pointer(self) -> None:
        report = CrashReport(
            sanitizer_reports=[
                SanitizerReport(
                    sanitizer=SanitizerKind.UNDEFINED,
                    error_type="member access within null pointer of type 'struct Foo'",
                )
            ]
        )
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.NULL_POINTER_DEREFERENCE
        assert result.confidence is Confidence.CERTAIN

    def test_ubsan_unknown_message_falls_back_to_undefined_behavior(self) -> None:
        report = CrashReport(
            sanitizer_reports=[
                SanitizerReport(
                    sanitizer=SanitizerKind.UNDEFINED,
                    error_type="something the classifier has never seen",
                )
            ]
        )
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.UNDEFINED_BEHAVIOR
        assert result.confidence is Confidence.PROBABLE

    def test_lsan_leak(self) -> None:
        report = CrashReport(
            sanitizer_reports=[
                SanitizerReport(
                    sanitizer=SanitizerKind.LEAK, error_type="direct leak"
                )
            ]
        )
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.MEMORY_LEAK
        assert result.confidence is Confidence.CERTAIN

    def test_msan_uninitialized_read(self) -> None:
        report = CrashReport(
            sanitizer_reports=[
                SanitizerReport(
                    sanitizer=SanitizerKind.MEMORY,
                    error_type="use-of-uninitialized-value",
                )
            ]
        )
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.UNDEFINED_BEHAVIOR
        assert result.sanitizer is SanitizerKind.MEMORY

    def test_tsan_data_race(self) -> None:
        report = CrashReport(
            sanitizer_reports=[
                SanitizerReport(sanitizer=SanitizerKind.THREAD, error_type="data race")
            ]
        )
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.UNDEFINED_BEHAVIOR
        assert result.sanitizer is SanitizerKind.THREAD


class TestMultipleReports:
    def test_higher_priority_wins(self) -> None:
        report = CrashReport(
            sanitizer_reports=[
                SanitizerReport(
                    sanitizer=SanitizerKind.UNDEFINED,
                    error_type="signed integer overflow",
                ),
                SanitizerReport(
                    sanitizer=SanitizerKind.ADDRESS,
                    error_type="heap-buffer-overflow",
                    access_type=AccessType.WRITE,
                ),
            ]
        )
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.HEAP_BUFFER_OVERFLOW
        assert result.source_report_index == 1

    def test_ties_break_toward_the_earliest_report(self) -> None:
        report = CrashReport(
            sanitizer_reports=[
                SanitizerReport(
                    sanitizer=SanitizerKind.ADDRESS,
                    error_type="heap-buffer-overflow",
                ),
                SanitizerReport(
                    sanitizer=SanitizerKind.ADDRESS,
                    error_type="heap-buffer-overflow",
                ),
            ]
        )
        result = CrashClassifier().classify(report)
        assert result.source_report_index == 0


class TestCompoundErrorTypes:
    def test_attempting_free_is_invalid_free(self) -> None:
        import pathlib
        text = pathlib.Path(
            __file__
        ).parent.joinpath("fixtures/sanitizer_output/asan_invalid_free.txt").read_text()
        from kmcs.analysis.crash_parser import parse_crash
        report = parse_crash(stderr=text)
        assert report.primary_report is not None
        assert report.primary_report.error_type == (
            "attempting free on address which was not malloc()-ed"
        )
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.INVALID_FREE


class TestSignalOnly:
    def test_sigsegv_is_segmentation_fault(self) -> None:
        report = CrashReport(signal_number=11, signal_name="SIGSEGV")
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.SEGMENTATION_FAULT
        assert result.confidence is Confidence.PROBABLE
        assert result.sanitizer is None

    def test_sigabrt_is_unknown(self) -> None:
        report = CrashReport(signal_number=6, signal_name="SIGABRT")
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.UNKNOWN
        assert result.confidence is Confidence.UNKNOWN

    def test_clean_exit_is_unknown(self) -> None:
        report = CrashReport(exit_code=0)
        result = CrashClassifier().classify(report)
        assert result.classification is CrashClassification.UNKNOWN

    def test_no_evidence_at_all(self) -> None:
        result = CrashClassifier().classify(CrashReport())
        assert result.classification is CrashClassification.UNKNOWN
        assert result.confidence is Confidence.UNKNOWN
