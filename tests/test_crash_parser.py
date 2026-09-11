"""Parse real sanitizer output samples into structured reports."""

from __future__ import annotations

from pathlib import Path

import pytest

from kmcs.analysis.crash_parser import (
    AccessType,
    CrashParser,
    parse_crash,
)
from kmcs.core.models import CrashClassification, SanitizerKind


FIXTURES = Path(__file__).parent / "fixtures" / "sanitizer_output"


def _load(name: str) -> str:
    path = FIXTURES / name
    assert path.is_file(), f"missing fixture: {path}"
    return path.read_text(encoding="utf-8")


class TestASanHeapBufferOverflow:
    @pytest.fixture()
    def report(self):
        return parse_crash(stderr=_load("asan_heap_buffer_overflow.txt"))

    def test_classification(self, report) -> None:
        assert report.classification is CrashClassification.HEAP_BUFFER_OVERFLOW

    def test_primary_report_is_asan(self, report) -> None:
        primary = report.primary_report
        assert primary is not None
        assert primary.sanitizer is SanitizerKind.ADDRESS
        assert primary.error_type == "heap-buffer-overflow"

    def test_access_fields(self, report) -> None:
        primary = report.primary_report
        assert primary is not None
        assert primary.access_type is AccessType.WRITE
        assert primary.access_size == 32
        assert primary.faulting_address == 0x6020000000B8

    def test_region_fields(self, report) -> None:
        primary = report.primary_report
        assert primary is not None
        assert primary.region_size == 8
        assert primary.region_start == 0x6020000000B0
        assert primary.region_end == 0x6020000000B8

    def test_top_frame_has_source_location(self, report) -> None:
        top = report.stack_frames[0]
        assert top.function == "main"
        assert top.source_file == "/src/demo/vulnerable.c"
        assert top.line == 18
        assert top.column == 5

    def test_source_location_shortcut(self, report) -> None:
        assert report.source_location == "/src/demo/vulnerable.c:18:5"

    def test_allocation_site_is_separate(self, report) -> None:
        primary = report.primary_report
        assert primary is not None
        # The allocation site's #1 frame points at vulnerable.c:15
        allocation_lines = [f.raw for f in primary.allocation_site]
        assert any("/src/demo/vulnerable.c:15" in line for line in allocation_lines)

    def test_summary_line_was_captured(self, report) -> None:
        primary = report.primary_report
        assert primary is not None
        assert primary.summary is not None
        assert "heap-buffer-overflow" in primary.summary

    def test_crashed_is_true(self, report) -> None:
        assert report.crashed is True

    def test_to_dict_is_serialisable(self, report) -> None:
        import json

        json.dumps(report.to_dict())


class TestASanUseAfterFree:
    @pytest.fixture()
    def report(self):
        return parse_crash(stderr=_load("asan_use_after_free.txt"))

    def test_classification(self, report) -> None:
        assert report.classification is CrashClassification.USE_AFTER_FREE

    def test_access_is_a_read(self, report) -> None:
        primary = report.primary_report
        assert primary is not None
        assert primary.access_type is AccessType.READ
        assert primary.access_size == 4

    def test_free_site_is_captured(self, report) -> None:
        primary = report.primary_report
        assert primary is not None
        free_lines = [f.raw for f in primary.free_site]
        assert any("uaf.c:20" in line for line in free_lines)


class TestUBSanSignedOverflow:
    @pytest.fixture()
    def report(self):
        return parse_crash(stderr=_load("ubsan_signed_overflow.txt"))

    def test_classification(self, report) -> None:
        assert report.classification is CrashClassification.UNDEFINED_BEHAVIOR

    def test_primary_report_is_ubsan(self, report) -> None:
        primary = report.primary_report
        assert primary is not None
        assert primary.sanitizer is SanitizerKind.UNDEFINED
        assert "signed integer overflow" in (primary.error_type or "")

    def test_stack_frames_extracted(self, report) -> None:
        assert len(report.stack_frames) >= 2
        top = report.stack_frames[0]
        assert top.function == "compute"
        assert top.source_file == "/src/demo/overflow.c"
        assert top.line == 14


class TestRawSignals:
    def test_sigsegv_classified_as_segmentation_fault(self) -> None:
        report = parse_crash(signal_number=11)
        assert report.classification is CrashClassification.SEGMENTATION_FAULT
        assert report.signal_name == "SIGSEGV"
        assert report.crashed is True

    def test_sigabrt_with_no_sanitizer_report_is_unknown(self) -> None:
        report = parse_crash(signal_number=6)
        assert report.classification is CrashClassification.UNKNOWN

    def test_clean_exit_is_not_a_crash(self) -> None:
        report = parse_crash(exit_code=0)
        assert report.crashed is False
        assert report.sanitizer_reports == []

    def test_exit_code_1_is_not_a_crash(self) -> None:
        # Many programs return 1 for benign reasons; KMCS does not treat that
        # as a crash unless the process died by signal or a sanitizer spoke.
        report = parse_crash(exit_code=1)
        assert report.crashed is False

    def test_unusual_exit_code_is_a_crash(self) -> None:
        report = parse_crash(exit_code=134)
        assert report.crashed is True


class TestParserRobustness:
    def test_empty_input_does_not_crash(self) -> None:
        report = parse_crash()
        assert report.sanitizer_reports == []
        assert report.classification is CrashClassification.UNKNOWN

    def test_garbage_input_does_not_crash(self) -> None:
        report = parse_crash(stderr="\x00\x01\x02 not real text \xff\xfe")
        assert isinstance(report.classification, CrashClassification)

    def test_frame_with_offset_only(self) -> None:
        parser = CrashParser()
        text = (
            "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
            "    #0 0x7f0000000000 (/lib/x86_64-linux-gnu/libc.so.6+0x12345)\n"
        )
        report = parser.parse(stderr=text)
        assert report.classification is CrashClassification.SEGMENTATION_FAULT
        top = report.stack_frames[0]
        assert top.module is not None and "libc" in top.module
        assert top.offset == 0x12345

    def test_expected_sanitizer_hint_fills_in_kind(self) -> None:
        # A bare UBSan message with no location prefix.  We provide the hint.
        text = "runtime error: signed integer overflow: 1 + 1 cannot be represented\n"
        report = parse_crash(
            stderr=text, expected_sanitizers=[SanitizerKind.UNDEFINED]
        )
        primary = report.primary_report
        assert primary is not None
        assert primary.sanitizer is SanitizerKind.UNDEFINED
