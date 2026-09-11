"""Malformed sanitizer output must not crash the parser."""

from __future__ import annotations

from kmcs.analysis.crash_parser import parse_crash
from kmcs.core.models import CrashClassification


class TestMalformed:
    def test_binary_garbage(self) -> None:
        report = parse_crash(stderr=b"\x00\x01\x02\xff\xfe".decode("latin-1"))
        assert report.classification is CrashClassification.UNKNOWN

    def test_truncated_asan_header(self) -> None:
        report = parse_crash(stderr="==1==ERROR: AddressSanitizer:")
        assert report.primary_report is not None
        assert report.primary_report.sanitizer.value == "address"

    def test_asan_with_no_frames(self) -> None:
        text = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        report = parse_crash(stderr=text)
        assert report.classification is CrashClassification.HEAP_BUFFER_OVERFLOW
        assert report.stack_frames == []

    def test_frames_with_odd_formatting(self) -> None:
        text = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "#0   0xabc   in   func  /a.c:10  \n"
            "#1 0xdef (binary+0x123)\n"
        )
        report = parse_crash(stderr=text)
        assert len(report.stack_frames) == 2

    def test_very_long_line(self) -> None:
        text = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        text += "#0 0x1 in func " + "A" * 100_000 + "\n"
        report = parse_crash(stderr=text)
        assert report.classification is CrashClassification.HEAP_BUFFER_OVERFLOW

    def test_duplicate_headers(self) -> None:
        text = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 0x1 in a /a.c:1\n"
            "==2==ERROR: AddressSanitizer: heap-use-after-free\n"
            "    #0 0x2 in b /b.c:2\n"
        )
        report = parse_crash(stderr=text)
        assert len(report.sanitizer_reports) == 2
        # Highest priority classification wins.
        assert report.classification is CrashClassification.HEAP_BUFFER_OVERFLOW
