"""Verify that KMCS remains responsive at realistic scale."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from kmcs.analysis.crash_parser import CrashReport, SanitizerReport, StackFrame
from kmcs.analysis.deduplicator import CrashDeduplicator
from kmcs.analysis.fingerprint import CrashFingerprinter
from kmcs.core.models import (
    Crash,
    CrashClassification,
    SanitizerKind,
)
from kmcs.reporting.base import ReportContext


def _crash(idx: int, fingerprint: str) -> Crash:
    return Crash(
        id=f"crash-{idx:06d}",
        fingerprint=fingerprint,
        description=f"crash {idx}",
        signal=11,
        classification=CrashClassification.HEAP_BUFFER_OVERFLOW,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc)
        + timedelta(seconds=idx),
    )


def _report(fingerprint: str) -> CrashReport:
    frame = StackFrame(
        index=0,
        raw=f"#0 0x1 in main /s/a.c:10",
        function="main",
        source_file="/s/a.c",
        line=10,
    )
    primary = SanitizerReport(
        sanitizer=SanitizerKind.ADDRESS,
        error_type="heap-buffer-overflow",
        stack_frames=[frame],
    )
    return CrashReport(
        sanitizer_reports=[primary],
        stack_frames=[frame],
        classification=CrashClassification.HEAP_BUFFER_OVERFLOW,
    )


class TestDeduplicationScale:
    def test_10k_crashes_across_50_fingerprints(self) -> None:
        observations = []
        for i in range(10_000):
            fp = f"fp-{i % 50}"
            observations.append((_crash(i, fp), _report(fp)))

        started = time.monotonic()
        result = CrashDeduplicator().deduplicate(observations)
        elapsed = time.monotonic() - started

        assert result.total_crashes == 10_000
        assert result.total_groups == 50
        assert result.duplicates_removed == 9_950
        assert elapsed < 10.0, f"dedup took {elapsed:.2f}s (expected <10s)"


class TestFingerprintScale:
    def test_fingerprint_is_linear(self) -> None:
        fp = CrashFingerprinter()
        report = _report("x")
        started = time.monotonic()
        for _ in range(10_000):
            fp.fingerprint(report)
        elapsed = time.monotonic() - started
        assert elapsed < 5.0, f"10k fingerprints took {elapsed:.2f}s"


class TestParserScale:
    def test_1mib_asan_output(self) -> None:
        from kmcs.analysis.crash_parser import parse_crash

        frame = "#0 0x1 in main /s/a.c:10\n"
        header = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        # ~1 MiB of frame lines.
        text = header + frame * (1_048_576 // len(frame))
        started = time.monotonic()
        report = parse_crash(stderr=text)
        elapsed = time.monotonic() - started
        assert report.primary_report is not None
        assert elapsed < 5.0, f"1 MiB parse took {elapsed:.2f}s"


class TestReportScale:
    def test_1000_findings_markdown(self) -> None:
        from kmcs.reporting.markdown import MarkdownReportRenderer

        findings = []
        crashes = []
        for i in range(1000):
            fp = f"fp-{i}"
            crash = _crash(i, fp)
            crashes.append(crash)
            from kmcs.core.models import Finding

            findings.append(
                Finding(
                    id=f"finding-{i}",
                    title=f"Finding {i}",
                    fingerprint=fp,
                    classification=CrashClassification.HEAP_BUFFER_OVERFLOW,
                    crash_ids=[crash.id],
                )
            )

        ctx = ReportContext(findings=findings, crashes=crashes)
        started = time.monotonic()
        rendered = MarkdownReportRenderer().render(ctx)
        elapsed = time.monotonic() - started
        assert rendered
        assert elapsed < 5.0, f"1000-finding markdown took {elapsed:.2f}s"

    def test_1000_findings_sarif(self) -> None:
        from kmcs.reporting.sarif import SARIFReportRenderer

        findings = []
        for i in range(1000):
            from kmcs.core.models import Finding

            findings.append(
                Finding(
                    id=f"finding-{i}",
                    title=f"Finding {i}",
                    fingerprint=f"fp-{i}",
                    classification=CrashClassification.HEAP_BUFFER_OVERFLOW,
                )
            )

        ctx = ReportContext(findings=findings)
        started = time.monotonic()
        rendered = SARIFReportRenderer().render(ctx)
        elapsed = time.monotonic() - started
        assert rendered
        assert elapsed < 3.0, f"1000-finding SARIF took {elapsed:.2f}s"


class TestTelemetryScale:
    def test_100_workers_1000_updates_each(self) -> None:
        from kmcs.campaigns.telemetry import TelemetryAggregator

        aggregator = TelemetryAggregator()
        started = time.monotonic()
        for worker in range(100):
            aggregator.register_worker(worker)
            for i in range(1000):
                aggregator.increment(worker, "artifacts_seen")
                if i % 10 == 0:
                    aggregator.update(
                        worker,
                        executions=i,
                        crashes=i // 100,
                    )
        snapshot = aggregator.snapshot()
        elapsed = time.monotonic() - started
        assert len(snapshot.workers) == 100
        assert snapshot.total_artifacts_seen == 100_000
        assert elapsed < 5.0, f"100k telemetry ops took {elapsed:.2f}s"
