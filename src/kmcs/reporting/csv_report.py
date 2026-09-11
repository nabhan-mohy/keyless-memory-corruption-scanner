"""CSV report renderer.

A CSV file has one header row, so a mixed findings-and-crashes CSV would be
malformed.  This renderer therefore produces exactly one table.  When both
sections are requested, findings take precedence — they are the *result* of
the analysis; crashes are the raw evidence.

An empty report still emits its header row, so that a downstream pipeline
that reads the file as a table always sees the schema it expects.
"""

from __future__ import annotations

import csv
import io

from kmcs.reporting.base import (
    RenderedReport,
    ReportContext,
    ReportFormat,
    ReportRenderer,
)

__all__ = ["CSVReportRenderer"]


_FINDING_COLUMNS: tuple[str, ...] = (
    "finding_id",
    "title",
    "classification",
    "severity",
    "fingerprint",
    "occurrences",
    "reproduction_status",
    "target_id",
    "first_crash_id",
    "source_location",
    "sample_input",
)

_CRASH_COLUMNS: tuple[str, ...] = (
    "crash_id",
    "campaign_id",
    "target_id",
    "classification",
    "severity",
    "sanitizer",
    "signal",
    "exit_code",
    "fingerprint",
    "source_location",
    "reproduction_status",
    "input_path",
    "evidence_path",
    "created_at",
)


class CSVReportRenderer(ReportRenderer):
    format = ReportFormat.CSV

    def render(self, context: ReportContext) -> str:
        buffer = io.StringIO(newline="")
        writer = csv.writer(buffer, quoting=csv.QUOTE_MINIMAL)

        use_findings = bool(context.findings) and context.section.include_findings
        use_crashes = (
            not use_findings
            and bool(context.crashes)
            and context.section.include_crashes
        )

        if use_findings:
            writer.writerow(_FINDING_COLUMNS)
            self._write_findings(writer, context)
        elif use_crashes:
            writer.writerow(_CRASH_COLUMNS)
            self._write_crashes(writer, context)
        else:
            writer.writerow(_FINDING_COLUMNS)

        return buffer.getvalue()

    # ------------------------------------------------------------------ writers

    @staticmethod
    def _write_findings(writer: csv.writer, context: ReportContext) -> None:
        for finding in context.findings_sorted():
            crashes = context.crashes_for_finding(finding)
            first = crashes[0] if crashes else None
            writer.writerow(
                [
                    finding.id,
                    finding.title,
                    finding.classification.value,
                    finding.severity.value,
                    finding.fingerprint,
                    len(finding.crash_ids),
                    finding.reproduction_status.value,
                    finding.target_id or "",
                    first.id if first else "",
                    first.source_location if first else "",
                    str(first.input_path) if first and first.input_path else "",
                ]
            )

    @staticmethod
    def _write_crashes(writer: csv.writer, context: ReportContext) -> None:
        for crash in context.crashes:
            writer.writerow(
                [
                    crash.id,
                    crash.campaign_id or "",
                    crash.target_id or "",
                    crash.classification.value,
                    crash.severity.value,
                    crash.sanitizer.value if crash.sanitizer else "",
                    crash.signal if crash.signal is not None else "",
                    crash.exit_code if crash.exit_code is not None else "",
                    crash.fingerprint or "",
                    crash.source_location or "",
                    crash.reproduction_status.value,
                    str(crash.input_path) if crash.input_path else "",
                    str(crash.evidence_path) if crash.evidence_path else "",
                    crash.created_at.isoformat(),
                ]
            )
