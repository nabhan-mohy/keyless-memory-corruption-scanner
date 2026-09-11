"""Markdown report renderer.

Output is plain CommonMark with GitHub-flavoured tables.  No HTML tags are
emitted, so the same document renders identically in GitHub, GitLab, Gitea,
VS Code, and every Markdown preview that follows CommonMark.

Long descriptions and stack traces are placed inside fenced code blocks with
an explicit info string so they are neither re-parsed as Markdown nor mangled
by whitespace collapsing.
"""

from __future__ import annotations

import json

from kmcs.core import models
from kmcs.reporting.base import (
    RenderedReport,
    ReportContext,
    ReportFormat,
    ReportRenderer,
    SEVERITY_ORDER,
)

__all__ = ["MarkdownReportRenderer"]

_MAX_SAMPLE_CRASHES = 10


class MarkdownReportRenderer(ReportRenderer):
    format = ReportFormat.MARKDOWN

    # ------------------------------------------------------------------ public

    def render(self, context: ReportContext) -> str:
        sections: list[list[str]] = [
            self._header(context),
            self._summary(context),
        ]

        if context.findings:
            sections.append(self._severity_breakdown(context))

        if context.section.include_findings and context.findings:
            sections.append(self._findings(context))

        if context.section.include_crashes and context.crashes:
            sections.append(self._crashes(context))

        if context.section.include_campaigns and context.campaigns:
            sections.append(self._campaigns(context))

        if context.section.include_targets and context.targets:
            sections.append(self._targets(context))

        if context.section.include_corpora and context.corpora:
            sections.append(self._corpora(context))

        if context.section.include_telemetry and context.telemetry:
            sections.append(self._telemetry(context))

        if context.metadata:
            sections.append(self._metadata(context))

        return self._join(sections)

    # ------------------------------------------------------------------ sections

    @staticmethod
    def _join(sections: list[list[str]]) -> str:
        chunks: list[str] = []
        for section in sections:
            if not section:
                continue
            chunks.append("\n".join(section).rstrip())
        return "\n\n".join(chunks) + "\n"

    @staticmethod
    def _header(context: ReportContext) -> list[str]:
        lines = [f"# {context.title}", ""]
        lines.append(f"- **Report ID:** `{context.report_id[:12]}`")
        lines.append(f"- **Generated:** {context.generated_at.isoformat()}")
        lines.append(f"- **KMCS version:** `{context.kmcs_version}`")
        if context.campaign is not None:
            lines.append(
                f"- **Campaign:** {context.campaign.name} "
                f"(`{context.campaign.id}`, {context.campaign.status.value})"
            )
        return lines

    @staticmethod
    def _summary(context: ReportContext) -> list[str]:
        summary = context.summary
        lines = ["## Summary", "", "| Metric | Count |", "| --- | ---: |"]
        lines.append(f"| Findings | {summary.findings} |")
        lines.append(f"| Crashes | {summary.crashes} |")
        lines.append(f"| Campaigns | {summary.campaigns} |")
        lines.append(f"| Targets | {summary.targets} |")
        lines.append(f"| Corpora | {summary.corpora} |")
        return lines

    @staticmethod
    def _severity_breakdown(context: ReportContext) -> list[str]:
        counts = context.summary.findings_by_severity
        lines = ["## Findings by severity", "", "| Severity | Count |", "| --- | ---: |"]
        for severity in SEVERITY_ORDER:
            lines.append(f"| {severity.value} | {counts.get(severity.value, 0)} |")
        return lines

    def _findings(self, context: ReportContext) -> list[str]:
        lines = ["## Findings", ""]
        for index, finding in enumerate(context.findings_sorted(), start=1):
            lines.extend(self._finding_section(context, finding, index))
            lines.append("")
        return lines

    def _finding_section(
        self,
        context: ReportContext,
        finding: models.Finding,
        index: int,
    ) -> list[str]:
        lines: list[str] = [f"### {index}. {finding.title}", ""]

        lines.append(f"- **ID:** `{finding.id}`")
        lines.append(f"- **Classification:** `{finding.classification.value}`")
        lines.append(f"- **Severity:** `{finding.severity.value}`")
        lines.append(f"- **Fingerprint:** `{finding.fingerprint}`")
        lines.append(f"- **Occurrences:** {len(finding.crash_ids)}")
        lines.append(
            f"- **Reproduction:** `{finding.reproduction_status.value}`"
        )
        if finding.target_id:
            lines.append(f"- **Target:** `{finding.target_id}`")
        lines.append("")

        if finding.description:
            lines.extend(["**Description**", "", "```text"])
            lines.append(finding.description.rstrip())
            lines.append("```")
            lines.append("")

        if finding.remediation:
            lines.extend(
                ["**Remediation**", "", finding.remediation.strip(), ""]
            )

        crashes = context.crashes_for_finding(finding)
        if crashes:
            lines.extend(self._sample_crashes_table(crashes))

        return lines

    @staticmethod
    def _sample_crashes_table(crashes: list[models.Crash]) -> list[str]:
        lines = ["**Reproducing inputs**", ""]
        lines.append("| Crash ID | Signal | Source location | Input |")
        lines.append("| --- | ---: | --- | --- |")
        for crash in crashes[:_MAX_SAMPLE_CRASHES]:
            signal = crash.signal if crash.signal is not None else "—"
            location = crash.source_location or "—"
            input_path = str(crash.input_path) if crash.input_path else "—"
            lines.append(
                f"| `{crash.id}` | {signal} | `{location}` | `{input_path}` |"
            )
        remaining = len(crashes) - _MAX_SAMPLE_CRASHES
        if remaining > 0:
            lines.append(f"| _…_ | _…_ | _…_ | {remaining} more |")
        lines.append("")
        return lines

    @staticmethod
    def _crashes(context: ReportContext) -> list[str]:
        lines = ["## Crashes", ""]
        lines.append(
            "| Crash ID | Classification | Signal | Fingerprint | Source location |"
        )
        lines.append("| --- | --- | ---: | --- | --- |")
        for crash in context.crashes:
            signal = crash.signal if crash.signal is not None else "—"
            fingerprint = crash.fingerprint or "—"
            location = crash.source_location or "—"
            lines.append(
                f"| `{crash.id}` | `{crash.classification.value}` | {signal} | "
                f"`{fingerprint}` | `{location}` |"
            )
        return lines

    @staticmethod
    def _campaigns(context: ReportContext) -> list[str]:
        lines = ["## Campaigns", ""]
        lines.append("| Name | Fuzzer | Workers | Status | Duration |")
        lines.append("| --- | --- | ---: | --- | ---: |")
        for campaign in context.campaigns:
            duration = (
                f"{campaign.duration_seconds}s"
                if campaign.duration_seconds is not None
                else "—"
            )
            lines.append(
                f"| {campaign.name} | `{campaign.fuzzer.value}` | "
                f"{campaign.workers} | `{campaign.status.value}` | {duration} |"
            )
        return lines

    @staticmethod
    def _targets(context: ReportContext) -> list[str]:
        lines = ["## Targets", ""]
        lines.append("| Name | Compiler | Build configuration | Sanitizers |")
        lines.append("| --- | --- | --- | --- |")
        for target in context.targets:
            compiler = target.compiler or "—"
            sanitizers = ", ".join(s.value for s in target.sanitizers) or "—"
            lines.append(
                f"| {target.name} | `{compiler}` | "
                f"`{target.build_configuration.value}` | {sanitizers} |"
            )
        return lines

    @staticmethod
    def _corpora(context: ReportContext) -> list[str]:
        lines = ["## Corpora", ""]
        lines.append("| Name | Target | Files | Size (bytes) |")
        lines.append("| --- | --- | ---: | ---: |")
        for corpus in context.corpora:
            lines.append(
                f"| {corpus.name} | `{corpus.target_id or '—'}` | "
                f"{corpus.file_count} | {corpus.total_bytes} |"
            )
        return lines

    @staticmethod
    def _telemetry(context: ReportContext) -> list[str]:
        assert context.telemetry is not None
        lines = ["## Telemetry", "", "```json"]
        lines.append(json.dumps(context.telemetry, indent=2, sort_keys=True))
        lines.append("```")
        return lines

    @staticmethod
    def _metadata(context: ReportContext) -> list[str]:
        lines = ["## Additional metadata", ""]
        for key, value in sorted(context.metadata.items()):
            lines.append(f"- **{key}:** `{value}`")
        return lines
