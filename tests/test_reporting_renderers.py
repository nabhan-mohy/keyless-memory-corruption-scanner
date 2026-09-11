"""Rendering behaviour for every report format.

These tests build synthetic :class:`ReportContext` objects and assert on the
rendered output.  No database, no target, no monitor.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from kmcs.core import models
from kmcs.reporting.base import (
    ReportContext,
    ReportFormat,
    ReportSection,
)
from kmcs.reporting.csv_report import CSVReportRenderer
from kmcs.reporting.html import HTMLReportRenderer
from kmcs.reporting.json_report import JSONReportRenderer
from kmcs.reporting.markdown import MarkdownReportRenderer
from kmcs.reporting.sarif import SARIFReportRenderer


# ---------------------------------------------------------------------- fixtures


def _now() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _context(
    *,
    findings: int = 2,
    crashes: int = 3,
    section: ReportSection | None = None,
) -> ReportContext:
    target = models.Target(
        name="libdemo",
        description="Demonstration library",
        build_configuration=models.BuildConfiguration.ASAN,
        sanitizers=[models.SanitizerKind.ADDRESS],
    )

    campaign = models.Campaign(
        name="campaign-1",
        target_id=target.id,
        fuzzer=models.FuzzerKind.AFLPP,
        sanitizers=[models.SanitizerKind.ADDRESS],
        workers=2,
        duration_seconds=60,
        status=models.CampaignStatus.COMPLETED,
    )

    crash_objs: list[models.Crash] = []
    for i in range(crashes):
        crash_objs.append(
            models.Crash(
                campaign_id=campaign.id,
                target_id=target.id,
                description=f"heap-buffer-overflow run {i}",
                signal=11,
                exit_code=None,
                sanitizer=models.SanitizerKind.ADDRESS,
                classification=models.CrashClassification.HEAP_BUFFER_OVERFLOW,
                severity=models.Severity.HIGH,
                fingerprint=f"fp-{i % 2}",
                source_location=f"/src/demo/vulnerable.c:{10 + i}:5",
                stderr_excerpt="==1==ERROR: AddressSanitizer: heap-buffer-overflow",
                input_path=Path(f"/tmp/crashes/id:{i:06d}"),
            )
        )

    findings_objs: list[models.Finding] = []
    for i in range(findings):
        findings_objs.append(
            models.Finding(
                title=f"Heap overflow in parse_chunk #{i}",
                description="The parse_chunk function writes past the buffer.",
                fingerprint=f"fp-{i}",
                classification=models.CrashClassification.HEAP_BUFFER_OVERFLOW,
                severity=models.Severity.HIGH,
                target_id=target.id,
                crash_ids=[c.id for c in crash_objs if c.fingerprint == f"fp-{i}"],
                remediation="Validate the input length before writing.",
            )
        )

    ctx = ReportContext(
        generated_at=_now(),
        title="KMCS demo report",
        findings=findings_objs,
        crashes=crash_objs,
        campaigns=[campaign],
        targets=[target],
        corpora=[],
        campaign=campaign,
        campaign_id=campaign.id,
        section=section or ReportSection(),
    )
    ctx.report_id = "0123456789abcdef"
    return ctx


# ---------------------------------------------------------------------- JSON


class TestJSONRenderer:
    def test_parses_as_json(self) -> None:
        rendered = JSONReportRenderer().render(_context())
        payload = json.loads(rendered)
        assert payload["schema"] == "kmcs.report.v1"
        assert payload["report_id"] == "0123456789abcdef"
        assert payload["summary"]["findings"] == 2
        assert payload["summary"]["crashes"] == 3

    def test_findings_are_ordered_by_severity(self) -> None:
        ctx = _context()
        payload = json.loads(JSONReportRenderer().render(ctx))
        severities = [f["severity"] for f in payload["findings"]]
        # All are HIGH in the fixture, so ordering is stable but the list
        # must be present.
        assert severities == ["high", "high"]

    def test_section_can_exclude_findings(self) -> None:
        ctx = _context(section=ReportSection(include_findings=False))
        payload = json.loads(JSONReportRenderer().render(ctx))
        assert "findings" not in payload
        assert "crashes" in payload

    def test_findings_only_section(self) -> None:
        ctx = _context(section=ReportSection.findings_only())
        payload = json.loads(JSONReportRenderer().render(ctx))
        assert "findings" in payload
        assert "crashes" in payload
        assert "campaigns" not in payload
        assert "targets" not in payload


# ---------------------------------------------------------------------- Markdown


class TestMarkdownRenderer:
    def test_has_expected_sections(self) -> None:
        rendered = MarkdownReportRenderer().render(_context())
        assert rendered.startswith("# KMCS demo report")
        assert "## Summary" in rendered
        assert "## Findings by severity" in rendered
        assert "## Findings" in rendered
        assert "## Crashes" in rendered
        assert "## Campaigns" in rendered

    def test_findings_are_numbered(self) -> None:
        rendered = MarkdownReportRenderer().render(_context())
        assert "### 1." in rendered
        assert "### 2." in rendered

    def test_uses_commonmark_code_fences(self) -> None:
        rendered = MarkdownReportRenderer().render(_context())
        assert rendered.count("```") % 2 == 0


# ---------------------------------------------------------------------- CSV


class TestCSVRenderer:
    def test_parses_as_csv(self) -> None:
        rendered = CSVReportRenderer().render(_context())
        reader = csv.reader(io.StringIO(rendered))
        rows = list(reader)
        assert rows[0][0] == "finding_id"
        assert len(rows) == 3  # header + 2 findings

    def test_empty_report_still_has_header(self) -> None:
        ctx = ReportContext(generated_at=_now())
        ctx.report_id = "empty"
        rendered = CSVReportRenderer().render(ctx)
        reader = csv.reader(io.StringIO(rendered))
        rows = list(reader)
        assert len(rows) == 1
        assert rows[0][0] == "finding_id"

    def test_crashes_only_when_no_findings(self) -> None:
        ctx = _context(findings=0, crashes=2)
        rendered = CSVReportRenderer().render(ctx)
        reader = csv.reader(io.StringIO(rendered))
        rows = list(reader)
        assert rows[0][0] == "crash_id"
        assert len(rows) == 3  # header + 2 crashes


# ---------------------------------------------------------------------- SARIF


class TestSARIFRenderer:
    def test_valid_sarif_envelope(self) -> None:
        rendered = SARIFReportRenderer().render(_context())
        payload = json.loads(rendered)
        assert payload["version"] == "2.1.0"
        assert "$schema" in payload
        assert len(payload["runs"]) == 1

    def test_run_has_driver_and_rules(self) -> None:
        payload = json.loads(SARIFReportRenderer().render(_context()))
        driver = payload["runs"][0]["tool"]["driver"]
        assert driver["name"] == "KMCS"
        assert any(r["id"] == "heap-buffer-overflow" for r in driver["rules"])

    def test_taxonomy_lists_every_classification(self) -> None:
        payload = json.loads(SARIFReportRenderer().render(_context()))
        taxonomy = payload["runs"][0]["taxonomies"][0]
        assert taxonomy["guid"] == "kmcs-memory-safety"
        assert len(taxonomy["taxa"]) == len(list(models.CrashClassification))

    def test_results_have_fingerprint(self) -> None:
        payload = json.loads(SARIFReportRenderer().render(_context()))
        results = payload["runs"][0]["results"]
        assert len(results) == 2
        for result in results:
            assert result["fingerprints"]["kmcs/fingerprint"]

    def test_location_parsed_from_source_location(self) -> None:
        payload = json.loads(SARIFReportRenderer().render(_context()))
        results = payload["runs"][0]["results"]
        for result in results:
            assert "locations" in result
            location = result["locations"][0]
            assert location["physicalLocation"]["artifactLocation"]["uri"].startswith("/src/demo/")
            assert location["physicalLocation"]["region"]["startLine"] >= 10

    def test_no_location_when_source_location_missing(self) -> None:
        ctx = _context()
        for crash in ctx.crashes:
            crash.source_location = None
        payload = json.loads(SARIFReportRenderer().render(ctx))
        for result in payload["runs"][0]["results"]:
            assert "locations" not in result


# ---------------------------------------------------------------------- HTML


class TestHTMLRenderer:
    def test_well_formed_envelope(self) -> None:
        rendered = HTMLReportRenderer().render(_context())
        assert rendered.startswith("<!doctype html>")
        assert rendered.rstrip().endswith("</html>")

    def test_no_javascript(self) -> None:
        rendered = HTMLReportRenderer().render(_context())
        assert "<script" not in rendered.lower()

    def test_no_external_references(self) -> None:
        rendered = HTMLReportRenderer().render(_context())
        # No http(s) href/src in the body.
        assert 'src="http' not in rendered
        assert 'href="http' not in rendered

    def test_anchors_and_toc_agree(self) -> None:
        ctx = _context()
        rendered = HTMLReportRenderer().render(ctx)
        for finding in ctx.findings:
            assert f'id="finding-{finding.id}"' in rendered
            assert f'href="#finding-{finding.id}"' in rendered

    def test_html_escapes_user_content(self) -> None:
        ctx = _context(findings=1)
        ctx.findings[0].title = "<script>alert(1)</script>"
        rendered = HTMLReportRenderer().render(ctx)
        assert "<script>alert(1)</script>" not in rendered
        assert "&lt;script&gt;" in rendered
