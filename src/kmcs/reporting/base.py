"""Report data model and renderer interface.

A :class:`ReportContext` is *everything* a renderer might need, pre-loaded by
the generator from the database.  Renderers treat it as read-only.  This
decoupling means:

* renderers never touch the database,
* a renderer can be tested with a hand-built context,
* and the same context feeds every format.

The :class:`ReportSummary` is computed once and shared, so every format agrees
on the numbers it reports.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from kmcs import __version__
from kmcs.core import models

__all__ = [
    "ReportError",
    "ReportFormat",
    "ReportSection",
    "ReportSummary",
    "ReportContext",
    "RenderedReport",
    "ReportRenderer",
]


class ReportError(Exception):
    """Raised by a renderer when the context is missing required data."""

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = dict(details or {})


class ReportFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    CSV = "csv"
    SARIF = "sarif"
    HTML = "html"

    @property
    def default_extension(self) -> str:
        return {
            ReportFormat.JSON: ".json",
            ReportFormat.MARKDOWN: ".md",
            ReportFormat.CSV: ".csv",
            ReportFormat.SARIF: ".sarif",
            ReportFormat.HTML: ".html",
        }[self]

    @property
    def media_type(self) -> str:
        return {
            ReportFormat.JSON: "application/json",
            ReportFormat.MARKDOWN: "text/markdown; charset=utf-8",
            ReportFormat.CSV: "text/csv; charset=utf-8",
            ReportFormat.SARIF: "application/sarif+json",
            ReportFormat.HTML: "text/html; charset=utf-8",
        }[self]

    @classmethod
    def parse(cls, value: str) -> "ReportFormat":
        """Parse ``value`` as a format, accepting a few aliases."""
        normalised = value.strip().lower()
        aliases = {
            "md": cls.MARKDOWN,
            "markdown": cls.MARKDOWN,
            "json": cls.JSON,
            "csv": cls.CSV,
            "sarif": cls.SARIF,
            "html": cls.HTML,
        }
        try:
            return aliases[normalised]
        except KeyError as exc:
            raise ReportError(
                f"Unknown report format: {value!r}",
                details={"known": sorted({k for k in aliases})},
            ) from exc


# Severity ordering shared by every renderer that groups or sorts by severity.
SEVERITY_ORDER: tuple[models.Severity, ...] = (
    models.Severity.CRITICAL,
    models.Severity.HIGH,
    models.Severity.MEDIUM,
    models.Severity.LOW,
    models.Severity.INFO,
    models.Severity.UNKNOWN,
)

__all__ += ["SEVERITY_ORDER"]


@dataclass(frozen=True, slots=True)
class ReportSection:
    """Which sections a report should include.  Defaults to everything."""

    include_findings: bool = True
    include_crashes: bool = True
    include_campaigns: bool = True
    include_targets: bool = True
    include_corpora: bool = True
    include_telemetry: bool = True

    @classmethod
    def findings_only(cls) -> "ReportSection":
        return cls(
            include_findings=True,
            include_crashes=True,
            include_campaigns=False,
            include_targets=False,
            include_corpora=False,
            include_telemetry=False,
        )


@dataclass(frozen=True, slots=True)
class ReportSummary:
    """Aggregates computed once and reused across every format."""

    findings: int
    crashes: int
    campaigns: int
    targets: int
    corpora: int
    findings_by_severity: dict[str, int]
    findings_by_classification: dict[str, int]
    crashes_by_classification: dict[str, int]

    @classmethod
    def from_context(cls, context: "ReportContext") -> "ReportSummary":
        findings_by_severity: dict[str, int] = {}
        for finding in context.findings:
            key = finding.severity.value
            findings_by_severity[key] = findings_by_severity.get(key, 0) + 1

        findings_by_classification: dict[str, int] = {}
        for finding in context.findings:
            key = finding.classification.value
            findings_by_classification[key] = findings_by_classification.get(key, 0) + 1

        crashes_by_classification: dict[str, int] = {}
        for crash in context.crashes:
            key = crash.classification.value
            crashes_by_classification[key] = crashes_by_classification.get(key, 0) + 1

        return cls(
            findings=len(context.findings),
            crashes=len(context.crashes),
            campaigns=len(context.campaigns),
            targets=len(context.targets),
            corpora=len(context.corpora),
            findings_by_severity=findings_by_severity,
            findings_by_classification=findings_by_classification,
            crashes_by_classification=crashes_by_classification,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": self.findings,
            "crashes": self.crashes,
            "campaigns": self.campaigns,
            "targets": self.targets,
            "corpora": self.corpora,
            "findings_by_severity": dict(self.findings_by_severity),
            "findings_by_classification": dict(self.findings_by_classification),
            "crashes_by_classification": dict(self.crashes_by_classification),
        }


@dataclass(slots=True)
class ReportContext:
    """Everything a renderer needs.  Treated as read-only by renderers."""

    report_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    generated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    kmcs_version: str = __version__
    title: str = "KMCS security report"

    findings: list[models.Finding] = field(default_factory=list)
    crashes: list[models.Crash] = field(default_factory=list)
    campaigns: list[models.Campaign] = field(default_factory=list)
    targets: list[models.Target] = field(default_factory=list)
    corpora: list[models.Corpus] = field(default_factory=list)

    section: ReportSection = field(default_factory=ReportSection)

    campaign_id: str | None = None
    campaign: models.Campaign | None = None

    telemetry: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # Computed lazily and cached.
    _summary: ReportSummary | None = field(default=None, init=False, repr=False)

    # ------------------------------------------------------------------ views

    @property
    def summary(self) -> ReportSummary:
        if self._summary is None:
            self._summary = ReportSummary.from_context(self)
        return self._summary

    def findings_sorted(self) -> list[models.Finding]:
        """Findings in report order: severity first, then title."""
        rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        return sorted(
            self.findings,
            key=lambda f: (rank.get(f.severity, 99), f.title.lower(), f.id),
        )

    def crashes_for_finding(self, finding: models.Finding) -> list[models.Crash]:
        index = {crash.id: crash for crash in self.crashes}
        return [index[cid] for cid in finding.crash_ids if cid in index]

    def target_by_id(self, target_id: str | None) -> models.Target | None:
        if target_id is None:
            return None
        for target in self.targets:
            if target.id == target_id:
                return target
        return None


@dataclass(frozen=True, slots=True)
class RenderedReport:
    """A rendered report ready to be returned or written to disk."""

    format: ReportFormat
    content: str
    filename: str

    @property
    def size_bytes(self) -> int:
        return len(self.content.encode("utf-8"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format.value,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
        }


class ReportRenderer(ABC):
    """Base class for every report renderer."""

    format: ReportFormat

    @abstractmethod
    def render(self, context: ReportContext) -> str:
        """Return the fully rendered report as a string."""

    # ------------------------------------------------------------------ helpers

    def filename_for(self, context: ReportContext) -> str:
        """Return a deterministic, timestamped filename."""
        stamp = context.generated_at.strftime("%Y%m%dT%H%M%SZ")
        short_id = context.report_id[:8]
        return f"kmcs-report-{stamp}-{short_id}{self.format.default_extension}"

    def render_report(self, context: ReportContext) -> RenderedReport:
        return RenderedReport(
            format=self.format,
            content=self.render(context),
            filename=self.filename_for(context),
        )
