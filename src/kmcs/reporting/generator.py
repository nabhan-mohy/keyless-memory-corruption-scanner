"""Build a :class:`ReportContext` from the database, then render it.

The generator is the only reporting component that touches the database.  It
produces a deterministic, ordered context — the same data always renders the
same bytes, which matters for diffing reports across runs and for CI checks
that compare expected output.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path

from sqlalchemy import select

from kmcs.core import models
from kmcs.core.config import KMCSConfig
from kmcs.database.database import Database
from kmcs.database.models import (
    CampaignRow,
    CorpusRow,
    CrashRow,
    FindingRow,
    TargetRow,
)
from kmcs.reporting.base import (
    RenderedReport,
    ReportContext,
    ReportError,
    ReportFormat,
    ReportRenderer,
    ReportSection,
)
from kmcs.reporting.csv_report import CSVReportRenderer
from kmcs.reporting.html import HTMLReportRenderer
from kmcs.reporting.json_report import JSONReportRenderer
from kmcs.reporting.markdown import MarkdownReportRenderer
from kmcs.reporting.sarif import SARIFReportRenderer

logger = logging.getLogger(__name__)

__all__ = ["ReportGenerator"]


_RENDERERS: dict[ReportFormat, type[ReportRenderer]] = {
    ReportFormat.JSON: JSONReportRenderer,
    ReportFormat.MARKDOWN: MarkdownReportRenderer,
    ReportFormat.CSV: CSVReportRenderer,
    ReportFormat.SARIF: SARIFReportRenderer,
    ReportFormat.HTML: HTMLReportRenderer,
}


class ReportGenerator:
    """Loads contexts from the database and renders them in any format."""

    def __init__(self, database: Database, config: KMCSConfig) -> None:
        self._database = database
        self._config = config

    # ------------------------------------------------------------------ render

    def generate(
        self,
        format: ReportFormat | str,
        *,
        output_dir: Path | None = None,
        filename: str | None = None,
        title: str | None = None,
        campaign_id: str | None = None,
        finding_ids: Iterable[str] | None = None,
        section: ReportSection | None = None,
        metadata: dict[str, object] | None = None,
    ) -> tuple[RenderedReport, Path | None]:
        """Build the context, render, and optionally write to disk.

        Returns ``(rendered, written_path)``.  ``written_path`` is ``None``
        when ``output_dir`` is ``None``.
        """
        if isinstance(format, str):
            format = ReportFormat.parse(format)

        context = self.build_context(
            title=title,
            campaign_id=campaign_id,
            finding_ids=finding_ids,
            section=section,
            metadata=metadata,
        )

        renderer_cls = _RENDERERS.get(format)
        if renderer_cls is None:
            raise ReportError(
                "No renderer is registered for this format",
                details={"format": format.value},
            )

        rendered = renderer_cls().render_report(context)
        if filename is not None:
            rendered = RenderedReport(
                format=rendered.format,
                content=rendered.content,
                filename=filename,
            )

        written: Path | None = None
        if output_dir is not None:
            target_dir = Path(output_dir)
            target_dir.mkdir(parents=True, exist_ok=True)
            written = target_dir / rendered.filename
            written.write_text(rendered.content, encoding="utf-8")
            logger.info("Wrote %s report to %s", format.value, written)

        return rendered, written

    # ------------------------------------------------------------------ context

    def build_context(
        self,
        *,
        title: str | None = None,
        campaign_id: str | None = None,
        finding_ids: Iterable[str] | None = None,
        section: ReportSection | None = None,
        metadata: dict[str, object] | None = None,
    ) -> ReportContext:
        section = section or ReportSection()
        context = ReportContext(
            title=title or self._default_title(campaign_id),
            section=section,
            campaign_id=campaign_id,
            metadata=dict(metadata or {}),
        )

        # --- campaign -----------------------------------------------------
        campaign: models.Campaign | None = None
        if campaign_id is not None:
            campaign = self._load_campaign(campaign_id)
            if campaign is None:
                raise ReportError(
                    "Campaign not found", details={"campaign_id": campaign_id}
                )
            context.campaign = campaign
            context.campaigns = [campaign]
        elif section.include_campaigns:
            context.campaigns = self._load_campaigns()

        # --- findings -----------------------------------------------------
        if section.include_findings:
            if finding_ids is not None:
                context.findings = self._load_findings_by_ids(list(finding_ids))
            elif campaign_id is not None:
                context.findings = self._load_findings_for_campaign(campaign_id)
            else:
                context.findings = self._load_findings()

        # --- crashes ------------------------------------------------------
        if section.include_crashes:
            if campaign_id is not None:
                context.crashes = self._load_crashes_for_campaign(campaign_id)
            elif context.findings:
                crash_ids = sorted(
                    {cid for finding in context.findings for cid in finding.crash_ids}
                )
                context.crashes = self._load_crashes_by_ids(crash_ids)
            else:
                context.crashes = self._load_crashes()

        # --- targets / corpora -------------------------------------------
        if section.include_targets:
            context.targets = self._load_targets()
        if section.include_corpora:
            context.corpora = self._load_corpora()

        # --- telemetry ---------------------------------------------------
        if (
            section.include_telemetry
            and campaign is not None
            and isinstance(campaign.metadata.get("telemetry"), dict)
        ):
            context.telemetry = dict(campaign.metadata["telemetry"])

        return context

    # ------------------------------------------------------------------ loaders

    @staticmethod
    def _default_title(campaign_id: str | None) -> str:
        if campaign_id:
            return f"KMCS security report — campaign {campaign_id}"
        return "KMCS security report"

    def _load_campaign(self, campaign_id: str) -> models.Campaign | None:
        with self._database.session() as session:
            row = session.get(CampaignRow, campaign_id)
            return None if row is None else row.to_domain()

    def _load_campaigns(self) -> list[models.Campaign]:
        with self._database.session() as session:
            rows = session.scalars(
                select(CampaignRow).order_by(CampaignRow.created_at.desc())
            ).all()
            return [row.to_domain() for row in rows]

    def _load_findings(self) -> list[models.Finding]:
        with self._database.session() as session:
            rows = session.scalars(
                select(FindingRow).order_by(FindingRow.created_at.desc())
            ).all()
            return [row.to_domain() for row in rows]

    def _load_findings_by_ids(self, finding_ids: list[str]) -> list[models.Finding]:
        if not finding_ids:
            return []
        with self._database.session() as session:
            rows = session.scalars(
                select(FindingRow).where(FindingRow.id.in_(finding_ids))
            ).all()
            by_id = {row.id: row.to_domain() for row in rows}
        return [by_id[fid] for fid in finding_ids if fid in by_id]

    def _load_findings_for_campaign(self, campaign_id: str) -> list[models.Finding]:
        with self._database.session() as session:
            crash_rows = session.scalars(
                select(CrashRow).where(CrashRow.campaign_id == campaign_id)
            ).all()
            crash_ids = {row.id for row in crash_rows}

            findings = session.scalars(
                select(FindingRow).order_by(FindingRow.created_at.desc())
            ).all()
            return [
                row.to_domain()
                for row in findings
                if crash_ids.intersection(row.crash_ids or [])
            ]

    def _load_crashes_for_campaign(self, campaign_id: str) -> list[models.Crash]:
        with self._database.session() as session:
            rows = session.scalars(
                select(CrashRow)
                .where(CrashRow.campaign_id == campaign_id)
                .order_by(CrashRow.created_at)
            ).all()
            return [row.to_domain() for row in rows]

    def _load_crashes_by_ids(self, crash_ids: list[str]) -> list[models.Crash]:
        if not crash_ids:
            return []
        with self._database.session() as session:
            rows = session.scalars(
                select(CrashRow)
                .where(CrashRow.id.in_(crash_ids))
                .order_by(CrashRow.created_at)
            ).all()
            return [row.to_domain() for row in rows]

    def _load_crashes(self) -> list[models.Crash]:
        with self._database.session() as session:
            rows = session.scalars(
                select(CrashRow).order_by(CrashRow.created_at.desc())
            ).all()
            return [row.to_domain() for row in rows]

    def _load_targets(self) -> list[models.Target]:
        with self._database.session() as session:
            rows = session.scalars(
                select(TargetRow).order_by(TargetRow.name)
            ).all()
            return [row.to_domain() for row in rows]

    def _load_corpora(self) -> list[models.Corpus]:
        with self._database.session() as session:
            rows = session.scalars(
                select(CorpusRow).order_by(CorpusRow.name)
            ).all()
            return [row.to_domain() for row in rows]
