"""Generator: database loading, format dispatch, and file writing."""

from __future__ import annotations

from pathlib import Path

import pytest

from kmcs.core import models
from kmcs.core.config import KMCSConfig
from kmcs.database.database import Database, build_sqlite_url
from kmcs.database.models import (
    CampaignRow,
    CrashRow,
    FindingRow,
    TargetRow,
)
from kmcs.reporting import ReportError, ReportFormat, ReportGenerator
from kmcs.reporting.base import ReportSection


@pytest.fixture()
def generator(tmp_path: Path):
    db = Database(build_sqlite_url(tmp_path / "kmcs.sqlite3"))
    db.initialize()
    config = KMCSConfig(base_dir=tmp_path / "kmcs")
    config.ensure_directories()

    target = models.Target(name="libdemo")
    campaign = models.Campaign(name="c1", target_id=target.id)
    crash = models.Crash(
        campaign_id=campaign.id,
        target_id=target.id,
        description="heap overflow",
        signal=11,
        classification=models.CrashClassification.HEAP_BUFFER_OVERFLOW,
        severity=models.Severity.HIGH,
        fingerprint="fp-1",
        source_location="/src/demo/v.c:10:5",
    )
    finding = models.Finding(
        title="Heap overflow in parse_chunk",
        fingerprint="fp-1",
        classification=models.CrashClassification.HEAP_BUFFER_OVERFLOW,
        severity=models.Severity.HIGH,
        target_id=target.id,
        crash_ids=[crash.id],
    )

    with db.session() as session:
        session.add(TargetRow.from_domain(target))
        session.flush()                                  # target first (FK)
        session.add(CampaignRow.from_domain(campaign))
        session.flush()                                  # then campaign
        session.add(CrashRow.from_domain(crash))
        session.add(FindingRow.from_domain(finding))

    try:
        yield ReportGenerator(db, config), {
            "target": target,
            "campaign": campaign,
            "crash": crash,
            "finding": finding,
        }
    finally:
        db.dispose()


class TestContextBuilding:
    def test_default_context_loads_everything(self, generator) -> None:
        gen, ids = generator
        ctx = gen.build_context()
        assert len(ctx.findings) == 1
        assert len(ctx.crashes) == 1
        assert len(ctx.campaigns) == 1
        assert len(ctx.targets) == 1

    def test_finding_filter(self, generator) -> None:
        gen, ids = generator
        ctx = gen.build_context(finding_ids=[ids["finding"].id])
        assert len(ctx.findings) == 1

    def test_campaign_filter(self, generator) -> None:
        gen, ids = generator
        ctx = gen.build_context(campaign_id=ids["campaign"].id)
        assert ctx.campaign is not None
        assert len(ctx.crashes) == 1

    def test_missing_campaign_raises(self, generator) -> None:
        gen, _ = generator
        with pytest.raises(ReportError):
            gen.build_context(campaign_id="does-not-exist")

    def test_findings_only_section(self, generator) -> None:
        gen, _ = generator
        ctx = gen.build_context(section=ReportSection.findings_only())
        assert ctx.targets == []
        assert ctx.campaigns == []


class TestRendering:
    def test_default_writes_to_disk(self, generator, tmp_path: Path) -> None:
        gen, _ = generator
        rendered, written = gen.generate(
            ReportFormat.JSON, output_dir=tmp_path / "reports"
        )
        assert written is not None
        assert written.is_file()
        assert written.read_text() == rendered.content

    def test_no_output_dir_returns_none(self, generator) -> None:
        gen, _ = generator
        _, written = gen.generate(ReportFormat.MARKDOWN)
        assert written is None

    def test_custom_filename_overrides(self, generator, tmp_path: Path) -> None:
        gen, _ = generator
        _, written = gen.generate(
            ReportFormat.SARIF,
            output_dir=tmp_path / "reports",
            filename="custom.sarif",
        )
        assert written is not None
        assert written.name == "custom.sarif"

    def test_accepts_string_format(self, generator) -> None:
        gen, _ = generator
        rendered, _ = gen.generate("markdown")
        assert rendered.format is ReportFormat.MARKDOWN

    def test_unknown_format_is_rejected(self, generator) -> None:
        gen, _ = generator
        with pytest.raises(ReportError):
            gen.generate("pdf")
