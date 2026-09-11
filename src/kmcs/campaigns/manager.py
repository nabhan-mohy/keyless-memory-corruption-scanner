"""Campaign CRUD and orchestration.

The manager is the only component that:

* creates, updates, and removes campaign records,
* builds a :class:`CampaignScheduler` from a stored campaign,
* finalises the campaign when the scheduler returns.

Finalisation is where the campaign's crashes become findings:

1. every persisted crash for the campaign is loaded,
2. their reports are **reconstructed** from the preserved evidence files
   (so the deduplicator sees structured data, not just rows),
3. the deduplicator builds findings,
4. findings and their crash links are written to the database.

The reports are re-parsed from evidence files rather than re-run, which
guarantees that deduplication never launches a target — it is purely a
post-processing step over preserved bytes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select

from kmcs.analysis.crash_detector import CrashDetector
from kmcs.analysis.crash_parser import CrashParser, CrashReport
from kmcs.analysis.deduplicator import CrashDeduplicator, DeduplicationResult
from kmcs.campaigns.scheduler import (
    CampaignScheduler,
    SchedulerConfig,
    SchedulerResult,
)
from kmcs.campaigns.telemetry import TelemetryAggregator
from kmcs.core import models
from kmcs.core.config import KMCSConfig
from kmcs.core.events import EventBus, EventType
from kmcs.core.exceptions import KMCSException
from kmcs.database.database import Database
from kmcs.database.models import (
    CampaignRow,
    CrashRow,
    FindingRow,
)

logger = logging.getLogger(__name__)

__all__ = [
    "CampaignError",
    "CampaignRunResult",
    "CampaignManager",
]


class CampaignError(KMCSException):
    exit_code = 62


@dataclass(slots=True)
class CampaignRunResult:
    campaign: models.Campaign
    scheduler_result: SchedulerResult
    deduplication: DeduplicationResult

    def to_dict(self) -> dict[str, object]:
        return {
            "campaign_id": self.campaign.id,
            "campaign_status": self.campaign.status.value,
            "scheduler": self.scheduler_result.to_dict(),
            "deduplication": self.deduplication.to_dict(),
        }


class CampaignManager:
    """CRUD and orchestration for campaigns."""

    def __init__(
        self,
        database: Database,
        config: KMCSConfig,
        *,
        detector: CrashDetector | None = None,
        deduplicator: CrashDeduplicator | None = None,
        bus: EventBus | None = None,
    ) -> None:
        self._database = database
        self._config = config
        self._detector = detector or CrashDetector(database=database)
        self._deduplicator = deduplicator or CrashDeduplicator()
        self._bus = bus or EventBus()
        self._parser = CrashParser()

    # ------------------------------------------------------------------ CRUD

    def get(self, campaign_id: str) -> models.Campaign | None:
        with self._database.session() as session:
            row = session.get(CampaignRow, campaign_id)
            return None if row is None else row.to_domain()

    def get_by_name(self, name: str) -> models.Campaign | None:
        cleaned = name.strip()
        if not cleaned:
            return None
        with self._database.session() as session:
            row = session.scalar(select(CampaignRow).where(CampaignRow.name == cleaned))
            return None if row is None else row.to_domain()

    def list(self) -> list[models.Campaign]:
        with self._database.session() as session:
            rows = session.scalars(
                select(CampaignRow).order_by(CampaignRow.created_at.desc())
            ).all()
            return [row.to_domain() for row in rows]

    def add(self, campaign: models.Campaign) -> models.Campaign:
        if self.get_by_name(campaign.name) is not None:
            raise CampaignError(
                "A campaign with this name already exists",
                details={"name": campaign.name},
            )
        with self._database.session() as session:
            session.add(CampaignRow.from_domain(campaign))
        logger.info("Created campaign %s (%s)", campaign.name, campaign.id)
        return campaign

    def update(self, campaign: models.Campaign) -> models.Campaign:
        with self._database.session() as session:
            row = session.get(CampaignRow, campaign.id)
            if row is None:
                raise CampaignError(
                    "Campaign does not exist", details={"campaign_id": campaign.id}
                )
            session.merge(CampaignRow.from_domain(campaign))
        return campaign

    def remove(self, campaign_id: str) -> bool:
        with self._database.session() as session:
            row = session.get(CampaignRow, campaign_id)
            if row is None:
                return False
            session.delete(row)
        return True

    # ------------------------------------------------------------------ execute

    def run(
        self,
        campaign_id: str,
        *,
        target_binary: Path,
        corpus_dir: Path,
        output_root: Path,
        environment: dict[str, str] | None = None,
        target_args: list[str] | None = None,
        extra_fuzzer_args: list[str] | None = None,
        clear_output_root: bool = False,
        poll_interval_seconds: float = 1.0,
    ) -> CampaignRunResult:
        """Run a stored campaign and finalise it."""
        campaign = self.get(campaign_id)
        if campaign is None:
            raise CampaignError(
                "Campaign does not exist", details={"campaign_id": campaign_id}
            )

        campaign.status = models.CampaignStatus.RUNNING
        campaign.started_at = models.utcnow()
        campaign.touch()
        self.update(campaign)

        scheduler_config = SchedulerConfig(
            campaign_id=campaign.id,
            target_id=campaign.target_id,
            target_binary=Path(target_binary),
            corpus_dir=Path(corpus_dir),
            output_root=Path(output_root),
            fuzzer=campaign.fuzzer,
            sanitizers=list(campaign.sanitizers),
            workers=campaign.workers,
            duration_seconds=campaign.duration_seconds,
            environment=dict(environment or {}),
            target_args=list(target_args or []),
            extra_fuzzer_args=list(extra_fuzzer_args or []),
            clear_output_root=clear_output_root,
            poll_interval_seconds=poll_interval_seconds,
        )

        scheduler = CampaignScheduler(
            scheduler_config,
            detector=self._detector,
            database=self._database,
            bus=self._bus,
            telemetry=TelemetryAggregator(campaign_id=campaign.id),
        )
        scheduler.prepare()
        scheduler_result = scheduler.run()

        # Reload, in case workers wrote to the campaign row.
        campaign = self.get(campaign_id)
        assert campaign is not None

        campaign.finished_at = models.utcnow()
        campaign.status = (
            models.CampaignStatus.CANCELLED
            if scheduler_result.cancelled
            else models.CampaignStatus.COMPLETED
        )
        campaign.touch()
        self.update(campaign)

        deduplication = self.finalize(campaign.id)

        return CampaignRunResult(
            campaign=campaign,
            scheduler_result=scheduler_result,
            deduplication=deduplication,
        )

    # ------------------------------------------------------------------ finalize

    def finalize(self, campaign_id: str) -> DeduplicationResult:
        """Group every crash in the campaign and persist findings."""
        crashes = self._load_crashes(campaign_id)

        observations: list[tuple[models.Crash, CrashReport]] = []
        for crash in crashes:
            report = self._reconstruct_report(crash)
            observations.append((crash, report))

        result = self._deduplicator.deduplicate(observations)

        # Wipe any previous findings for this campaign's crashes (idempotent
        # re-run of finalize).
        crash_ids = {crash.id for crash in crashes}
        with self._database.session() as session:
            if crash_ids:
                existing = session.scalars(select(FindingRow)).all()
                for row in existing:
                    if crash_ids.intersection(row.crash_ids or []):
                        session.delete(row)
            # Link findings to the campaign.
            for finding in result.findings:
                finding.metadata["campaign_id"] = campaign_id
                session.add(FindingRow.from_domain(finding))

        logger.info(
            "Campaign %s finalised: %d crashes, %d groups, %d findings",
            campaign_id,
            result.total_crashes,
            result.total_groups,
            len(result.findings),
        )

        self._bus.emit(
            EventType.FINDING_CREATED,
            {
                "campaign_id": campaign_id,
                "finding_count": len(result.findings),
            },
            source="campaign-manager",
        )
        return result

    # ------------------------------------------------------------------ helpers

    def _load_crashes(self, campaign_id: str) -> list[models.Crash]:
        with self._database.session() as session:
            rows = session.scalars(
                select(CrashRow).where(CrashRow.campaign_id == campaign_id)
            ).all()
            return [row.to_domain() for row in rows]

    def _reconstruct_report(self, crash: models.Crash) -> CrashReport:
        """Rebuild a :class:`CrashReport` from a persisted crash row.

        Evidence files written by the detector carry the exact stdout and
        stderr the target produced; we re-parse them so the deduplicator sees
        the same structured data the detector did.  When an evidence file is
        missing, we fall back to the stored excerpts.
        """
        stdout = ""
        stderr = ""
        if crash.evidence_path is not None:
            try:
                stderr = crash.evidence_path.read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError as exc:
                logger.warning(
                    "Could not read evidence for crash %s: %s", crash.id, exc
                )

        stdout_meta = crash.metadata.get("stdout_path")
        if isinstance(stdout_meta, str):
            try:
                stdout = Path(stdout_meta).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                stdout = crash.stdout_excerpt or ""

        if not stdout:
            stdout = crash.stdout_excerpt or ""
        if not stderr:
            stderr = crash.stderr_excerpt or ""

        duration = crash.metadata.get("duration_seconds")
        if not isinstance(duration, (int, float)):
            duration = None

        return self._parser.parse(
            stdout=stdout,
            stderr=stderr,
            exit_code=crash.exit_code,
            signal_number=crash.signal,
            timed_out=bool(crash.metadata.get("timed_out", False)),
            duration_seconds=duration,
        )
