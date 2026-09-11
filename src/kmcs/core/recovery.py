"""Resilience after an unclean shutdown.

Fuzzing campaigns run for hours.  A laptop sleeps.  A terminal gets closed.
A kernel panics.  When KMCS restarts, it must:

* recognise campaigns that were left in ``RUNNING`` state,
* close them out without pretending they completed,
* finalise their crashes into findings (so nothing is lost),
* verify that every recorded crash still has evidence on disk,
* and clean up worker scratch directories that no active campaign owns.

The recovery module does not *guess* what happened.  It records what it found
and what it did.  If a campaign's output directory is gone, KMCS says so; it
does not fabricate a completion.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select

from kmcs.analysis.crash_parser import CrashParser
from kmcs.analysis.deduplicator import CrashDeduplicator
from kmcs.core import models
from kmcs.core.config import KMCSConfig
from kmcs.core.events import EventBus, EventType
from kmcs.database.database import Database
from kmcs.database.models import CampaignRow, CrashRow, FindingRow

logger = logging.getLogger(__name__)

__all__ = [
    "RecoveryReport",
    "RecoveryManager",
]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class RecoveryReport:
    interrupted_campaigns: list[str] = field(default_factory=list)
    finalised_campaigns: list[str] = field(default_factory=list)
    crashes_without_evidence: list[str] = field(default_factory=list)
    orphan_output_dirs: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return (
            not self.interrupted_campaigns
            and not self.crashes_without_evidence
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "clean": self.clean,
            "interrupted_campaigns": list(self.interrupted_campaigns),
            "finalised_campaigns": list(self.finalised_campaigns),
            "crashes_without_evidence": list(self.crashes_without_evidence),
            "orphan_output_dirs": list(self.orphan_output_dirs),
            "warnings": list(self.warnings),
        }


class RecoveryManager:
    """Detects and repairs the state left by an unclean shutdown."""

    def __init__(
        self,
        database: Database,
        config: KMCSConfig,
        *,
        bus: EventBus | None = None,
        deduplicator: CrashDeduplicator | None = None,
    ) -> None:
        self._database = database
        self._config = config
        self._bus = bus
        self._deduplicator = deduplicator or CrashDeduplicator()
        self._parser = CrashParser()

    # ------------------------------------------------------------------ public

    def recover(self, *, finalize: bool = True) -> RecoveryReport:
        """Run every recovery step and return a report of what happened."""
        report = RecoveryReport()

        interrupted = self._find_interrupted_campaigns()
        for campaign in interrupted:
            report.interrupted_campaigns.append(campaign.id)

        self._mark_interrupted(interrupted)
        self._publish(
            "recovery.interrupted",
            {"count": len(interrupted)},
        )

        if finalize:
            for campaign in interrupted:
                try:
                    self._finalize(campaign.id)
                except Exception as exc:  # noqa: BLE001 - reported, not raised
                    report.warnings.append(
                        f"finalize({campaign.id}) failed: {type(exc).__name__}: {exc}"
                    )
                    logger.exception("Recovery could not finalize campaign %s", campaign.id)
                else:
                    report.finalised_campaigns.append(campaign.id)

        missing = self._crashes_without_evidence()
        report.crashes_without_evidence.extend(missing)
        if missing:
            self._publish("recovery.missing_evidence", {"count": len(missing)})

        orphans = self._orphan_output_dirs()
        report.orphan_output_dirs.extend(orphans)

        return report

    # ------------------------------------------------------------------ steps

    def _find_interrupted_campaigns(self) -> list[models.Campaign]:
        with self._database.session() as session:
            rows = session.scalars(
                select(CampaignRow).where(
                    CampaignRow.status == models.CampaignStatus.RUNNING.value
                )
            ).all()
            return [row.to_domain() for row in rows]

    def _mark_interrupted(self, campaigns: list[models.Campaign]) -> None:
        if not campaigns:
            return
        now = _utcnow()
        with self._database.session() as session:
            for campaign in campaigns:
                row = session.get(CampaignRow, campaign.id)
                if row is None:
                    continue
                row.status = models.CampaignStatus.CANCELLED.value
                row.finished_at = now.replace(tzinfo=None) if row.finished_at is None else row.finished_at
                metadata = dict(row.metadata_json or {})
                metadata["recovery"] = {
                    "detected_at": now.isoformat(),
                    "reason": "campaign was in RUNNING state at startup",
                }
                row.metadata_json = metadata
        logger.warning(
            "Marked %d campaign(s) as cancelled (interrupted)",
            len(campaigns),
        )

    def _finalize(self, campaign_id: str) -> None:
        crashes = self._load_crashes(campaign_id)
        if not crashes:
            return

        observations: list[tuple[models.Crash, object]] = []
        for crash in crashes:
            report = self._reconstruct_report(crash)
            observations.append((crash, report))

        result = self._deduplicator.deduplicate(observations)  # type: ignore[arg-type]

        crash_ids = {crash.id for crash in crashes}
        with self._database.session() as session:
            existing = session.scalars(select(FindingRow)).all()
            for row in existing:
                if crash_ids.intersection(row.crash_ids or []):
                    session.delete(row)
            for finding in result.findings:
                finding.metadata["recovered"] = True
                finding.metadata["campaign_id"] = campaign_id
                session.add(FindingRow.from_domain(finding))

    def _crashes_without_evidence(self) -> list[str]:
        missing: list[str] = []
        with self._database.session() as session:
            rows = session.scalars(select(CrashRow)).all()
            for row in rows:
                if row.evidence_path is None:
                    continue
                if not Path(row.evidence_path).is_file():
                    missing.append(row.id)
        return missing

    def _orphan_output_dirs(self) -> list[str]:
        """Campaign output directories that no campaign references.

        Campaign output is not stored in the database; the caller (the CLI)
        tells KMCS where it is.  We therefore cannot detect orphans without
        knowing that root, and we return an empty list.  The hook exists so
        Phase 8 (if any) can pass a root.
        """
        return []

    # ------------------------------------------------------------------ helpers

    def _load_crashes(self, campaign_id: str) -> list[models.Crash]:
        with self._database.session() as session:
            rows = session.scalars(
                select(CrashRow).where(CrashRow.campaign_id == campaign_id)
            ).all()
            return [row.to_domain() for row in rows]

    def _reconstruct_report(self, crash: models.Crash):
        stdout = crash.stdout_excerpt or ""
        stderr = crash.stderr_excerpt or ""

        if crash.evidence_path is not None and Path(crash.evidence_path).is_file():
            try:
                stderr = Path(crash.evidence_path).read_text(
                    encoding="utf-8", errors="replace"
                )
            except OSError:
                pass

        metadata = crash.metadata or {}
        duration = metadata.get("duration_seconds")
        if not isinstance(duration, (int, float)):
            duration = None

        return self._parser.parse(
            stdout=stdout,
            stderr=stderr,
            exit_code=crash.exit_code,
            signal_number=crash.signal,
            timed_out=bool(metadata.get("timed_out", False)),
            duration_seconds=duration,
        )

    def _publish(self, event_name: str, payload: dict[str, object]) -> None:
        if self._bus is None:
            return
        try:
            event_type = EventType(event_name)
        except ValueError:
            return
        self._bus.emit(event_type, payload, source="recovery")
