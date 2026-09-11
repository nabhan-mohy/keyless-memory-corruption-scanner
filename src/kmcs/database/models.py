"""SQLAlchemy table definitions and domain <-> row conversion.

Column values are stored in their primitive form (strings, integers, JSON) so the
database stays inspectable with the ``sqlite3`` CLI.  Enum values are stored by
value, paths as text, and datetimes as naive UTC — SQLite has no native
timezone-aware type, and re-attaching UTC on read avoids subtle comparison bugs.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, MetaData, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from kmcs.core import models as domain

__all__ = [
    "Base",
    "TargetRow",
    "CorpusRow",
    "CampaignRow",
    "CrashRow",
    "FindingRow",
    "ReportRow",
]

_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Declarative base for every KMCS table."""

    metadata = MetaData(naming_convention=_NAMING_CONVENTION)


# ---------------------------------------------------------------------- helpers


def _to_storage_dt(value: datetime | None) -> datetime | None:
    """Convert to naive UTC for storage."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _from_storage_dt(value: datetime | None) -> datetime | None:
    """Re-attach UTC to a datetime read back from SQLite."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _path_to_text(value: Path | None) -> str | None:
    return None if value is None else str(value)


def _text_to_path(value: str | None) -> Path | None:
    return None if value is None else Path(value)


def _enum_values(items: list[Enum]) -> list[str]:
    return [str(item.value) for item in items]


# ---------------------------------------------------------------------- targets


class TargetRow(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    source_dir: Mapped[str | None] = mapped_column(Text)
    build_dir: Mapped[str | None] = mapped_column(Text)
    executable: Mapped[str | None] = mapped_column(Text)
    harness_path: Mapped[str | None] = mapped_column(Text)
    compiler: Mapped[str | None] = mapped_column(String(120))
    build_configuration: Mapped[str] = mapped_column(
        String(32), nullable=False, default=domain.BuildConfiguration.DEBUG.value
    )
    sanitizers: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    @classmethod
    def from_domain(cls, target: domain.Target) -> "TargetRow":
        return cls(
            id=target.id,
            name=target.name,
            description=target.description,
            source_dir=_path_to_text(target.source_dir),
            build_dir=_path_to_text(target.build_dir),
            executable=_path_to_text(target.executable),
            harness_path=_path_to_text(target.harness_path),
            compiler=target.compiler,
            build_configuration=target.build_configuration.value,
            sanitizers=_enum_values(target.sanitizers),
            created_at=_to_storage_dt(target.created_at),
            updated_at=_to_storage_dt(target.updated_at),
            metadata_json=dict(target.metadata),
        )

    def to_domain(self) -> domain.Target:
        return domain.Target(
            id=self.id,
            name=self.name,
            description=self.description or "",
            source_dir=_text_to_path(self.source_dir),
            build_dir=_text_to_path(self.build_dir),
            executable=_text_to_path(self.executable),
            harness_path=_text_to_path(self.harness_path),
            compiler=self.compiler,
            build_configuration=domain.BuildConfiguration(self.build_configuration),
            sanitizers=[domain.SanitizerKind(value) for value in (self.sanitizers or [])],
            created_at=_from_storage_dt(self.created_at),
            updated_at=_from_storage_dt(self.updated_at),
            metadata=dict(self.metadata_json or {}),
        )


# ---------------------------------------------------------------------- corpora


class CorpusRow(Base):
    __tablename__ = "corpora"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), index=True
    )
    path: Mapped[str | None] = mapped_column(Text)
    file_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    @classmethod
    def from_domain(cls, corpus: domain.Corpus) -> "CorpusRow":
        return cls(
            id=corpus.id,
            name=corpus.name,
            description=corpus.description,
            target_id=corpus.target_id,
            path=_path_to_text(corpus.path),
            file_count=corpus.file_count,
            total_bytes=corpus.total_bytes,
            created_at=_to_storage_dt(corpus.created_at),
            updated_at=_to_storage_dt(corpus.updated_at),
            metadata_json=dict(corpus.metadata),
        )

    def to_domain(self) -> domain.Corpus:
        return domain.Corpus(
            id=self.id,
            name=self.name,
            description=self.description or "",
            target_id=self.target_id,
            path=_text_to_path(self.path),
            file_count=self.file_count,
            total_bytes=self.total_bytes,
            created_at=_from_storage_dt(self.created_at),
            updated_at=_from_storage_dt(self.updated_at),
            metadata=dict(self.metadata_json or {}),
        )


# -------------------------------------------------------------------- campaigns


class CampaignRow(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    target_id: Mapped[str] = mapped_column(
        ForeignKey("targets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    corpus_id: Mapped[str | None] = mapped_column(
        ForeignKey("corpora.id", ondelete="SET NULL"), index=True
    )
    fuzzer: Mapped[str] = mapped_column(
        String(32), nullable=False, default=domain.FuzzerKind.AFLPP.value
    )
    sanitizers: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    workers: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    duration_seconds: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=domain.CampaignStatus.PENDING.value
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    @classmethod
    def from_domain(cls, campaign: domain.Campaign) -> "CampaignRow":
        return cls(
            id=campaign.id,
            name=campaign.name,
            description=campaign.description,
            target_id=campaign.target_id,
            corpus_id=campaign.corpus_id,
            fuzzer=campaign.fuzzer.value,
            sanitizers=_enum_values(campaign.sanitizers),
            workers=campaign.workers,
            duration_seconds=campaign.duration_seconds,
            status=campaign.status.value,
            started_at=_to_storage_dt(campaign.started_at),
            finished_at=_to_storage_dt(campaign.finished_at),
            created_at=_to_storage_dt(campaign.created_at),
            updated_at=_to_storage_dt(campaign.updated_at),
            metadata_json=dict(campaign.metadata),
        )

    def to_domain(self) -> domain.Campaign:
        return domain.Campaign(
            id=self.id,
            name=self.name,
            description=self.description or "",
            target_id=self.target_id,
            corpus_id=self.corpus_id,
            fuzzer=domain.FuzzerKind(self.fuzzer),
            sanitizers=[domain.SanitizerKind(value) for value in (self.sanitizers or [])],
            workers=self.workers,
            duration_seconds=self.duration_seconds,
            status=domain.CampaignStatus(self.status),
            started_at=_from_storage_dt(self.started_at),
            finished_at=_from_storage_dt(self.finished_at),
            created_at=_from_storage_dt(self.created_at),
            updated_at=_from_storage_dt(self.updated_at),
            metadata=dict(self.metadata_json or {}),
        )


# ----------------------------------------------------------------------- crashes


class CrashRow(Base):
    __tablename__ = "crashes"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    campaign_id: Mapped[str | None] = mapped_column(
        ForeignKey("campaigns.id", ondelete="SET NULL"), index=True
    )
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), index=True
    )
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    input_path: Mapped[str | None] = mapped_column(Text)
    artifact_path: Mapped[str | None] = mapped_column(Text)
    evidence_path: Mapped[str | None] = mapped_column(Text)
    signal: Mapped[int | None] = mapped_column(Integer)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    sanitizer: Mapped[str | None] = mapped_column(String(32))
    classification: Mapped[str] = mapped_column(
        String(48), nullable=False, default=domain.CrashClassification.UNKNOWN.value
    )
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default=domain.Severity.UNKNOWN.value
    )
    fingerprint: Mapped[str | None] = mapped_column(String(128), index=True)
    stack_trace: Mapped[str | None] = mapped_column(Text)
    source_location: Mapped[str | None] = mapped_column(Text)
    reproduction_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=domain.ReproductionStatus.NOT_TESTED.value
    )
    stdout_excerpt: Mapped[str | None] = mapped_column(Text)
    stderr_excerpt: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    @classmethod
    def from_domain(cls, crash: domain.Crash) -> "CrashRow":
        return cls(
            id=crash.id,
            campaign_id=crash.campaign_id,
            target_id=crash.target_id,
            description=crash.description,
            input_path=_path_to_text(crash.input_path),
            artifact_path=_path_to_text(crash.artifact_path),
            evidence_path=_path_to_text(crash.evidence_path),
            signal=crash.signal,
            exit_code=crash.exit_code,
            sanitizer=None if crash.sanitizer is None else crash.sanitizer.value,
            classification=crash.classification.value,
            severity=crash.severity.value,
            fingerprint=crash.fingerprint,
            stack_trace=crash.stack_trace,
            source_location=crash.source_location,
            reproduction_status=crash.reproduction_status.value,
            stdout_excerpt=crash.stdout_excerpt,
            stderr_excerpt=crash.stderr_excerpt,
            created_at=_to_storage_dt(crash.created_at),
            updated_at=_to_storage_dt(crash.updated_at),
            metadata_json=dict(crash.metadata),
        )

    def to_domain(self) -> domain.Crash:
        return domain.Crash(
            id=self.id,
            campaign_id=self.campaign_id,
            target_id=self.target_id,
            description=self.description or "",
            input_path=_text_to_path(self.input_path),
            artifact_path=_text_to_path(self.artifact_path),
            evidence_path=_text_to_path(self.evidence_path),
            signal=self.signal,
            exit_code=self.exit_code,
            sanitizer=None if self.sanitizer is None else domain.SanitizerKind(self.sanitizer),
            classification=domain.CrashClassification(self.classification),
            severity=domain.Severity(self.severity),
            fingerprint=self.fingerprint,
            stack_trace=self.stack_trace,
            source_location=self.source_location,
            reproduction_status=domain.ReproductionStatus(self.reproduction_status),
            stdout_excerpt=self.stdout_excerpt,
            stderr_excerpt=self.stderr_excerpt,
            created_at=_from_storage_dt(self.created_at),
            updated_at=_from_storage_dt(self.updated_at),
            metadata=dict(self.metadata_json or {}),
        )


# ---------------------------------------------------------------------- findings


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    classification: Mapped[str] = mapped_column(
        String(48), nullable=False, default=domain.CrashClassification.UNKNOWN.value
    )
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default=domain.Severity.UNKNOWN.value
    )
    target_id: Mapped[str | None] = mapped_column(
        ForeignKey("targets.id", ondelete="SET NULL"), index=True
    )
    crash_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    reproduction_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=domain.ReproductionStatus.NOT_TESTED.value
    )
    remediation: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    @classmethod
    def from_domain(cls, finding: domain.Finding) -> "FindingRow":
        return cls(
            id=finding.id,
            title=finding.title,
            description=finding.description,
            fingerprint=finding.fingerprint,
            classification=finding.classification.value,
            severity=finding.severity.value,
            target_id=finding.target_id,
            crash_ids=list(finding.crash_ids),
            reproduction_status=finding.reproduction_status.value,
            remediation=finding.remediation,
            created_at=_to_storage_dt(finding.created_at),
            updated_at=_to_storage_dt(finding.updated_at),
            metadata_json=dict(finding.metadata),
        )

    def to_domain(self) -> domain.Finding:
        return domain.Finding(
            id=self.id,
            title=self.title,
            description=self.description or "",
            fingerprint=self.fingerprint,
            classification=domain.CrashClassification(self.classification),
            severity=domain.Severity(self.severity),
            target_id=self.target_id,
            crash_ids=list(self.crash_ids or []),
            reproduction_status=domain.ReproductionStatus(self.reproduction_status),
            remediation=self.remediation,
            created_at=_from_storage_dt(self.created_at),
            updated_at=_from_storage_dt(self.updated_at),
            metadata=dict(self.metadata_json or {}),
        )


# ----------------------------------------------------------------------- reports


class ReportRow(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    format: Mapped[str] = mapped_column(
        String(16), nullable=False, default=domain.ReportFormat.JSON.value
    )
    path: Mapped[str | None] = mapped_column(Text)
    campaign_id: Mapped[str | None] = mapped_column(
        ForeignKey("campaigns.id", ondelete="SET NULL"), index=True
    )
    finding_ids: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    @classmethod
    def from_domain(cls, report: domain.Report) -> "ReportRow":
        return cls(
            id=report.id,
            name=report.name,
            format=report.format.value,
            path=_path_to_text(report.path),
            campaign_id=report.campaign_id,
            finding_ids=list(report.finding_ids),
            created_at=_to_storage_dt(report.created_at),
            updated_at=_to_storage_dt(report.updated_at),
            metadata_json=dict(report.metadata),
        )

    def to_domain(self) -> domain.Report:
        return domain.Report(
            id=self.id,
            name=self.name,
            format=domain.ReportFormat(self.format),
            path=_text_to_path(self.path),
            campaign_id=self.campaign_id,
            finding_ids=list(self.finding_ids or []),
            created_at=_from_storage_dt(self.created_at),
            updated_at=_from_storage_dt(self.updated_at),
            metadata=dict(self.metadata_json or {}),
        )
