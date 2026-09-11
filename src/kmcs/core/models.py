"""Database-independent domain models.

These describe what KMCS *is about* — targets, corpora, campaigns, crashes,
findings, reports.  They deliberately know nothing about SQLAlchemy or SQLite so
the analysis code in later phases can be tested without a database.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "new_id",
    "utcnow",
    "BuildConfiguration",
    "SanitizerKind",
    "FuzzerKind",
    "CampaignStatus",
    "CrashClassification",
    "Severity",
    "ReproductionStatus",
    "ReportFormat",
    "Entity",
    "Target",
    "Corpus",
    "Campaign",
    "Crash",
    "Finding",
    "Report",
]


def new_id() -> str:
    """Return a fresh opaque identifier."""
    return uuid.uuid4().hex


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


class BuildConfiguration(str, Enum):
    DEBUG = "debug"
    RELEASE = "release"
    ASAN = "asan"
    UBSAN = "ubsan"
    ASAN_UBSAN = "asan+ubsan"
    COVERAGE = "coverage"


class SanitizerKind(str, Enum):
    NONE = "none"
    ADDRESS = "address"
    UNDEFINED = "undefined"
    LEAK = "leak"
    MEMORY = "memory"
    THREAD = "thread"


class FuzzerKind(str, Enum):
    AFLPP = "afl++"
    LIBFUZZER = "libfuzzer"
    HONGFUZZ = "honggfuzz"


class CampaignStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CrashClassification(str, Enum):
    """Crash classes KMCS may report.

    ``UNKNOWN`` is the honest default: if the evidence does not support a
    classification, KMCS must not guess.
    """

    HEAP_BUFFER_OVERFLOW = "heap-buffer-overflow"
    STACK_BUFFER_OVERFLOW = "stack-buffer-overflow"
    GLOBAL_BUFFER_OVERFLOW = "global-buffer-overflow"
    USE_AFTER_FREE = "use-after-free"
    DOUBLE_FREE = "double-free"
    INVALID_FREE = "invalid-free"
    OUT_OF_BOUNDS_READ = "out-of-bounds-read"
    OUT_OF_BOUNDS_WRITE = "out-of-bounds-write"
    NULL_POINTER_DEREFERENCE = "null-pointer-dereference"
    SEGMENTATION_FAULT = "segmentation-fault"
    UNDEFINED_BEHAVIOR = "undefined-behavior"
    MEMORY_LEAK = "memory-leak"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    """Evidence-based severity.  Never an exploitability claim."""

    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReproductionStatus(str, Enum):
    NOT_TESTED = "not-tested"
    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not-reproduced"
    INTERMITTENT = "intermittent"
    ERROR = "error"


class ReportFormat(str, Enum):
    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    CSV = "csv"
    SARIF = "sarif"


class Entity(BaseModel):
    """Fields shared by every persisted KMCS entity."""

    model_config = ConfigDict(validate_assignment=True)

    id: str = Field(default_factory=new_id)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def touch(self) -> None:
        """Mark the entity as modified now."""
        self.updated_at = utcnow()


class Target(Entity):
    """An authorised C/C++ program KMCS is allowed to fuzz."""

    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    source_dir: Path | None = None
    build_dir: Path | None = None
    executable: Path | None = None
    harness_path: Path | None = None
    compiler: str | None = None
    build_configuration: BuildConfiguration = BuildConfiguration.DEBUG
    sanitizers: list[SanitizerKind] = Field(default_factory=list)

    @field_validator("name", mode="after")
    @classmethod
    def _normalise_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("target name must not be empty or whitespace-only")
        return cleaned


class Corpus(Entity):
    """A collection of input files used to seed a fuzzing campaign."""

    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    target_id: str | None = None
    path: Path | None = None
    file_count: int = Field(default=0, ge=0)
    total_bytes: int = Field(default=0, ge=0)

    @field_validator("name", mode="after")
    @classmethod
    def _normalise_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("corpus name must not be empty or whitespace-only")
        return cleaned


class Campaign(Entity):
    """A complete, configured fuzzing run."""

    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    target_id: str
    corpus_id: str | None = None
    fuzzer: FuzzerKind = FuzzerKind.AFLPP
    sanitizers: list[SanitizerKind] = Field(default_factory=list)
    workers: int = Field(default=1, ge=1, le=1024)
    duration_seconds: int | None = Field(default=None, ge=0)
    status: CampaignStatus = CampaignStatus.PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None

    @field_validator("name", mode="after")
    @classmethod
    def _normalise_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("campaign name must not be empty or whitespace-only")
        return cleaned


class Crash(Entity):
    """Raw evidence that a target died or a sanitizer fired.

    Every field here is derived from observed evidence.  ``input_path`` and
    ``evidence_path`` point at the preserved originals; KMCS never discards raw
    evidence in favour of a summary.
    """

    campaign_id: str | None = None
    target_id: str | None = None
    description: str = ""
    input_path: Path | None = None
    artifact_path: Path | None = None
    evidence_path: Path | None = None
    signal: int | None = None
    exit_code: int | None = None
    sanitizer: SanitizerKind | None = None
    classification: CrashClassification = CrashClassification.UNKNOWN
    severity: Severity = Severity.UNKNOWN
    fingerprint: str | None = None
    stack_trace: str | None = None
    source_location: str | None = None
    reproduction_status: ReproductionStatus = ReproductionStatus.NOT_TESTED
    stdout_excerpt: str | None = None
    stderr_excerpt: str | None = None


class Finding(Entity):
    """A deduplicated, structured security finding."""

    title: str = Field(min_length=1, max_length=300)
    description: str = ""
    fingerprint: str = Field(min_length=1, max_length=128)
    classification: CrashClassification = CrashClassification.UNKNOWN
    severity: Severity = Severity.UNKNOWN
    target_id: str | None = None
    crash_ids: list[str] = Field(default_factory=list)
    reproduction_status: ReproductionStatus = ReproductionStatus.NOT_TESTED
    remediation: str | None = None

    @field_validator("title", mode="after")
    @classmethod
    def _normalise_title(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("finding title must not be empty or whitespace-only")
        return cleaned


class Report(Entity):
    """A rendered artefact describing one or more findings."""

    name: str = Field(min_length=1, max_length=200)
    format: ReportFormat = ReportFormat.JSON
    path: Path | None = None
    campaign_id: str | None = None
    finding_ids: list[str] = Field(default_factory=list)

    @field_validator("name", mode="after")
    @classmethod
    def _normalise_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("report name must not be empty or whitespace-only")
        return cleaned
