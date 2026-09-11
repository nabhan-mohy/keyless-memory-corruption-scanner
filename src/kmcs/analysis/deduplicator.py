"""Group crashes by fingerprint and construct findings.

Input:  a sequence of ``(Crash, CrashReport)`` pairs.

Output: a :class:`DeduplicationResult` containing one :class:`CrashGroup` per
distinct fingerprint, plus one :class:`Finding` per group.

Guarantees:

* **Determinism.** Grouping is order-independent; the representative of each
  group is selected by a total, observable rule (smallest input file, then
  earliest ``created_at``, then smallest ``id``).
* **Preservation.** Every input crash ID appears in exactly one output group.
* **No fabrication.** The number of crashes and the number of duplicates are
  the actual counts of the input sequence.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kmcs.analysis.classifier import ClassificationResult, CrashClassifier
from kmcs.analysis.crash_parser import CrashReport
from kmcs.analysis.fingerprint import CrashFingerprint, CrashFingerprinter
from kmcs.analysis.severity import SeverityAssessment, SeverityAssessor
from kmcs.core import models
from kmcs.core.models import Crash, Finding, ReproductionStatus

logger = logging.getLogger(__name__)

__all__ = [
    "CrashGroup",
    "DeduplicationResult",
    "CrashDeduplicator",
]


@dataclass(slots=True)
class CrashGroup:
    """A set of crashes that share a fingerprint."""

    fingerprint: CrashFingerprint
    classification: ClassificationResult
    severity: SeverityAssessment
    crashes: list[Crash] = field(default_factory=list)
    reports: list[CrashReport] = field(default_factory=list)
    representative_index: int = 0

    @property
    def representative(self) -> Crash:
        return self.crashes[self.representative_index]

    @property
    def representative_report(self) -> CrashReport:
        return self.reports[self.representative_index]

    @property
    def crash_ids(self) -> list[str]:
        return [crash.id for crash in self.crashes]

    @property
    def size(self) -> int:
        return len(self.crashes)


@dataclass(slots=True)
class DeduplicationResult:
    groups: list[CrashGroup]
    findings: list[Finding]
    total_crashes: int
    total_groups: int
    duplicates_removed: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_crashes": self.total_crashes,
            "total_groups": self.total_groups,
            "duplicates_removed": self.duplicates_removed,
            "groups": [
                {
                    "fingerprint": group.fingerprint.value,
                    "size": group.size,
                    "classification": group.classification.classification.value,
                    "severity": group.severity.severity.value,
                    "representative_id": group.representative.id,
                    "crash_ids": group.crash_ids,
                }
                for group in self.groups
            ],
            "finding_ids": [f.id for f in self.findings],
        }


_REMEDIATION_BY_CLASSIFICATION: dict[models.CrashClassification, str] = {
    models.CrashClassification.HEAP_BUFFER_OVERFLOW: (
        "Validate buffer sizes before every read and write. Confirm that the "
        "allocation size and the access index are computed from the same "
        "invariant, and prefer bounds-checked containers where practical."
    ),
    models.CrashClassification.STACK_BUFFER_OVERFLOW: (
        "Validate fixed-size stack array bounds. Replace fixed arrays with "
        "dynamically sized storage where the maximum size is not a fixed "
        "compile-time constant."
    ),
    models.CrashClassification.GLOBAL_BUFFER_OVERFLOW: (
        "Validate accesses to static arrays. Prefer bounds-checked types."
    ),
    models.CrashClassification.USE_AFTER_FREE: (
        "Ensure objects are not dereferenced after they are freed. Consider "
        "ownership-aware smart pointers, and set pointers to NULL after free "
        "where manual lifetime management is required."
    ),
    models.CrashClassification.DOUBLE_FREE: (
        "Ensure each allocation is freed exactly once. Avoid freeing pointers "
        "that may alias each other."
    ),
    models.CrashClassification.INVALID_FREE: (
        "Free only pointers returned by malloc / calloc / realloc / new. "
        "Interior pointers are not valid free targets."
    ),
    models.CrashClassification.OUT_OF_BOUNDS_WRITE: (
        "Validate indices before writing. Prefer bounds-checked containers."
    ),
    models.CrashClassification.OUT_OF_BOUNDS_READ: (
        "Validate indices before reading. Prefer bounds-checked containers."
    ),
    models.CrashClassification.NULL_POINTER_DEREFERENCE: (
        "Check pointer validity before dereferencing. Treat API return values "
        "and structure fields as potentially NULL unless documented otherwise."
    ),
    models.CrashClassification.SEGMENTATION_FAULT: (
        "Review the stack trace for the dereferenced address. Validate "
        "pointers before use."
    ),
    models.CrashClassification.UNDEFINED_BEHAVIOR: (
        "Review the exact UBSan message. Common causes include signed integer "
        "overflow, shift-out-of-range, and division by zero."
    ),
    models.CrashClassification.MEMORY_LEAK: (
        "Ensure every allocated object is freed on every exit path, including "
        "error paths."
    ),
    models.CrashClassification.UNKNOWN: (
        "KMCS could not confidently classify this crash. Manual review of the "
        "preserved evidence is required."
    ),
}


class CrashDeduplicator:
    """Groups crashes by fingerprint and produces findings."""

    def __init__(
        self,
        *,
        fingerprinter: CrashFingerprinter | None = None,
        classifier: CrashClassifier | None = None,
        severity_assessor: SeverityAssessor | None = None,
    ) -> None:
        self._fingerprinter = fingerprinter or CrashFingerprinter()
        self._classifier = classifier or CrashClassifier()
        self._severity = severity_assessor or SeverityAssessor()

    # ------------------------------------------------------------------ public

    def deduplicate(
        self,
        observations: Sequence[tuple[Crash, CrashReport]],
    ) -> DeduplicationResult:
        if not observations:
            return DeduplicationResult(
                groups=[],
                findings=[],
                total_crashes=0,
                total_groups=0,
                duplicates_removed=0,
            )

        # --- compute fingerprints and build groups ------------------------
        groups_by_fp: dict[str, CrashGroup] = {}

        for crash, report in observations:
            fingerprint = self._fingerprinter.fingerprint(report)
            group = groups_by_fp.get(fingerprint.value)
            if group is None:
                classification = self._classifier.classify(report)
                severity = self._severity.assess(
                    report, classification.classification
                )
                group = CrashGroup(
                    fingerprint=fingerprint,
                    classification=classification,
                    severity=severity,
                )
                groups_by_fp[fingerprint.value] = group
            group.crashes.append(crash)
            group.reports.append(report)

        # --- choose representative per group ------------------------------
        for group in groups_by_fp.values():
            group.representative_index = self._pick_representative(group)

        # --- deterministic group ordering ---------------------------------
        groups = sorted(
            groups_by_fp.values(),
            key=lambda g: (-g.size, g.fingerprint.value),
        )

        # --- build findings ----------------------------------------------
        findings = [self._build_finding(group) for group in groups]

        total = len(observations)
        return DeduplicationResult(
            groups=groups,
            findings=findings,
            total_crashes=total,
            total_groups=len(groups),
            duplicates_removed=total - len(groups),
        )

    # ------------------------------------------------------------------ internal

    @staticmethod
    def _pick_representative(group: CrashGroup) -> int:
        """Return the index of the representative crash in ``group``.

        Selection rule (total order, stable):

        1. Smallest input file (bytes), if the file exists.
        2. Earliest ``created_at``.
        3. Smallest ``id``.
        """
        scored: list[tuple[float, float, str, int]] = []
        for index, crash in enumerate(group.crashes):
            size = CrashDeduplicator._input_size(crash)
            created = crash.created_at.timestamp()
            scored.append((size, created, crash.id, index))
        scored.sort()
        return scored[0][3]

    @staticmethod
    def _input_size(crash: Crash) -> float:
        path = crash.input_path
        if path is None:
            return math.inf
        try:
            return float(path.stat().st_size)
        except OSError:
            return math.inf

    def _build_finding(self, group: CrashGroup) -> Finding:
        representative = group.representative
        report = group.representative_report
        classification = group.classification.classification
        severity = group.severity.severity

        title = self._build_title(classification, report)
        description = self._build_description(
            classification=classification,
            severity=severity,
            fingerprint=group.fingerprint,
            group=group,
            report=report,
        )

        return Finding(
            title=title,
            description=description,
            fingerprint=group.fingerprint.value,
            classification=classification,
            severity=severity,
            target_id=representative.target_id,
            crash_ids=group.crash_ids,
            reproduction_status=representative.reproduction_status,
            remediation=_REMEDIATION_BY_CLASSIFICATION.get(classification),
            metadata={
                "representative_crash_id": representative.id,
                "occurrence_count": group.size,
                "fingerprint_canonical": group.fingerprint.canonical,
                "classification_confidence": group.classification.confidence.value,
                "classification_evidence": list(group.classification.evidence),
                "severity_rationale": group.severity.rationale,
                "severity_factors": [
                    {"factor": k, "value": v} for k, v in group.severity.factors
                ],
            },
        )

    @staticmethod
    def _build_title(
        classification: models.CrashClassification, report: CrashReport
    ) -> str:
        top = report.stack_frames[0] if report.stack_frames else None

        if top is not None and top.function:
            return f"{classification.value} in {top.function}"
        if top is not None and top.source_file:
            return f"{classification.value} in {Path(top.source_file).name}"
        if report.signal_name:
            return f"{classification.value} ({report.signal_name})"
        return classification.value

    @staticmethod
    def _build_description(
        *,
        classification: models.CrashClassification,
        severity: models.Severity,
        fingerprint: CrashFingerprint,
        group: CrashGroup,
        report: CrashReport,
    ) -> str:
        lines: list[str] = []
        lines.append(f"Classification: {classification.value}")
        lines.append(f"Severity: {severity.value}")
        lines.append(f"Confidence: {group.classification.confidence.value}")
        lines.append(f"Fingerprint: {fingerprint.value}")
        lines.append(f"Occurrences: {group.size}")

        primary = report.primary_report
        if primary is not None:
            lines.append(f"Sanitizer: {primary.sanitizer.value}")
            if primary.error_type:
                lines.append(f"Error type: {primary.error_type}")
            if primary.access_type.value != "unknown":
                suffix = f" of size {primary.access_size}" if primary.access_size else ""
                lines.append(f"Access: {primary.access_type.value}{suffix}")

        if report.source_location:
            lines.append(f"Source location: {report.source_location}")
        if report.signal_name:
            lines.append(f"Signal: {report.signal_name}")

        if report.stack_frames:
            lines.append("")
            lines.append("Top frames (from sanitizer):")
            for frame in report.stack_frames[:5]:
                lines.append(f"  {frame.raw.strip()}")

        if primary is not None and primary.free_site:
            lines.append("")
            lines.append("Freed at:")
            for frame in primary.free_site[:3]:
                lines.append(f"  {frame.raw.strip()}")

        if primary is not None and primary.allocation_site:
            lines.append("")
            lines.append("Allocated at:")
            for frame in primary.allocation_site[:3]:
                lines.append(f"  {frame.raw.strip()}")

        return "\n".join(lines)
