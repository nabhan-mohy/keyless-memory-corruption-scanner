"""Evidence-based severity assessment.

**KMCS does not assess exploitability.**  Severity here is a triage signal
derived strictly from the sanitizer's own evidence: it says "this class of bug
is generally more serious than that class of bug", nothing more.  A finding
labelled HIGH is not a claim that the bug is exploitable, remote, or
unauthenticated; it is a claim that the memory-safety violation, *if
reachable*, is significant.

The assessor never emits :attr:`Severity.CRITICAL`.  That value is reserved for
a future, explicit exploitability analysis that KMCS will not perform
automatically.

Every assessment records:

* the severity value,
* a short rationale explaining the mapping from evidence to severity,
* a tuple of ``(factor, value)`` pairs naming the specific evidence used.
"""

from __future__ import annotations

from dataclasses import dataclass

from kmcs.analysis.crash_parser import AccessType, CrashReport
from kmcs.core.models import CrashClassification, Severity

__all__ = [
    "SeverityAssessment",
    "SeverityAssessor",
]


@dataclass(frozen=True, slots=True)
class SeverityAssessment:
    severity: Severity
    rationale: str
    factors: tuple[tuple[str, str], ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "severity": self.severity.value,
            "rationale": self.rationale,
            "factors": [{"factor": k, "value": v} for k, v in self.factors],
        }


# Base severity for every classification.  These are triage values, not
# exploitability claims.  Notes on each entry are in the assessor's rationale.
_BASE_SEVERITY: dict[CrashClassification, Severity] = {
    CrashClassification.HEAP_BUFFER_OVERFLOW: Severity.HIGH,
    CrashClassification.STACK_BUFFER_OVERFLOW: Severity.HIGH,
    CrashClassification.GLOBAL_BUFFER_OVERFLOW: Severity.MEDIUM,
    CrashClassification.USE_AFTER_FREE: Severity.HIGH,
    CrashClassification.DOUBLE_FREE: Severity.HIGH,
    CrashClassification.INVALID_FREE: Severity.MEDIUM,
    CrashClassification.OUT_OF_BOUNDS_WRITE: Severity.HIGH,
    CrashClassification.OUT_OF_BOUNDS_READ: Severity.MEDIUM,
    CrashClassification.NULL_POINTER_DEREFERENCE: Severity.LOW,
    CrashClassification.SEGMENTATION_FAULT: Severity.UNKNOWN,
    CrashClassification.UNDEFINED_BEHAVIOR: Severity.LOW,
    CrashClassification.MEMORY_LEAK: Severity.INFO,
    CrashClassification.UNKNOWN: Severity.UNKNOWN,
}

_BASE_RATIONALE: dict[CrashClassification, str] = {
    CrashClassification.HEAP_BUFFER_OVERFLOW: (
        "Heap buffer overflow is a memory-corruption class that can corrupt "
        "adjacent heap objects."
    ),
    CrashClassification.STACK_BUFFER_OVERFLOW: (
        "Stack buffer overflow is a memory-corruption class that can overwrite "
        "the return address and other saved state."
    ),
    CrashClassification.GLOBAL_BUFFER_OVERFLOW: (
        "Global buffer overflow corrupts a static object; typically lower "
        "impact than heap or stack corruption but still a memory-safety bug."
    ),
    CrashClassification.USE_AFTER_FREE: (
        "Use-after-free is a memory-corruption class in which a dangling "
        "pointer is dereferenced."
    ),
    CrashClassification.DOUBLE_FREE: (
        "Double-free is a memory-corruption class that can produce overlapping "
        "allocations."
    ),
    CrashClassification.INVALID_FREE: (
        "Freeing a non-heap pointer is undefined behaviour; impact depends on "
        "the allocator in use."
    ),
    CrashClassification.OUT_OF_BOUNDS_WRITE: (
        "Out-of-bounds write is a memory-corruption class."
    ),
    CrashClassification.OUT_OF_BOUNDS_READ: (
        "Out-of-bounds read can leak memory contents; usually lower impact "
        "than an out-of-bounds write."
    ),
    CrashClassification.NULL_POINTER_DEREFERENCE: (
        "Null-pointer dereference is typically a denial-of-service rather than "
        "memory corruption on modern systems."
    ),
    CrashClassification.UNDEFINED_BEHAVIOR: (
        "Undefined behaviour from UndefinedBehaviorSanitizer is not itself "
        "memory corruption; it is a standard-conformance defect whose impact "
        "depends on the compiler and target."
    ),
    CrashClassification.MEMORY_LEAK: (
        "Memory leak is a resource-exhaustion defect, not a memory-safety bug."
    ),
    CrashClassification.UNKNOWN: (
        "Insufficient evidence to assign a classification; severity is "
        "therefore unknown."
    ),
}


class SeverityAssessor:
    """Computes an evidence-based severity for a classified crash."""

    def assess(
        self,
        report: CrashReport,
        classification: CrashClassification,
    ) -> SeverityAssessment:
        base = _BASE_SEVERITY.get(classification, Severity.UNKNOWN)
        rationale = _BASE_RATIONALE.get(
            classification, "No severity mapping is defined for this classification."
        )
        factors: list[tuple[str, str]] = [
            ("classification", classification.value),
            ("base_severity", base.value),
        ]

        # --- signal-only SEGV: peek at the faulting address ---------------
        if classification is CrashClassification.SEGMENTATION_FAULT:
            address = self._first_faulting_address(report)
            if address is not None:
                factors.append(("faulting_address", f"0x{address:x}"))
                if address < 0x1000:
                    return SeverityAssessment(
                        severity=Severity.LOW,
                        rationale=(
                            "Segmentation fault at a near-null address; this "
                            "is characteristic of a null-pointer dereference."
                        ),
                        factors=tuple(factors),
                    )
            return SeverityAssessment(
                severity=Severity.UNKNOWN,
                rationale=(
                    "Segmentation fault without a sanitizer report; the stack "
                    "trace alone cannot distinguish a null-pointer dereference "
                    "from a corrupted pointer. Manual review required."
                ),
                factors=tuple(factors),
            )

        # --- access-type nuance -------------------------------------------
        access = self._access_type_of_primary(report)
        if access is not AccessType.UNKNOWN:
            factors.append(("access_type", access.value))
            # Reads on otherwise-HIGH classes are downgraded to MEDIUM, not
            # below: an out-of-bounds read can still leak sensitive memory.
            if (
                access is AccessType.READ
                and base is Severity.HIGH
                and classification in (
                    CrashClassification.HEAP_BUFFER_OVERFLOW,
                    CrashClassification.STACK_BUFFER_OVERFLOW,
                    CrashClassification.OUT_OF_BOUNDS_WRITE,
                )
            ):
                return SeverityAssessment(
                    severity=Severity.MEDIUM,
                    rationale=(
                        rationale
                        + " The sanitizer reported a READ rather than a WRITE, "
                        "which lowers the typical impact."
                    ),
                    factors=tuple(factors),
                )

        # --- memory-leak nuance -------------------------------------------
        if classification is CrashClassification.MEMORY_LEAK:
            factors.append(("impact", "resource-exhaustion"))
            return SeverityAssessment(
                severity=Severity.INFO,
                rationale=(
                    "Memory leaks do not corrupt memory but can exhaust address "
                    "space over long runs. Severity is informational."
                ),
                factors=tuple(factors),
            )

        return SeverityAssessment(
            severity=base,
            rationale=rationale,
            factors=tuple(factors),
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _first_faulting_address(report: CrashReport) -> int | None:
        primary = report.primary_report
        if primary is not None and primary.faulting_address is not None:
            return primary.faulting_address
        return None

    @staticmethod
    def _access_type_of_primary(report: CrashReport) -> AccessType:
        primary = report.primary_report
        if primary is None:
            return AccessType.UNKNOWN
        return primary.access_type
