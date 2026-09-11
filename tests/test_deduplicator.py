"""Deduplicator: grouping, representative selection, finding construction."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from kmcs.analysis.crash_parser import (
    AccessType,
    CrashReport,
    SanitizerReport,
    StackFrame,
)
from kmcs.analysis.deduplicator import CrashDeduplicator
from kmcs.analysis.fingerprint import CrashFingerprinter, FingerprintConfig
from kmcs.core.models import Crash, CrashClassification, SanitizerKind


def _frame(idx: int, func: str, file: str = "/s/a.c", line: int = 10) -> StackFrame:
    return StackFrame(
        index=idx,
        raw=f"#{idx} {func} {file}:{line}",
        function=func,
        source_file=file,
        line=line,
    )


def _report(error_type: str, *, func: str, line: int = 10) -> CrashReport:
    frame = _frame(0, func, line=line)
    primary = SanitizerReport(
        sanitizer=SanitizerKind.ADDRESS,
        error_type=error_type,
        access_type=AccessType.WRITE,
        stack_frames=[frame],
    )
    return CrashReport(
        sanitizer_reports=[primary],
        stack_frames=[frame],
        classification=CrashClassification.HEAP_BUFFER_OVERFLOW,
    )


def _crash(
    *,
    crash_id: str = "",
    input_path: Path | None = None,
    created_offset: int = 0,
) -> Crash:
    crash = Crash(
        input_path=input_path,
        description="x",
    )
    if crash_id:
        # Pydantic allows assignment; field is on the model.
        crash.id = crash_id
    crash.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(
        seconds=created_offset
    )
    return crash


class TestEmpty:
    def test_empty_input_produces_empty_result(self) -> None:
        result = CrashDeduplicator().deduplicate([])
        assert result.groups == []
        assert result.findings == []
        assert result.total_crashes == 0
        assert result.total_groups == 0
        assert result.duplicates_removed == 0


class TestGrouping:
    def test_identical_crashes_collapse_to_one_group(self) -> None:
        report = _report("heap-buffer-overflow", func="main")
        pairs = [(_crash(), report) for _ in range(5)]

        result = CrashDeduplicator().deduplicate(pairs)
        assert result.total_crashes == 5
        assert result.total_groups == 1
        assert result.duplicates_removed == 4
        assert result.groups[0].size == 5

    def test_distinct_fingerprints_stay_separate(self) -> None:
        pairs = [
            (_crash(), _report("heap-buffer-overflow", func="parse_a")),
            (_crash(), _report("heap-buffer-overflow", func="parse_b")),
            (_crash(), _report("use-after-free", func="parse_a")),
        ]

        result = CrashDeduplicator().deduplicate(pairs)
        assert result.total_groups == 3
        assert result.duplicates_removed == 0

    def test_three_by_ten_split(self) -> None:
        pairs = []
        for func in ("a", "b", "c"):
            for _ in range(10):
                pairs.append((_crash(), _report("heap-buffer-overflow", func=func)))

        result = CrashDeduplicator().deduplicate(pairs)
        assert result.total_crashes == 30
        assert result.total_groups == 3
        assert all(g.size == 10 for g in result.groups)

    def test_groups_are_ordered_by_size_descending(self) -> None:
        pairs = []
        for _ in range(5):
            pairs.append((_crash(), _report("heap-buffer-overflow", func="big")))
        for _ in range(2):
            pairs.append((_crash(), _report("heap-buffer-overflow", func="small")))

        result = CrashDeduplicator().deduplicate(pairs)
        assert result.groups[0].size == 5
        assert result.groups[1].size == 2


class TestRepresentativeSelection:
    def test_smallest_input_wins(self, tmp_path: Path) -> None:
        big_file = tmp_path / "big"
        big_file.write_bytes(b"x" * 1000)
        small_file = tmp_path / "small"
        small_file.write_bytes(b"x")

        report = _report("heap-buffer-overflow", func="main")
        pairs = [
            (_crash(input_path=big_file, created_offset=0), report),
            (_crash(input_path=small_file, created_offset=10), report),
        ]

        result = CrashDeduplicator().deduplicate(pairs)
        representative = result.groups[0].representative
        assert representative.input_path == small_file

    def test_earliest_wins_when_sizes_tie(self) -> None:
        report = _report("heap-buffer-overflow", func="main")
        pairs = [
            (_crash(crash_id="z", created_offset=10), report),
            (_crash(crash_id="a", created_offset=0), report),
        ]

        result = CrashDeduplicator().deduplicate(pairs)
        assert result.groups[0].representative.id == "a"

    def test_missing_input_file_falls_back_to_created_at(self, tmp_path: Path) -> None:
        missing = tmp_path / "no-such-file"
        present = tmp_path / "present"
        present.write_bytes(b"x")

        report = _report("heap-buffer-overflow", func="main")
        pairs = [
            (_crash(input_path=missing, created_offset=0), report),
            (_crash(input_path=present, created_offset=100), report),
        ]

        result = CrashDeduplicator().deduplicate(pairs)
        assert result.groups[0].representative.input_path == present


class TestFindingConstruction:
    def test_finding_links_every_crash_id(self) -> None:
        report = _report("heap-buffer-overflow", func="parse_chunk")
        pairs = [(_crash(crash_id=f"c{i}"), report) for i in range(4)]

        result = CrashDeduplicator().deduplicate(pairs)
        finding = result.findings[0]
        assert set(finding.crash_ids) == {"c0", "c1", "c2", "c3"}

    def test_finding_title_names_the_function(self) -> None:
        report = _report("heap-buffer-overflow", func="parse_chunk")
        result = CrashDeduplicator().deduplicate([(_crash(), report)])
        assert "parse_chunk" in result.findings[0].title
        assert "heap-buffer-overflow" in result.findings[0].title

    def test_finding_has_fingerprint_and_classification(self) -> None:
        report = _report("heap-buffer-overflow", func="main")
        result = CrashDeduplicator().deduplicate([(_crash(), report)])
        finding = result.findings[0]
        assert finding.fingerprint
        assert finding.classification is CrashClassification.HEAP_BUFFER_OVERFLOW

    def test_finding_records_evidence_in_metadata(self) -> None:
        report = _report("heap-buffer-overflow", func="main")
        result = CrashDeduplicator().deduplicate([(_crash(), report)])
        metadata = result.findings[0].metadata
        assert metadata["occurrence_count"] == 1
        assert "fingerprint_canonical" in metadata
        assert "classification_evidence" in metadata
        assert "severity_rationale" in metadata
        assert "severity_factors" in metadata

    def test_finding_description_includes_stack_frames(self) -> None:
        report = _report("heap-buffer-overflow", func="parse_chunk")
        result = CrashDeduplicator().deduplicate([(_crash(), report)])
        description = result.findings[0].description
        assert "Classification: heap-buffer-overflow" in description
        assert "parse_chunk" in description
        assert "Fingerprint:" in description

    def test_remediation_is_classification_specific(self) -> None:
        report = _report("heap-buffer-overflow", func="main")
        result = CrashDeduplicator().deduplicate([(_crash(), report)])
        remediation = result.findings[0].remediation
        assert remediation is not None
        assert "buffer" in remediation.lower()


class TestDeterminism:
    def test_group_ordering_is_stable(self) -> None:
        pairs = [
            (_crash(), _report("heap-buffer-overflow", func="b")),
            (_crash(), _report("heap-buffer-overflow", func="a")),
        ]
        result_a = CrashDeduplicator().deduplicate(pairs)
        result_b = CrashDeduplicator().deduplicate(pairs)
        assert [g.fingerprint.value for g in result_a.groups] == [
            g.fingerprint.value for g in result_b.groups
        ]

    def test_custom_fingerprinter_is_honoured(self) -> None:
        # With stack_depth=1 and no aux stacks, two crashes that differ only in
        # a lower frame collapse together.
        shallow = CrashFingerprinter(
            FingerprintConfig(stack_depth=1, include_auxiliary_stacks=False)
        )
        dedup = CrashDeduplicator(fingerprinter=shallow)

        frame_top = _frame(0, "parse")
        frame_lower_a = _frame(1, "caller_a")
        frame_lower_b = _frame(1, "caller_b")

        report_a = CrashReport(
            sanitizer_reports=[
                SanitizerReport(
                    sanitizer=SanitizerKind.ADDRESS,
                    error_type="heap-buffer-overflow",
                    stack_frames=[frame_top, frame_lower_a],
                )
            ],
            stack_frames=[frame_top, frame_lower_a],
        )
        report_b = CrashReport(
            sanitizer_reports=[
                SanitizerReport(
                    sanitizer=SanitizerKind.ADDRESS,
                    error_type="heap-buffer-overflow",
                    stack_frames=[frame_top, frame_lower_b],
                )
            ],
            stack_frames=[frame_top, frame_lower_b],
        )

        result = dedup.deduplicate([(_crash(), report_a), (_crash(), report_b)])
        assert result.total_groups == 1


class TestSerialisation:
    def test_result_to_dict_is_json_serialisable(self) -> None:
        import json

        report = _report("heap-buffer-overflow", func="main")
        result = CrashDeduplicator().deduplicate(
            [(_crash(crash_id="a"), report), (_crash(crash_id="b"), report)]
        )
        json.dumps(result.to_dict())
