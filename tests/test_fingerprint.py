"""Fingerprinter: determinism, portability, and discrimination."""

from __future__ import annotations

from kmcs.analysis.crash_parser import (
    AccessType,
    CrashReport,
    SanitizerReport,
    StackFrame,
)
from kmcs.analysis.fingerprint import CrashFingerprinter, FingerprintConfig
from kmcs.core.models import CrashClassification, SanitizerKind


def _frame(
    idx: int,
    func: str,
    file: str | None = "/s/demo/vulnerable.c",
    line: int | None = 18,
    module: str | None = None,
    offset: int | None = None,
) -> StackFrame:
    raw_parts = [f"#{idx} 0x0000"]
    if func:
        raw_parts.append(f"in {func}")
    if file and line:
        raw_parts.append(f"{file}:{line}")
    if module:
        raw_parts.append(f"({module}+0x{offset or 0:x})")
    return StackFrame(
        index=idx,
        raw=" ".join(raw_parts),
        function=func,
        source_file=file,
        line=line,
        module=module,
        offset=offset,
    )


def _asan_report(
    *,
    error_type: str = "heap-buffer-overflow",
    stack: list[StackFrame] | None = None,
    free_site: list[StackFrame] | None = None,
    alloc_site: list[StackFrame] | None = None,
    access: AccessType = AccessType.WRITE,
) -> CrashReport:
    primary = SanitizerReport(
        sanitizer=SanitizerKind.ADDRESS,
        error_type=error_type,
        access_type=access,
        stack_frames=stack or [],
        free_site=free_site or [],
        allocation_site=alloc_site or [],
    )
    return CrashReport(
        sanitizer_reports=[primary],
        stack_frames=list(stack or []),
        classification=CrashClassification.HEAP_BUFFER_OVERFLOW,
    )


class TestDeterminism:
    def test_same_report_produces_same_fingerprint(self) -> None:
        report = _asan_report(stack=[_frame(0, "main")])
        fp = CrashFingerprinter()
        first = fp.fingerprint(report)
        second = fp.fingerprint(report)
        assert first.value == second.value
        assert first.canonical == second.canonical

    def test_different_fingerprinter_instances_agree(self) -> None:
        report = _asan_report(stack=[_frame(0, "main")])
        assert (
            CrashFingerprinter().fingerprint(report).value
            == CrashFingerprinter().fingerprint(report).value
        )


class TestDiscrimination:
    def test_different_error_type_changes_fingerprint(self) -> None:
        fp = CrashFingerprinter()
        a = fp.fingerprint(_asan_report(error_type="heap-buffer-overflow"))
        b = fp.fingerprint(_asan_report(error_type="use-after-free"))
        assert a.value != b.value

    def test_different_function_changes_fingerprint(self) -> None:
        fp = CrashFingerprinter()
        a = fp.fingerprint(_asan_report(stack=[_frame(0, "parse_chunk")]))
        b = fp.fingerprint(_asan_report(stack=[_frame(0, "parse_header")]))
        assert a.value != b.value

    def test_different_line_changes_fingerprint(self) -> None:
        fp = CrashFingerprinter()
        a = fp.fingerprint(_asan_report(stack=[_frame(0, "main", line=18)]))
        b = fp.fingerprint(_asan_report(stack=[_frame(0, "main", line=19)]))
        assert a.value != b.value

    def test_same_frames_different_paths_same_fingerprint(self) -> None:
        """The fingerprint must be portable across build directories."""
        fp = CrashFingerprinter()
        a = fp.fingerprint(
            _asan_report(stack=[_frame(0, "main", file="/tmp/build-1234/demo/vulnerable.c")])
        )
        b = fp.fingerprint(
            _asan_report(stack=[_frame(0, "main", file="/home/analyst/src/demo/vulnerable.c")])
        )
        assert a.value == b.value


class TestRuntimeFiltering:
    def test_libc_frames_are_filtered(self) -> None:
        fp = CrashFingerprinter()
        user_frame = _frame(0, "main")
        libc_frame = _frame(
            1,
            "__libc_start_main",
            file="/build/glibc-2.35/csu/libc-start.c",
            line=308,
        )

        a = fp.fingerprint(_asan_report(stack=[user_frame, libc_frame]))
        b = fp.fingerprint(_asan_report(stack=[user_frame]))
        assert a.value == b.value

    def test_sanitizer_internal_frames_are_filtered(self) -> None:
        fp = CrashFingerprinter()
        user_frame = _frame(0, "main")
        sanitizer_frame = _frame(
            1, "__asan_memcpy", file="/src/llvm-project/compiler-rt/asan.c", line=42
        )

        a = fp.fingerprint(_asan_report(stack=[user_frame, sanitizer_frame]))
        b = fp.fingerprint(_asan_report(stack=[user_frame]))
        assert a.value == b.value

    def test_filtering_can_be_disabled(self) -> None:
        fp = CrashFingerprinter(FingerprintConfig(filter_runtime_frames=False))
        user_frame = _frame(0, "main")
        libc_frame = _frame(1, "__libc_start_main", file="/csu/libc-start.c", line=308)
        a = fp.fingerprint(_asan_report(stack=[user_frame, libc_frame]))
        b = fp.fingerprint(_asan_report(stack=[user_frame]))
        assert a.value != b.value


class TestStackDepth:
    def test_stack_depth_limits_how_many_frames_matter(self) -> None:
        report_a = _asan_report(
            stack=[_frame(0, "main"), _frame(1, "helper")]
        )
        report_b = _asan_report(
            stack=[_frame(0, "main"), _frame(1, "completely_different")]
        )

        depth_1 = CrashFingerprinter(FingerprintConfig(stack_depth=1))
        depth_2 = CrashFingerprinter(FingerprintConfig(stack_depth=2))

        assert depth_1.fingerprint(report_a).value == depth_1.fingerprint(report_b).value
        assert depth_2.fingerprint(report_a).value != depth_2.fingerprint(report_b).value


class TestAuxiliaryStacks:
    def test_free_and_alloc_stacks_distinguish_uafs(self) -> None:
        common_free = [_frame(0, "free_site")]
        alloc_a = [_frame(0, "alloc_a")]
        alloc_b = [_frame(0, "alloc_b")]

        report_a = _asan_report(
            error_type="heap-use-after-free",
            free_site=common_free,
            alloc_site=alloc_a,
        )
        report_b = _asan_report(
            error_type="heap-use-after-free",
            free_site=common_free,
            alloc_site=alloc_b,
        )

        fp = CrashFingerprinter()
        assert fp.fingerprint(report_a).value != fp.fingerprint(report_b).value

    def test_auxiliary_stacks_can_be_disabled(self) -> None:
        common_free = [_frame(0, "free_site")]
        report_a = _asan_report(
            error_type="heap-use-after-free",
            free_site=common_free,
            alloc_site=[_frame(0, "alloc_a")],
        )
        report_b = _asan_report(
            error_type="heap-use-after-free",
            free_site=common_free,
            alloc_site=[_frame(0, "alloc_b")],
        )

        fp = CrashFingerprinter(
            FingerprintConfig(include_auxiliary_stacks=False)
        )
        assert fp.fingerprint(report_a).value == fp.fingerprint(report_b).value


class TestSignalOnly:
    def test_signal_only_fingerprint_is_deterministic(self) -> None:
        report_a = CrashReport(signal_number=11, signal_name="SIGSEGV")
        report_b = CrashReport(signal_number=11, signal_name="SIGSEGV")
        fp = CrashFingerprinter()
        assert fp.fingerprint(report_a).value == fp.fingerprint(report_b).value

    def test_different_signals_differ(self) -> None:
        fp = CrashFingerprinter()
        a = fp.fingerprint(CrashReport(signal_number=11, signal_name="SIGSEGV"))
        b = fp.fingerprint(CrashReport(signal_number=6, signal_name="SIGABRT"))
        assert a.value != b.value


class TestCanonicalString:
    def test_canonical_contains_expected_components(self) -> None:
        report = _asan_report(stack=[_frame(0, "main")])
        fp = CrashFingerprinter().fingerprint(report)
        assert "sanitizer=address" in fp.canonical
        assert "error_type=heap-buffer-overflow" in fp.canonical
        assert "fn=main" in fp.canonical

    def test_config_validation(self) -> None:
        import pytest

        with pytest.raises(ValueError):
            FingerprintConfig(stack_depth=0)
        with pytest.raises(ValueError):
            FingerprintConfig(stack_depth=1000)
        with pytest.raises(ValueError):
            FingerprintConfig(truncate_to=2)
