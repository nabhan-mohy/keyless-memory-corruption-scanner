"""Sanitizer adapter metadata and availability probes."""

from __future__ import annotations

from kmcs.core.models import SanitizerKind
from kmcs.sanitizers import all_adapters, get_adapter
from kmcs.sanitizers.asan import AddressSanitizerAdapter
from kmcs.sanitizers.lsan import LeakSanitizerAdapter
from kmcs.sanitizers.msan import MemorySanitizerAdapter
from kmcs.sanitizers.tsan import ThreadSanitizerAdapter
from kmcs.sanitizers.ubsan import UndefinedBehaviorSanitizerAdapter
from kmcs.targets.detector import EnvironmentDetector


class TestRegistry:
    def test_all_expected_adapters_are_registered(self) -> None:
        kinds = {adapter.spec.kind for adapter in all_adapters()}
        assert kinds == {
            SanitizerKind.ADDRESS,
            SanitizerKind.UNDEFINED,
            SanitizerKind.LEAK,
            SanitizerKind.MEMORY,
            SanitizerKind.THREAD,
        }

    def test_get_adapter_returns_the_right_class(self) -> None:
        assert get_adapter(SanitizerKind.ADDRESS) is AddressSanitizerAdapter
        assert get_adapter(SanitizerKind.UNDEFINED) is UndefinedBehaviorSanitizerAdapter
        assert get_adapter(SanitizerKind.LEAK) is LeakSanitizerAdapter
        assert get_adapter(SanitizerKind.MEMORY) is MemorySanitizerAdapter
        assert get_adapter(SanitizerKind.THREAD) is ThreadSanitizerAdapter


class TestMetadata:
    def test_each_adapter_has_a_spec_with_flags_and_patterns(self) -> None:
        for adapter in all_adapters():
            spec = adapter.spec
            assert spec.compiler_flags, spec.name
            assert spec.linker_flags, spec.name
            assert spec.runtime_env_var, spec.name
            assert spec.error_pattern is not None, spec.name

    def test_asan_afl_env_var(self) -> None:
        assert AddressSanitizerAdapter.afl_env_var() == "AFL_USE_ASAN"

    def test_ubsan_does_not_detect_heap_overflow(self) -> None:
        # Sanity: UBSan's pattern must not match an ASan-style line.
        assert not UndefinedBehaviorSanitizerAdapter.matches_report_line(
            "==12345==ERROR: AddressSanitizer: heap-buffer-overflow"
        )
        assert UndefinedBehaviorSanitizerAdapter.matches_report_line(
            "file.c:1:2: runtime error: signed integer overflow"
        )

    def test_asan_pattern_matches_header_and_summary(self) -> None:
        assert AddressSanitizerAdapter.matches_report_line(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x..."
        )
        assert AddressSanitizerAdapter.matches_report_line(
            "SUMMARY: AddressSanitizer: heap-buffer-overflow file:1 in func"
        )


class TestOptionsEnvironment:
    def test_asan_environment_appends_to_existing(self) -> None:
        env = AddressSanitizerAdapter.build_environment(
            {"ASAN_OPTIONS": "existing=1"}, abort_on_error=False
        )
        assert env["ASAN_OPTIONS"].startswith("existing=1:")
        assert "abort_on_error=0" in env["ASAN_OPTIONS"]

    def test_asan_environment_creates_when_absent(self) -> None:
        env = AddressSanitizerAdapter.build_environment({}, symbolize=False)
        assert "symbolize=0" in env["ASAN_OPTIONS"]

    def test_ubsan_environment_does_not_touch_asan(self) -> None:
        env = UndefinedBehaviorSanitizerAdapter.build_environment(
            {"ASAN_OPTIONS": "abort_on_error=1"}
        )
        assert env["ASAN_OPTIONS"] == "abort_on_error=1"
        assert "UBSAN_OPTIONS" in env


class TestAvailabilityProbeWithFakeDetector:
    def test_probe_reports_unavailable_without_a_compiler(self) -> None:
        detector = EnvironmentDetector(
            which=lambda _: None,
            runner=lambda cmd, t: (0, "", ""),
        )
        result = AddressSanitizerAdapter.availability(detector)
        assert result.available is False
        assert "No C compiler" in (result.reason or "")


class TestAvailabilityProbeReal:
    """Uses the real toolchain.  Must not fail on systems with no compiler."""

    def test_asan_availability_does_not_crash(self) -> None:
        detector = EnvironmentDetector()
        result = AddressSanitizerAdapter.availability(detector, timeout=20.0)
        # Either available or unavailable, but always with a coherent shape.
        if not result.available:
            assert result.reason
