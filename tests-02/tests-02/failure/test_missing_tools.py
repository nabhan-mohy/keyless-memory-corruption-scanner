"""Missing external tools must be reported, never faked."""

from __future__ import annotations

from kmcs.core.models import FuzzerKind, SanitizerKind
from kmcs.fuzzers import AFLPlusPlusAdapter, HonggfuzzAdapter, LibFuzzerAdapter
from kmcs.sanitizers import get_adapter
from kmcs.targets.build import BuildError, BuildManager, BuildRequest
from kmcs.targets.detector import EnvironmentDetector


class TestDetector:
    def test_no_tools_present(self) -> None:
        detector = EnvironmentDetector(
            which=lambda _name: None,
            runner=lambda _cmd, _timeout: (0, "", ""),
        )
        report = detector.detect_all(["clang", "gcc", "afl-fuzz", "gdb"])
        assert report.available_names() == []
        for info in report.tools.values():
            assert info.available is False
            assert info.error


class TestFuzzerAdapters:
    def test_aflpp_missing(self) -> None:
        detector = EnvironmentDetector(
            which=lambda _name: None,
            runner=lambda _cmd, _timeout: (0, "", ""),
        )
        availability = AFLPlusPlusAdapter.check_availability(detector)
        assert availability.available is False
        assert availability.reason

    def test_libfuzzer_missing(self) -> None:
        detector = EnvironmentDetector(
            which=lambda _name: None,
            runner=lambda _cmd, _timeout: (0, "", ""),
        )
        availability = LibFuzzerAdapter.check_availability(detector)
        assert availability.available is False

    def test_honggfuzz_missing(self) -> None:
        detector = EnvironmentDetector(
            which=lambda _name: None,
            runner=lambda _cmd, _timeout: (0, "", ""),
        )
        availability = HonggfuzzAdapter.check_availability(detector)
        assert availability.available is False


class TestBuildManager:
    def test_no_compiler_at_all(self, tmp_path) -> None:
        detector = EnvironmentDetector(
            which=lambda _name: None,
            runner=lambda _cmd, _timeout: (0, "", ""),
        )
        source = tmp_path / "in.c"
        source.write_text("int main(void){return 0;}\n")
        manager = BuildManager(detector)
        try:
            manager.build(BuildRequest(sources=[source], output=tmp_path / "out"))
        except BuildError as exc:
            assert "compiler" in str(exc).lower()
        else:
            raise AssertionError("expected BuildError")


class TestSanitizerAvailability:
    def test_no_compiler(self) -> None:
        detector = EnvironmentDetector(
            which=lambda _name: None,
            runner=lambda _cmd, _timeout: (0, "", ""),
        )
        adapter = get_adapter(SanitizerKind.ADDRESS)
        availability = adapter.availability(detector)
        assert availability.available is False
        assert availability.reason
