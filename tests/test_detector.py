"""Environment detection uses only real system checks."""

from __future__ import annotations

from kmcs.targets.detector import (
    EnvironmentDetector,
    ToolCategory,
    ToolNotFoundError,
    KNOWN_TOOLS,
)


def _fake_which(paths: dict[str, str]):
    def which(name: str) -> str | None:
        return paths.get(name)

    return which


def _fake_runner(responses: dict[str, tuple[int, str, str]]):
    """Return a runner keyed on the first element of the argv it sees."""

    def runner(cmd: list[str], timeout: float) -> tuple[int, str, str]:
        return responses.get(cmd[0], (0, "", ""))

    return runner


class TestDetection:
    def test_missing_tool_is_reported_unavailable(self) -> None:
        detector = EnvironmentDetector(which=_fake_which({}), runner=_fake_runner({}))
        info = detector.detect("clang")

        assert info.available is False
        assert info.path is None
        assert "not found" in (info.error or "")

    def test_present_tool_reads_a_version_string(self) -> None:
        detector = EnvironmentDetector(
            which=_fake_which({"clang": "/usr/bin/clang"}),
            runner=_fake_runner(
                {"/usr/bin/clang": (0, "Ubuntu clang version 17.0.6\n", "")}
            ),
        )
        info = detector.detect("clang")

        assert info.available is True
        assert info.path == "/usr/bin/clang"
        assert info.version == "Ubuntu clang version 17.0.6"

    def test_version_from_stderr_is_accepted(self) -> None:
        """gdb and other tools print --version to stderr on some systems."""
        detector = EnvironmentDetector(
            which=_fake_which({"gdb": "/usr/bin/gdb"}),
            runner=_fake_runner(
                {"/usr/bin/gdb": (0, "", "GNU gdb (Ubuntu 14.1) 14.1\n")}
            ),
        )
        info = detector.detect("gdb")

        assert info.available is True
        assert info.version == "GNU gdb (Ubuntu 14.1) 14.1"

    def test_which_exception_is_swallowed(self) -> None:
        def broken_which(_name: str) -> str | None:
            raise RuntimeError("which exploded")

        detector = EnvironmentDetector(which=broken_which, runner=_fake_runner({}))
        info = detector.detect("clang")

        assert info.available is False
        assert "which() failed" in (info.error or "")

    def test_unknown_tool_name_is_reported(self) -> None:
        detector = EnvironmentDetector(which=_fake_which({}), runner=_fake_runner({}))
        info = detector.detect("no-such-tool")

        assert info.available is False
        assert "Unknown tool" in (info.error or "")


class TestReport:
    def test_detect_all_returns_an_entry_per_known_tool(self) -> None:
        detector = EnvironmentDetector(which=_fake_which({}), runner=_fake_runner({}))
        report = detector.detect_all()

        for spec in KNOWN_TOOLS:
            assert spec.name in report.tools

    def test_require_raises_for_a_missing_tool(self) -> None:
        detector = EnvironmentDetector(which=_fake_which({}), runner=_fake_runner({}))
        report = detector.detect_all(["clang"])

        try:
            report.require("clang")
        except ToolNotFoundError as exc:
            assert "clang" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected ToolNotFoundError")

    def test_require_returns_available_tool(self) -> None:
        detector = EnvironmentDetector(
            which=_fake_which({"clang": "/usr/bin/clang"}),
            runner=_fake_runner({"/usr/bin/clang": (0, "clang 17\n", "")}),
        )
        report = detector.detect_all(["clang"])
        info = report.require("clang")

        assert info.path == "/usr/bin/clang"

    def test_by_category(self) -> None:
        detector = EnvironmentDetector(
            which=_fake_which({"clang": "/usr/bin/clang"}),
            runner=_fake_runner({"/usr/bin/clang": (0, "clang 17\n", "")}),
        )
        report = detector.detect_category(ToolCategory.COMPILER)

        assert report.available("clang")
        assert not report.available("gcc")

    def test_to_dict_is_serialisable(self) -> None:
        import json

        detector = EnvironmentDetector(which=_fake_which({}), runner=_fake_runner({}))
        report = detector.detect_all(["clang"])
        json.dumps(report.to_dict())  # must not raise


class TestRealSystem:
    """These call the real system.  They must not assert tool presence."""

    def test_real_detection_does_not_crash(self) -> None:
        detector = EnvironmentDetector()
        report = detector.detect_all(["cc", "gcc", "clang", "make"])

        # Any combination of present/absent is fine; the point is that no
        # exception escapes and every entry has a coherent shape.
        for info in report.tools.values():
            assert info.name
            if info.available:
                assert info.path
            else:
                assert info.error
