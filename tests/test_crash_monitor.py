"""The crash monitor runs real targets, preserves evidence, and reports facts."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from kmcs.analysis.crash_monitor import CrashMonitor, MonitorConfig, MonitorError


# ---------------------------------------------------------------------- helpers


def _write_script(path: Path, body: str) -> Path:
    """Write an executable POSIX shell script for the test."""
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture()
def work_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "work"
    directory.mkdir()
    return directory


# ---------------------------------------------------------------------- unit


class TestConfigValidation:
    def test_missing_target_is_rejected(self, work_dir: Path) -> None:
        config = MonitorConfig(target=work_dir / "no-such-binary")
        with pytest.raises(MonitorError):
            config.validate()

    def test_negative_timeout_is_rejected(self, tmp_path: Path) -> None:
        binary = _write_script(tmp_path / "ok", "#!/bin/sh\nexit 0\n")
        config = MonitorConfig(target=binary, timeout_seconds=0)
        with pytest.raises(MonitorError):
            config.validate()


# ---------------------------------------------------------------------- run


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell scripts")
class TestRunningRealTargets:
    def test_clean_exit_is_not_a_crash(self, tmp_path: Path) -> None:
        binary = _write_script(tmp_path / "clean", "#!/bin/sh\nexit 0\n")

        observation = CrashMonitor().run(
            MonitorConfig(target=binary), input_bytes=b""
        )

        assert observation.exit_code == 0
        assert observation.signal_number is None
        assert observation.crashed is False

    def test_sigsegv_is_detected(self, tmp_path: Path) -> None:
        # Kill ourselves with SIGSEGV.
        binary = _write_script(
            tmp_path / "segv", "#!/bin/sh\nkill -SEGV $$\n"
        )

        observation = CrashMonitor().run(
            MonitorConfig(target=binary, timeout_seconds=5.0), input_bytes=b""
        )

        assert observation.signal_number == 11
        assert observation.exit_code is None
        assert observation.report.signal_name == "SIGSEGV"
        assert observation.crashed is True

    def test_nonzero_exit_is_detected(self, tmp_path: Path) -> None:
        binary = _write_script(tmp_path / "abort", "#!/bin/sh\nexit 134\n")

        observation = CrashMonitor().run(
            MonitorConfig(target=binary), input_bytes=b""
        )

        assert observation.exit_code == 134
        assert observation.signal_number is None
        assert observation.crashed is True

    def test_timeout_kills_the_process(self, tmp_path: Path) -> None:
        binary = _write_script(tmp_path / "slow", "#!/bin/sh\nsleep 30\n")

        observation = CrashMonitor().run(
            MonitorConfig(target=binary, timeout_seconds=0.5), input_bytes=b""
        )

        assert observation.timed_out is True
        assert observation.crashed is True  # timeouts are reportable

    def test_stdin_input_is_written(self, tmp_path: Path) -> None:
        binary = _write_script(
            tmp_path / "echo", "#!/bin/sh\ncat > /dev/null\n"
        )
        observation = CrashMonitor().run(
            MonitorConfig(target=binary), input_bytes=b"hello world"
        )
        # The script consumed stdin cleanly; this proves the pipe worked.
        assert observation.exit_code == 0

    def test_argument_mode_passes_the_path(self, tmp_path: Path) -> None:
        binary = _write_script(
            tmp_path / "argcheck", '#!/bin/sh\ntest -f "$1" || exit 1\n'
        )
        input_file = tmp_path / "input.bin"
        input_file.write_bytes(b"payload")

        observation = CrashMonitor().run(
            MonitorConfig(target=binary, argument_input_path=True),
            input_path=input_file,
        )

        assert observation.exit_code == 0
        assert observation.command[-1] == str(input_file)

    def test_evidence_is_preserved_on_disk(self, tmp_path: Path) -> None:
        binary = _write_script(
            tmp_path / "noisy",
            "#!/bin/sh\necho 'to-stdout'\necho 'to-stderr' >&2\nexit 1\n",
        )
        evidence = tmp_path / "evidence"

        observation = CrashMonitor().run(
            MonitorConfig(target=binary, evidence_dir=evidence),
            input_bytes=b"",
        )

        assert observation.stdout_path.is_file()
        assert observation.stderr_path.is_file()
        assert "to-stdout" in observation.stdout
        assert "to-stderr" in observation.stderr
        assert observation.stdout_path.read_text() == observation.stdout
        assert observation.stderr_path.read_text() == observation.stderr

    def test_missing_execute_permission_is_reported(self, tmp_path: Path) -> None:
        binary = tmp_path / "noexec"
        binary.write_text("#!/bin/sh\nexit 0\n")
        binary.chmod(0o644)  # not executable

        with pytest.raises(MonitorError):
            CrashMonitor().run(
                MonitorConfig(target=binary), input_bytes=b""
            )

    def test_no_input_is_rejected(self, tmp_path: Path) -> None:
        binary = _write_script(tmp_path / "ok", "#!/bin/sh\nexit 0\n")
        with pytest.raises(MonitorError):
            CrashMonitor().run(MonitorConfig(target=binary))

    def test_argument_mode_requires_input_path(self, tmp_path: Path) -> None:
        binary = _write_script(tmp_path / "ok", "#!/bin/sh\nexit 0\n")
        with pytest.raises(MonitorError):
            CrashMonitor().run(
                MonitorConfig(target=binary, argument_input_path=True),
                input_bytes=b"",
            )

    def test_sanitizer_options_are_reported(self, tmp_path: Path) -> None:
        binary = _write_script(tmp_path / "ok", "#!/bin/sh\nexit 0\n")
        observation = CrashMonitor().run(
            MonitorConfig(
                target=binary,
                environment={"ASAN_OPTIONS": "abort_on_error=1"},
            ),
            input_bytes=b"",
        )
        assert observation.environment.get("ASAN_OPTIONS") == "abort_on_error=1"


# ---------------------------------------------------------------------- real ASan


@pytest.mark.integration
@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX signal semantics")
class TestRealASanCrash:
    """Build the demo target under ASan and detect the crash for real."""

    def test_detects_heap_buffer_overflow(self, tmp_path: Path) -> None:
        from kmcs.core.models import BuildConfiguration, SanitizerKind
        from kmcs.targets.build import BuildManager, BuildRequest
        from kmcs.targets.detector import EnvironmentDetector

        fixture = (
            Path(__file__).parent / "fixtures" / "demo_target" / "vulnerable.c"
        )
        assert fixture.is_file()

        detector = EnvironmentDetector()
        report = detector.detect_all(["clang", "gcc", "cc"])
        compiler = None
        for name in ("clang", "gcc", "cc"):
            info = report.get(name)
            if info is not None and info.available and info.path:
                compiler = info.path
                break
        if compiler is None:
            pytest.skip("no C compiler")

        binary = tmp_path / "demo"
        build_result = BuildManager(detector).build(
            BuildRequest(
                sources=[fixture],
                output=binary,
                compiler=compiler,
                configuration=BuildConfiguration.ASAN,
                sanitizers=[SanitizerKind.ADDRESS],
            )
        )
        assert build_result.success, build_result.stderr

        evidence = tmp_path / "evidence"
        from kmcs.sanitizers.asan import AddressSanitizerAdapter

        env = AddressSanitizerAdapter.build_environment(
            {},
            abort_on_error=True,
            symbolize=True,
        )

        observation = CrashMonitor().run(
            MonitorConfig(
                target=binary,
                timeout_seconds=10.0,
                evidence_dir=evidence,
                environment=env,
                expected_sanitizers=[SanitizerKind.ADDRESS],
            ),
            input_bytes=b"A" * 32,
        )

        assert observation.crashed is True
        assert observation.report.classification.value == "heap-buffer-overflow"

        # Evidence files exist and contain the sanitizer report.
        assert observation.stderr_path.is_file()
        text = observation.stderr_path.read_text(encoding="utf-8", errors="replace")
        assert "AddressSanitizer" in text
        assert "heap-buffer-overflow" in text
