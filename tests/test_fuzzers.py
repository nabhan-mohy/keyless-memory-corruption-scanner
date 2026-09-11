"""Fuzzer adapters: availability, planning, and stats parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from kmcs.core.models import FuzzerKind
from kmcs.fuzzers.aflpp import AFLPlusPlusAdapter
from kmcs.fuzzers.base import FuzzerConfig, FuzzerStatus
from kmcs.fuzzers.honggfuzz import HonggfuzzAdapter
from kmcs.fuzzers.libfuzzer import LibFuzzerAdapter
from kmcs.targets.detector import EnvironmentDetector


# ---------------------------------------------------------------------- helpers


def _detector(paths: dict[str, str]):
    def which(name: str) -> str | None:
        return paths.get(name)

    def runner(cmd: list[str], timeout: float) -> tuple[int, str, str]:
        return 0, f"{Path(cmd[0]).name} 1.0\n", ""

    return EnvironmentDetector(which=which, runner=runner)


@pytest.fixture()
def target_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "target"
    binary.write_bytes(b"\x7fELF-demo")  # not a real ELF, but a real file
    binary.chmod(0o755)
    return binary


@pytest.fixture()
def input_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "corpus"
    directory.mkdir()
    (directory / "seed").write_bytes(b"seed")
    return directory


@pytest.fixture()
def output_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "out"
    directory.mkdir()
    return directory


# ---------------------------------------------------------------------- AFL++


class TestAFLPlusPlus:
    def test_unavailable_without_afl_fuzz(self) -> None:
        availability = AFLPlusPlusAdapter.check_availability(_detector({}))
        assert availability.available is False
        assert availability.reason

    def test_available_but_flags_missing_wrapper(self) -> None:
        availability = AFLPlusPlusAdapter.check_availability(
            _detector({"afl-fuzz": "/usr/bin/afl-fuzz"})
        )
        assert availability.available is True
        assert availability.reason is not None
        assert "wrapper" in availability.reason

    def test_fully_available(self) -> None:
        availability = AFLPlusPlusAdapter.check_availability(
            _detector(
                {
                    "afl-fuzz": "/usr/bin/afl-fuzz",
                    "afl-clang-fast": "/usr/bin/afl-clang-fast",
                }
            )
        )
        assert availability.available is True
        assert availability.reason is None

    def test_plan_contains_required_arguments(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        adapter = AFLPlusPlusAdapter(
            FuzzerConfig(
                target_binary=target_binary,
                input_dir=input_dir,
                output_dir=output_dir,
                duration_seconds=30,
                timeout_seconds=2.0,
                memory_limit_mb=512,
            )
        )
        command, env = adapter.plan()

        assert command[0] == "afl-fuzz"
        assert "-i" in command and str(input_dir) in command
        assert "-o" in command and str(output_dir) in command
        assert "-V" in command and "30" in command
        assert "-t" in command and "2000" in command
        assert "-m" in command and "512" in command
        assert "--" in command
        assert str(target_binary) in command
        assert env["AFL_NO_UI"] == "1"
        assert env["AFL_SKIP_CPUFREQ"] == "1"

    def test_stats_unavailable_when_file_missing(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        adapter = AFLPlusPlusAdapter(
            FuzzerConfig(
                target_binary=target_binary, input_dir=input_dir, output_dir=output_dir
            )
        )
        stats = adapter.stats()

        assert stats.executions is None
        assert "not present" in stats.source

    def test_stats_parsed_from_default_layout(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        default = output_dir / "default"
        default.mkdir()
        (default / "fuzzer_stats").write_text(
            "start_time        : 1000\n"
            "last_update       : 1030\n"
            "fuzzer_pid        : 4242\n"
            "cycles_done       : 3\n"
            "execs_done        : 120000\n"
            "execs_per_sec     : 4000.5\n"
            "corpus_count      : 42\n"
            "saved_crashes     : 5\n"
            "saved_hangs       : 1\n"
            "bitmap_cvg        : 12.34%\n"
        )

        adapter = AFLPlusPlusAdapter(
            FuzzerConfig(
                target_binary=target_binary, input_dir=input_dir, output_dir=output_dir
            )
        )
        stats = adapter.stats()

        assert stats.executions == 120000
        assert stats.executions_per_second == 4000.5
        assert stats.corpus_count == 42
        assert stats.crashes == 5
        assert stats.hangs == 1
        assert stats.cycles_done == 3
        assert stats.runtime_seconds == pytest.approx(30.0)
        assert stats.coverage_percent == pytest.approx(12.34)
        assert "fuzzer_stats" in stats.source

    def test_stats_parsed_from_legacy_layout(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        (output_dir / "fuzzer_stats").write_text("execs_done: 100\nsaved_crashes: 0\n")

        adapter = AFLPlusPlusAdapter(
            FuzzerConfig(
                target_binary=target_binary, input_dir=input_dir, output_dir=output_dir
            )
        )
        stats = adapter.stats()

        assert stats.executions == 100
        assert stats.crashes == 0

    def test_malformed_stats_file_returns_unavailable(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        default = output_dir / "default"
        default.mkdir()
        (default / "fuzzer_stats").write_text("this is not key:value\n")

        adapter = AFLPlusPlusAdapter(
            FuzzerConfig(
                target_binary=target_binary, input_dir=input_dir, output_dir=output_dir
            )
        )
        stats = adapter.stats()

        assert stats.executions is None
        assert "no key:value pairs" in stats.source


# ---------------------------------------------------------------------- libFuzzer


class TestLibFuzzer:
    def test_unavailable_without_clang(self) -> None:
        availability = LibFuzzerAdapter.check_availability(_detector({}))
        assert availability.available is False
        assert "clang" in (availability.reason or "")

    def test_available_with_clang(self) -> None:
        availability = LibFuzzerAdapter.check_availability(
            _detector({"clang": "/usr/bin/clang"})
        )
        assert availability.available is True
        assert availability.binary == "/usr/bin/clang"

    def test_plan_uses_target_as_the_command(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        adapter = LibFuzzerAdapter(
            FuzzerConfig(
                target_binary=target_binary,
                input_dir=input_dir,
                output_dir=output_dir,
                duration_seconds=45,
                timeout_seconds=3.0,
                memory_limit_mb=256,
            )
        )
        command, _ = adapter.plan()

        assert command[0] == str(target_binary)
        joined = " ".join(command)
        assert "-max_total_time=45" in joined
        assert "-timeout=3" in joined
        assert "-rss_limit_mb=256" in joined
        assert f"-artifact_prefix={output_dir}/" in joined
        assert command[-1] == str(input_dir)

    def test_stats_unavailable_when_log_missing(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        adapter = LibFuzzerAdapter(
            FuzzerConfig(
                target_binary=target_binary, input_dir=input_dir, output_dir=output_dir
            )
        )
        stats = adapter.stats()
        assert "empty or missing" in stats.source

    def test_stats_parsed_from_progress_and_done_lines(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        log = output_dir / "libfuzzer.log"
        log.write_text(
            "INFO: Seed: 1\n"
            "INFO: seed corpus: files: 3 min: 1b max: 32b total: 96b rss: 25Mb\n"
            "#2      INITED cov: 10 ft: 12 corp: 3/96b exec/s: 0 rss: 25Mb\n"
            "#1024   NEW    cov: 128 ft: 256 corp: 42/1024b lim: 100 exec/s: 512 rss: 30Mb\n"
            "#2048   DONE   cov: 200 ft: 500 corp: 64/2048b lim: 200 exec/s: 1024 rss: 35Mb\n"
            "Done 2048 runs in 4 second(s)\n"
        )

        adapter = LibFuzzerAdapter(
            FuzzerConfig(
                target_binary=target_binary, input_dir=input_dir, output_dir=output_dir
            )
        )
        stats = adapter.stats()

        assert stats.executions == 2048  # Done line wins
        assert stats.corpus_count == 64  # last progress line
        assert stats.executions_per_second == 1024.0
        assert stats.coverage_percent == 200.0
        assert stats.runtime_seconds == 4.0
        assert "libfuzzer" in stats.source

    def test_stats_parsed_without_done_line(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        (output_dir / "libfuzzer.log").write_text(
            "#512     NEW    cov: 64 ft: 128 corp: 20/512b exec/s: 256 rss: 30Mb\n"
        )

        adapter = LibFuzzerAdapter(
            FuzzerConfig(
                target_binary=target_binary, input_dir=input_dir, output_dir=output_dir
            )
        )
        stats = adapter.stats()

        assert stats.executions == 512
        assert stats.runtime_seconds is None  # we did not have a Done line

    def test_unrecognised_log_returns_unavailable(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        (output_dir / "libfuzzer.log").write_text(
            "some unrelated output that no parser recognises\n"
        )

        adapter = LibFuzzerAdapter(
            FuzzerConfig(
                target_binary=target_binary, input_dir=input_dir, output_dir=output_dir
            )
        )
        stats = adapter.stats()
        assert "no recognised progress lines" in stats.source

    def test_artifact_files_are_listed(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        (output_dir / "crash-abc123").write_bytes(b"x")
        (output_dir / "timeout-def456").write_bytes(b"x")
        (output_dir / "unrelated").write_bytes(b"x")

        adapter = LibFuzzerAdapter(
            FuzzerConfig(
                target_binary=target_binary, input_dir=input_dir, output_dir=output_dir
            )
        )
        artifacts = [p.name for p in adapter.artifact_files()]

        assert "crash-abc123" in artifacts
        assert "timeout-def456" in artifacts
        assert "unrelated" not in artifacts


# ---------------------------------------------------------------------- honggfuzz


class TestHonggfuzz:
    def test_unavailable_without_binary(self) -> None:
        availability = HonggfuzzAdapter.check_availability(_detector({}))
        assert availability.available is False

    def test_available_when_installed(self) -> None:
        availability = HonggfuzzAdapter.check_availability(
            _detector({"honggfuzz": "/usr/bin/honggfuzz"})
        )
        assert availability.available is True
        assert availability.reason is not None  # stats caveat is stated

    def test_plan_builds_a_real_command(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        adapter = HonggfuzzAdapter(
            FuzzerConfig(
                target_binary=target_binary,
                input_dir=input_dir,
                output_dir=output_dir,
                duration_seconds=20,
                workers=2,
            )
        )
        command, _ = adapter.plan()

        assert command[0] == "honggfuzz"
        assert "-i" in command and str(input_dir) in command
        assert "-o" in command and str(output_dir) in command
        assert "-n" in command and "2" in command
        assert "--" in command
        assert str(target_binary) in command

    def test_stats_are_honest_about_being_unavailable(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        adapter = HonggfuzzAdapter(
            FuzzerConfig(
                target_binary=target_binary, input_dir=input_dir, output_dir=output_dir
            )
        )
        stats = adapter.stats()
        assert stats.executions is None
        assert "no machine-readable statistics source" in stats.source


# ---------------------------------------------------------------------- base


class TestFuzzerConfig:
    def test_missing_binary_is_rejected(self, input_dir: Path, output_dir: Path) -> None:
        config = FuzzerConfig(
            target_binary=Path("/nonexistent/binary"),
            input_dir=input_dir,
            output_dir=output_dir,
        )
        with pytest.raises(Exception):
            config.validate()

    def test_missing_input_dir_is_rejected(
        self, target_binary: Path, output_dir: Path
    ) -> None:
        config = FuzzerConfig(
            target_binary=target_binary,
            input_dir=Path("/nonexistent/corpus"),
            output_dir=output_dir,
        )
        with pytest.raises(Exception):
            config.validate()

    def test_zero_workers_is_rejected(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        config = FuzzerConfig(
            target_binary=target_binary,
            input_dir=input_dir,
            output_dir=output_dir,
            workers=0,
        )
        with pytest.raises(Exception):
            config.validate()

    def test_valid_config_passes(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        FuzzerConfig(
            target_binary=target_binary,
            input_dir=input_dir,
            output_dir=output_dir,
        ).validate()


class TestLifecycleWithoutRealEngine:
    def test_status_starts_as_not_started(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        adapter = LibFuzzerAdapter(
            FuzzerConfig(
                target_binary=target_binary, input_dir=input_dir, output_dir=output_dir
            )
        )
        assert adapter.status is FuzzerStatus.NOT_STARTED

    def test_stopping_a_never_started_adapter_is_safe(
        self, target_binary: Path, input_dir: Path, output_dir: Path
    ) -> None:
        adapter = LibFuzzerAdapter(
            FuzzerConfig(
                target_binary=target_binary, input_dir=input_dir, output_dir=output_dir
            )
        )
        adapter.stop()  # must not raise

    def test_start_with_missing_binary_fails_cleanly(
        self, input_dir: Path, output_dir: Path
    ) -> None:
        adapter = LibFuzzerAdapter(
            FuzzerConfig(
                target_binary=Path("/no/such/binary"),
                input_dir=input_dir,
                output_dir=output_dir,
            )
        )
        from kmcs.fuzzers.base import FuzzerError

        with pytest.raises(FuzzerError):
            adapter.start()
        assert adapter.status is FuzzerStatus.NOT_STARTED


@pytest.mark.integration
class TestRealAFLpp:
    def test_build_and_run_afl_for_a_few_seconds(self, tmp_path: Path) -> None:
        """End-to-end: build the demo target and let AFL++ actually fuzz it."""
        detector = EnvironmentDetector()
        availability = AFLPlusPlusAdapter.check_availability(detector)
        if not availability.available:
            pytest.skip(f"afl++ not available: {availability.reason}")

        compiler = detector.detect_all(["afl-clang-fast", "afl-gcc"])
        wrapper = None
        for name in ("afl-clang-fast", "afl-gcc"):
            info = compiler.get(name)
            if info is not None and info.available and info.path:
                wrapper = info.path
                break
        if wrapper is None:
            pytest.skip("no AFL++ compiler wrapper")

        fixture = Path(__file__).parent / "fixtures" / "demo_target" / "vulnerable.c"
        binary = tmp_path / "demo"

        from kmcs.core.models import BuildConfiguration, FuzzerKind, SanitizerKind
        from kmcs.targets.build import BuildManager, BuildRequest

        build_manager = BuildManager(detector)
        build_result = build_manager.build(
            BuildRequest(
                sources=[fixture],
                output=binary,
                compiler=wrapper,
                configuration=BuildConfiguration.ASAN,
                sanitizers=[SanitizerKind.ADDRESS],
                for_fuzzer=FuzzerKind.AFLPP,
            )
        )
        assert build_result.success, build_result.stderr

        corpus = tmp_path / "corpus"
        corpus.mkdir()
        (corpus / "seed").write_bytes(b"AAAA")

        output = tmp_path / "afl-out"

        adapter = AFLPlusPlusAdapter(
            FuzzerConfig(
                target_binary=binary,
                input_dir=corpus,
                output_dir=output,
                duration_seconds=5,
                timeout_seconds=2.0,
                memory_limit_mb=0,  # ASan needs "no limit" on some kernels
            )
        )

        adapter.start()
        try:
            import time

            time.sleep(5.0)
        finally:
            adapter.stop(timeout=15.0)

        # AFL++ must have created the fuzzer_stats file it always writes.
        stats = adapter.stats()
        assert stats.executions is not None
        assert stats.executions >= 0
        assert "fuzzer_stats" in stats.source
