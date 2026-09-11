"""Build manager: compiler selection, flag construction, real invocation."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from kmcs.core.models import BuildConfiguration, FuzzerKind, SanitizerKind
from kmcs.targets.build import BuildError, BuildManager, BuildRequest
from kmcs.targets.detector import EnvironmentDetector


def _detector_with(clang: bool = True, gcc: bool = False, afl: bool = False):
    paths: dict[str, str] = {}
    if clang:
        paths["clang"] = "/usr/bin/clang"
    if gcc:
        paths["gcc"] = "/usr/bin/gcc"
    if afl:
        paths["afl-clang-fast"] = "/usr/bin/afl-clang-fast"
        paths["afl-fuzz"] = "/usr/bin/afl-fuzz"

    def which(name: str) -> str | None:
        return paths.get(name)

    def runner(cmd: list[str], timeout: float) -> tuple[int, str, str]:
        return 0, f"{Path(cmd[0]).name} version test\n", ""

    return EnvironmentDetector(which=which, runner=runner)


class TestCompilerSelection:
    def test_explicit_compiler_path_wins(self, tmp_path: Path) -> None:
        fake_compiler = tmp_path / "mycc"
        fake_compiler.write_text("#!/bin/sh\n")
        fake_compiler.chmod(0o755)

        manager = BuildManager(_detector_with())
        request = BuildRequest(
            sources=[tmp_path / "in.c"],
            output=tmp_path / "out",
            compiler=str(fake_compiler),
        )

        assert manager.select_compiler(request) == str(fake_compiler)

    def test_missing_explicit_compiler_raises(self, tmp_path: Path) -> None:
        manager = BuildManager(_detector_with())
        request = BuildRequest(
            sources=[tmp_path / "in.c"],
            output=tmp_path / "out",
            compiler="definitely-not-a-real-compiler-xyz",
        )

        with pytest.raises(BuildError):
            manager.select_compiler(request)

    def test_afl_wrapper_is_preferred_for_afl_targets(self, tmp_path: Path) -> None:
        manager = BuildManager(_detector_with(clang=True, afl=True))
        request = BuildRequest(
            sources=[tmp_path / "in.c"],
            output=tmp_path / "out",
            for_fuzzer=FuzzerKind.AFLPP,
        )

        assert manager.select_compiler(request).endswith("afl-clang-fast")

    def test_falls_back_to_clang_when_nothing_else_exists(self, tmp_path: Path) -> None:
        manager = BuildManager(_detector_with(clang=True))
        request = BuildRequest(sources=[tmp_path / "in.c"], output=tmp_path / "out")

        assert manager.select_compiler(request).endswith("clang")

    def test_no_compiler_raises(self, tmp_path: Path) -> None:
        manager = BuildManager(_detector_with(clang=False, gcc=False))
        request = BuildRequest(sources=[tmp_path / "in.c"], output=tmp_path / "out")

        with pytest.raises(BuildError):
            manager.select_compiler(request)


class TestPlanning:
    def test_missing_sources_are_rejected(self, tmp_path: Path) -> None:
        manager = BuildManager(_detector_with())
        request = BuildRequest(sources=[], output=tmp_path / "out")
        with pytest.raises(BuildError):
            manager.plan(request)

    def test_nonexistent_source_file_is_reported(self, tmp_path: Path) -> None:
        manager = BuildManager(_detector_with())
        request = BuildRequest(
            sources=[tmp_path / "does-not-exist.c"], output=tmp_path / "out"
        )
        with pytest.raises(BuildError):
            manager.plan(request)

    def test_asan_adds_sanitizer_flags(self, tmp_path: Path) -> None:
        source = tmp_path / "in.c"
        source.write_text("int main(void){return 0;}\n")

        manager = BuildManager(_detector_with())
        request = BuildRequest(
            sources=[source],
            output=tmp_path / "out",
            configuration=BuildConfiguration.ASAN,
            sanitizers=[SanitizerKind.ADDRESS],
        )

        command, _ = manager.plan(request)
        joined = " ".join(command)
        assert "-fsanitize=address" in joined
        assert "-g" in joined
        assert "-fno-omit-frame-pointer" in joined

    def test_afl_uses_env_var_instead_of_flags_for_sanitizers(
        self, tmp_path: Path
    ) -> None:
        source = tmp_path / "in.c"
        source.write_text("int main(void){return 0;}\n")

        manager = BuildManager(_detector_with(clang=True, afl=True))
        request = BuildRequest(
            sources=[source],
            output=tmp_path / "out",
            for_fuzzer=FuzzerKind.AFLPP,
            sanitizers=[SanitizerKind.ADDRESS],
        )

        _, env = manager.plan(request)
        assert env.get("AFL_USE_ASAN") == "1"

    def test_libfuzzer_links_the_engine(self, tmp_path: Path) -> None:
        source = tmp_path / "in.c"
        source.write_text("int main(void){return 0;}\n")

        manager = BuildManager(_detector_with())
        request = BuildRequest(
            sources=[source],
            output=tmp_path / "out",
            for_fuzzer=FuzzerKind.LIBFUZZER,
        )

        command, _ = manager.plan(request)
        assert "-fsanitize=fuzzer" in command
        assert command.count("-fsanitize=fuzzer") == 2  # compile and link

    def test_user_flags_and_defines_are_appended(self, tmp_path: Path) -> None:
        source = tmp_path / "in.c"
        source.write_text("int main(void){return 0;}\n")

        manager = BuildManager(_detector_with())
        request = BuildRequest(
            sources=[source],
            output=tmp_path / "out",
            cflags=["-Wall"],
            defines=["DEBUG=1"],
            include_dirs=[tmp_path / "include"],
            libraries=["-lm"],
        )

        command, _ = manager.plan(request)
        joined = " ".join(command)
        assert "-Wall" in joined
        assert "-DDEBUG=1" in joined
        assert f"-I{tmp_path / 'include'}" in joined
        assert "-lm" in joined


class TestExecutionWithoutRealCompiler:
    def test_runner_failure_is_reported_as_unsuccessful(self, tmp_path: Path) -> None:
        source = tmp_path / "in.c"
        source.write_text("int main(void){return 0;}\n")

        def failing_runner(cmd, env, cwd, timeout):
            return 1, "", "error: something went wrong\n"

        manager = BuildManager(_detector_with(), runner=failing_runner)
        result = manager.build(
            BuildRequest(sources=[source], output=tmp_path / "out")
        )

        assert result.success is False
        assert result.returncode == 1
        assert "something went wrong" in result.stderr
        assert result.output_exists is False

    def test_runner_success_without_output_file_is_not_success(
        self, tmp_path: Path
    ) -> None:
        source = tmp_path / "in.c"
        source.write_text("int main(void){return 0;}\n")

        def silent_runner(cmd, env, cwd, timeout):
            return 0, "", ""  # no output file is ever created

        manager = BuildManager(_detector_with(), runner=silent_runner)
        result = manager.build(
            BuildRequest(sources=[source], output=tmp_path / "out")
        )

        assert result.success is False
        assert result.output_exists is False

    def test_result_dict_is_json_serialisable(self, tmp_path: Path) -> None:
        import json

        source = tmp_path / "in.c"
        source.write_text("int main(void){return 0;}\n")

        manager = BuildManager(
            _detector_with(),
            runner=lambda cmd, env, cwd, timeout: (0, "ok", ""),
        )
        result = manager.build(
            BuildRequest(sources=[source], output=tmp_path / "out")
        )
        json.dumps(result.to_dict())


@pytest.mark.integration
class TestRealBuild:
    """Compile the demo target with a real toolchain, if one is present."""

    def test_demo_target_compiles_and_crashes_under_asan(self, tmp_path: Path) -> None:
        fixture = Path(__file__).parent / "fixtures" / "demo_target" / "vulnerable.c"
        assert fixture.is_file()

        detector = EnvironmentDetector()
        report = detector.detect_all(["clang", "gcc", "cc"])

        if not any(report.available(name) for name in ("clang", "gcc", "cc")):
            pytest.skip("no C compiler on this system")

        manager = BuildManager(detector)
        output = tmp_path / "demo"

        compiler_name = "clang" if report.available("clang") else "gcc"
        request = BuildRequest(
            sources=[fixture],
            output=output,
            compiler=report.require(compiler_name).path,
            configuration=BuildConfiguration.ASAN,
            sanitizers=[SanitizerKind.ADDRESS],
        )

        result = manager.build(request)
        assert result.success, result.stderr
        assert result.output_exists

        # Real execution of the instrumented binary with a triggering input.
        import subprocess

        proc = subprocess.run(
            [str(output)],
            input=b"A" * 32,
            capture_output=True,
            timeout=10,
            check=False,
        )
        combined = (proc.stdout + proc.stderr).decode(errors="replace")

        # ASan exits with a non-zero code and prints a diagnostic.
        assert proc.returncode != 0
        assert "AddressSanitizer" in combined
        assert "heap-buffer-overflow" in combined
