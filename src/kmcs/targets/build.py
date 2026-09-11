"""Real compiler invocation.

The build manager knows three things:

1. how to choose a compiler (user override, fuzzer-specific wrapper, clang, gcc),
2. how to translate a :class:`BuildConfiguration` and a list of sanitizers into
   real ``-fsanitize=...`` flags and AFL++ environment variables,
3. how to run that command and preserve the complete output.

It does not invent build results.  A build succeeds only when the compiler's
exit status is zero and the output file exists on disk.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kmcs.core.exceptions import KMCSException
from kmcs.core.models import BuildConfiguration, FuzzerKind, SanitizerKind
from kmcs.targets.detector import EnvironmentDetector, EnvironmentReport

logger = logging.getLogger(__name__)

__all__ = [
    "BuildError",
    "BuildRequest",
    "BuildResult",
    "BuildManager",
]


class BuildError(KMCSException):
    exit_code = 13


# (cmd, env, cwd, timeout) -> (returncode, stdout, stderr).  Never raises.
BuildRunner = Callable[[list[str], Mapping[str, str], Path, float], tuple[int, str, str]]


_SANITIZER_FLAGS: dict[SanitizerKind, tuple[str, ...]] = {
    SanitizerKind.ADDRESS: ("-fsanitize=address",),
    SanitizerKind.UNDEFINED: ("-fsanitize=undefined",),
    SanitizerKind.LEAK: ("-fsanitize=leak",),
    SanitizerKind.MEMORY: ("-fsanitize=memory",),
    SanitizerKind.THREAD: ("-fsanitize=thread",),
}

_SANITIZER_AFL_ENV: dict[SanitizerKind, str] = {
    SanitizerKind.ADDRESS: "AFL_USE_ASAN",
    SanitizerKind.UNDEFINED: "AFL_USE_UBSAN",
    SanitizerKind.LEAK: "AFL_USE_LSAN",
    SanitizerKind.MEMORY: "AFL_USE_MSAN",
    SanitizerKind.THREAD: "AFL_USE_TSAN",
}


@dataclass(slots=True)
class BuildRequest:
    """Everything the build manager needs, with no hidden defaults."""

    sources: list[Path]
    output: Path
    configuration: BuildConfiguration = BuildConfiguration.DEBUG
    sanitizers: list[SanitizerKind] = field(default_factory=list)
    compiler: str | None = None
    cflags: list[str] = field(default_factory=list)
    ldflags: list[str] = field(default_factory=list)
    defines: list[str] = field(default_factory=list)
    include_dirs: list[Path] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)
    environment: dict[str, str] = field(default_factory=dict)
    working_directory: Path | None = None
    for_fuzzer: FuzzerKind | None = None
    timeout_seconds: float = 300.0


@dataclass(slots=True)
class BuildResult:
    success: bool
    command: list[str]
    environment: dict[str, str]
    returncode: int
    stdout: str
    stderr: str
    output_path: Path
    output_exists: bool
    duration_seconds: float
    compiler: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "command": list(self.command),
            "returncode": self.returncode,
            "output_path": str(self.output_path),
            "output_exists": self.output_exists,
            "duration_seconds": self.duration_seconds,
            "compiler": self.compiler,
            # stdout / stderr are intentionally included in full; KMCS never
            # discards raw evidence in favour of a summary.
            "stdout": self.stdout,
            "stderr": self.stderr,
        }


def _default_build_runner(
    cmd: list[str],
    env: Mapping[str, str],
    cwd: Path,
    timeout: float,
) -> tuple[int, str, str]:
    """Run ``cmd`` with the given environment.  Never raises."""
    try:
        completed = subprocess.run(
            cmd,
            env=dict(env),
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout or "", completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return -1, stdout, stderr or f"build timed out after {timeout}s"
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return -1, "", str(exc)


class BuildManager:
    """Compiles target sources with the requested configuration."""

    def __init__(
        self,
        detector: EnvironmentDetector,
        *,
        runner: BuildRunner | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self._detector = detector
        self._runner = runner or _default_build_runner
        # Base environment; per-request environment is layered on top.
        self._environment: dict[str, str] = dict(environment or {})

    # ------------------------------------------------------------------ compiler

    def select_compiler(
        self,
        request: BuildRequest,
        report: EnvironmentReport | None = None,
    ) -> str:
        """Return the compiler path to use, or raise :class:`BuildError`."""
        if request.compiler:
            resolved = shutil.which(request.compiler) or (
                request.compiler if Path(request.compiler).is_file() else None
            )
            if resolved is None:
                raise BuildError(
                    "Requested compiler was not found",
                    details={"compiler": request.compiler},
                )
            return resolved

        report = report or self._detector.detect_all()

        candidates: list[str] = []
        if request.for_fuzzer is FuzzerKind.AFLPP:
            # AFL++ wrapper preferred: it injects coverage instrumentation.
            candidates.extend(["afl-clang-fast", "afl-clang-lto", "afl-gcc"])
        if request.for_fuzzer is FuzzerKind.LIBFUZZER:
            candidates.extend(["clang", "clang++"])
        candidates.extend(["clang", "gcc", "cc"])

        for name in candidates:
            info = report.get(name)
            if info is not None and info.available and info.path:
                return info.path

        raise BuildError(
            "No usable C compiler was found",
            details={"candidates": candidates},
        )

    # ------------------------------------------------------------------ planning

    def plan(
        self,
        request: BuildRequest,
        *,
        report: EnvironmentReport | None = None,
    ) -> tuple[list[str], dict[str, str]]:
        """Build the command line and environment without executing anything.

        Exposed publicly so tests and the CLI can inspect exactly what KMCS
        would run.
        """
        if not request.sources:
            raise BuildError("Build request contains no source files")

        missing = [str(path) for path in request.sources if not path.is_file()]
        if missing:
            raise BuildError(
                "One or more source files do not exist",
                details={"missing": missing},
            )

        compiler = self.select_compiler(request, report)

        cflags: list[str] = []
        ldflags: list[str] = []
        env: dict[str, str] = dict(os.environ)
        env.update(self._environment)
        env.update(request.environment)

        # --- configuration-specific flags ------------------------------------
        if request.configuration is BuildConfiguration.DEBUG:
            cflags.extend(["-g", "-O0", "-fno-omit-frame-pointer"])
        elif request.configuration is BuildConfiguration.RELEASE:
            cflags.extend(["-O2", "-g"])
        elif request.configuration is BuildConfiguration.COVERAGE:
            # clang/gcc branch and edge coverage; AFL++ adds its own when its
            # wrapper is used, and libFuzzer uses -fsanitize=fuzzer.
            cflags.extend(["-g", "-O1", "-fprofile-instr-generate",
                           "-fcoverage-mapping"])
        elif request.configuration in (
            BuildConfiguration.ASAN,
            BuildConfiguration.UBSAN,
            BuildConfiguration.ASAN_UBSAN,
        ):
            cflags.extend(["-g", "-O1", "-fno-omit-frame-pointer"])

        # --- sanitizer flags -------------------------------------------------
        for sanitizer in request.sanitizers:
            if sanitizer is SanitizerKind.NONE:
                continue
            cflags.extend(_SANITIZER_FLAGS.get(sanitizer, ()))
            ldflags.extend(_SANITIZER_FLAGS.get(sanitizer, ()))
            if request.for_fuzzer is FuzzerKind.AFLPP:
                var = _SANITIZER_AFL_ENV.get(sanitizer)
                if var:
                    env[var] = "1"

        # --- libFuzzer: the engine is linked into the binary -----------------
        if request.for_fuzzer is FuzzerKind.LIBFUZZER:
            cflags.append("-fsanitize=fuzzer")
            ldflags.append("-fsanitize=fuzzer")

        # --- caller-supplied extras -----------------------------------------
        cflags.extend(request.cflags)
        for define in request.defines:
            cflags.append(f"-D{define}")
        for include in request.include_dirs:
            cflags.append(f"-I{include}")

        ldflags.extend(request.ldflags)
        for library in request.libraries:
            ldflags.append(library)

        command: list[str] = [compiler, *cflags]
        command.extend(str(path) for path in request.sources)
        command.extend(ldflags)
        command.extend(["-o", str(request.output)])

        return command, env

    # ------------------------------------------------------------------ execution

    def build(
        self,
        request: BuildRequest,
        *,
        report: EnvironmentReport | None = None,
    ) -> BuildResult:
        """Compile the target and report exactly what happened."""
        report = report or self._detector.detect_all()
        command, env = self.plan(request, report=report)

        cwd = request.working_directory or request.output.parent
        cwd.mkdir(parents=True, exist_ok=True)
        request.output.parent.mkdir(parents=True, exist_ok=True)

        logger.info("Building target: %s", " ".join(command))
        started = time.monotonic()
        returncode, stdout, stderr = self._runner(
            command, env, cwd, request.timeout_seconds
        )
        duration = time.monotonic() - started

        output_exists = request.output.is_file()
        success = returncode == 0 and output_exists

        if not success:
            logger.warning(
                "Build failed (exit %d, output_exists=%s)", returncode, output_exists
            )
        else:
            logger.info("Build succeeded in %.2fs: %s", duration, request.output)

        return BuildResult(
            success=success,
            command=command,
            environment=env,
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            output_path=request.output,
            output_exists=output_exists,
            duration_seconds=duration,
            compiler=command[0],
        )
