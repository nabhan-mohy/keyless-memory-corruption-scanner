"""libFuzzer adapter.

libFuzzer is linked *into* the target binary, not invoked as a separate tool.
The adapter therefore:

* checks that a C/C++ compiler and libFuzzer runtime are present,
* launches the instrumented target binary with ``-max_total_time=...``,
* parses the progress lines the runtime writes to stderr.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import ClassVar

from kmcs.core.models import FuzzerKind
from kmcs.fuzzers.base import (
    FuzzerAdapter,
    FuzzerAvailability,
    FuzzerStats,
)
from kmcs.targets.detector import EnvironmentDetector

__all__ = ["LibFuzzerAdapter"]


# libFuzzer progress line, e.g.:
#   #1024   NEW    cov: 123 ft: 456 corp: 20/1024b lim: 100 exec/s: 200 rss: 30Mb
#   #2048   DONE   cov: 200 ft: 500 corp: 30/2048b lim: 200 exec/s: 400 rss: 35Mb
_PROGRESS_RE = re.compile(
    r"^#(?P<runs>\d+)\s+"
    r"(?P<state>[A-Z_]+)?\s*"
    r"cov:\s*(?P<cov>\d+)\s+"
    r"ft:\s*(?P<ft>\d+)\s+"
    r"corp:\s*(?P<corp>\d+)(?:/(?P<corp_bytes>\d+)b)?"
    r"(?:\s+lim:\s*(?P<lim>\d+))?"
    r".*?"
    r"exec/s:\s*(?P<exec_s>\d+)",
)

# Final summary, e.g.: Done 1234567 runs in 30 second(s)
_DONE_RE = re.compile(
    r"Done\s+(?P<runs>\d+)\s+runs\s+in\s+(?P<seconds>\d+)\s+second",
)


class LibFuzzerAdapter(FuzzerAdapter):
    kind: ClassVar[FuzzerKind] = FuzzerKind.LIBFUZZER

    # ------------------------------------------------------------------ availability

    @classmethod
    def check_availability(cls, detector: EnvironmentDetector) -> FuzzerAvailability:
        report = detector.detect_all(["clang", "clang++"])
        clang = report.get("clang") or report.get("clang++")
        if clang is None or not clang.available:
            return FuzzerAvailability(
                fuzzer=cls.kind,
                available=False,
                reason=(
                    "libFuzzer requires a clang/clang++ compiler that provides "
                    "the -fsanitize=fuzzer runtime; neither was found on $PATH"
                ),
            )

        return FuzzerAvailability(
            fuzzer=cls.kind,
            available=True,
            binary=clang.path,
            version=clang.version,
            reason=(
                "libFuzzer is linked into the target; ensure the target was "
                "built with -fsanitize=fuzzer"
            ),
        )

    # ------------------------------------------------------------------ planning

    def plan(self) -> tuple[list[str], dict[str, str]]:
        env = self._base_environment()

        command: list[str] = [str(self._config.target_binary)]

        if self._config.duration_seconds is not None:
            command.append(f"-max_total_time={self._config.duration_seconds}")

        # libFuzzer expects a *per-input* timeout in seconds.
        command.append(f"-timeout={int(self._config.timeout_seconds)}")

        if self._config.memory_limit_mb is not None:
            command.append(f"-rss_limit_mb={self._config.memory_limit_mb}")

        # Preserve crashes next to the log rather than in the cwd.
        command.append(f"-artifact_prefix={self._config.output_dir}{'/'}")

        command += list(self._config.extra_args)

        # The corpus directory is a positional argument; libFuzzer will write
        # newly-discovered inputs back into it.
        command.append(str(self._config.input_dir))

        # Any arguments after the corpus belong to the target; KMCS forwards
        # ``target_args`` explicitly so ordering is unambiguous.
        command += list(self._config.target_args)

        return command, env

    # ------------------------------------------------------------------ stats

    def stats(self) -> FuzzerStats:
        text = self._read_log_text()
        if not text.strip():
            return FuzzerStats.unavailable(
                f"libfuzzer: {self._log_path} is empty or missing"
            )

        last_progress: re.Match[str] | None = None
        for line in text.splitlines():
            match = _PROGRESS_RE.match(line.strip())
            if match is not None:
                last_progress = match

        done_match: re.Match[str] | None = None
        for line in reversed(text.splitlines()):
            match = _DONE_RE.search(line)
            if match is not None:
                done_match = match
                break

        if last_progress is None and done_match is None:
            return FuzzerStats.unavailable(
                f"libfuzzer: no recognised progress lines in {self._log_path}"
            )

        executions: int | None = None
        corpus_count: int | None = None
        coverage_percent: float | None = None
        executions_per_second: float | None = None

        if last_progress is not None:
            executions = int(last_progress.group("runs"))
            corpus_count = int(last_progress.group("corp"))
            executions_per_second = float(last_progress.group("exec_s"))
            # libFuzzer's ``cov`` counts coverage points it has touched.  That
            # is not a percentage of the target, so KMCS reports it verbatim
            # rather than as a percentage.
            coverage_percent = float(last_progress.group("cov"))

        if done_match is not None:
            executions = int(done_match.group("runs"))

        runtime: float | None = None
        if done_match is not None:
            runtime = float(done_match.group("seconds"))

        raw: dict[str, str] = {}
        if last_progress is not None:
            raw["last_progress"] = last_progress.group(0)
        if done_match is not None:
            raw["done"] = done_match.group(0)

        return FuzzerStats(
            source=f"libfuzzer: {self._log_path}",
            runtime_seconds=runtime,
            executions=executions,
            executions_per_second=executions_per_second,
            corpus_count=corpus_count,
            coverage_percent=coverage_percent,
            raw=raw,
        )

    # ------------------------------------------------------------------ helpers

    def artifact_files(self) -> list[Path]:
        """Return real crash artifacts libFuzzer has written so far.

        libFuzzer names them ``crash-<hash>`` / ``oom-<hash>`` / ``timeout-<hash>``.
        """
        if not self._config.output_dir.is_dir():
            return []
        prefixes = ("crash-", "oom-", "timeout-", "leak-")
        return sorted(
            path
            for path in self._config.output_dir.iterdir()
            if path.is_file() and path.name.startswith(prefixes)
        )
