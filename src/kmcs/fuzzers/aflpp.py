"""AFL++ adapter.

Launches ``afl-fuzz`` against a target and reads the ``fuzzer_stats`` file that
AFL++ itself writes.  ...
"""

from __future__ import annotations

import logging
import re                     # <-- add this if missing
from pathlib import Path
from typing import Any, ClassVar

from kmcs.core.models import FuzzerKind
from kmcs.fuzzers.base import (
    FuzzerAdapter,
    FuzzerAvailability,
    FuzzerError,
    FuzzerStats,
)
from kmcs.targets.detector import EnvironmentDetector

logger = logging.getLogger(__name__)

__all__ = ["AFLPlusPlusAdapter"]


class AFLPlusPlusAdapter(FuzzerAdapter):
    kind: ClassVar[FuzzerKind] = FuzzerKind.AFLPP

    # ------------------------------------------------------------------ availability

    @classmethod
    def check_availability(cls, detector: EnvironmentDetector) -> FuzzerAvailability:
        report = detector.detect_all(["afl-fuzz", "afl-clang-fast", "afl-gcc"])
        afl_fuzz = report.get("afl-fuzz")

        if afl_fuzz is None or not afl_fuzz.available:
            return FuzzerAvailability(
                fuzzer=cls.kind,
                available=False,
                reason=(afl_fuzz.error if afl_fuzz else "afl-fuzz not found on $PATH"),
            )

        wrapper = report.get("afl-clang-fast") or report.get("afl-gcc")
        reason = None
        if wrapper is None or not wrapper.available:
            reason = (
                "afl-fuzz is present, but no AFL++ compiler wrapper "
                "(afl-clang-fast / afl-gcc) was found; targets cannot be "
                "instrumented for coverage"
            )

        return FuzzerAvailability(
            fuzzer=cls.kind,
            available=True,
            binary=afl_fuzz.path,
            version=afl_fuzz.version,
            reason=reason,
        )

    # ------------------------------------------------------------------ planning

    def plan(self) -> tuple[list[str], dict[str, str]]:
        env = self._base_environment()
        env["AFL_NO_UI"] = "1"
        env["AFL_SKIP_CPUFREQ"] = "1"
        env["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"

        # Uninstrumented binaries cannot run AFL++'s fork server.  Detect this
        # and switch AFL++ into dumb mode automatically so that the campaign
        # works regardless of how the target was built.
        instrumented = self._is_afl_instrumented()
        if not instrumented:
            env["AFL_SKIP_BIN_CHECK"] = "1"
            env["AFL_DUMB_FORKSRV"] = "1"

        command: list[str] = [
            "afl-fuzz",
            "-i", str(self._config.input_dir),
            "-o", str(self._config.output_dir),
        ]

        if not instrumented:
            # ``-n`` tells AFL++ to run the target as a plain subprocess
            # instead of trying the fork-server handshake.
            command.append("-n")

        if self._config.duration_seconds is not None:
            command += ["-V", str(self._config.duration_seconds)]

        command += ["-t", f"{int(self._config.timeout_seconds * 1000)}"]

        if self._config.memory_limit_mb is not None:
            command += ["-m", str(self._config.memory_limit_mb)]

        command += list(self._config.extra_args)
        command.append("--")
        command.append(str(self._config.target_binary))
        command += list(self._config.target_args)

        return command, env

    # ------------------------------------------------------------------ stats

    def _stats_file(self) -> Path | None:
        """Locate the file AFL++ writes for this instance.

        Recent AFL++ uses ``<output>/default/fuzzer_stats``; older versions
        wrote ``<output>/fuzzer_stats`` directly.  Both are checked, in that
        order.
        """
        candidates = [
            self._config.output_dir / "default" / "fuzzer_stats",
            self._config.output_dir / "fuzzer_stats",
        ]
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        return None

    _STATS_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

    @classmethod
    def _parse_fuzzer_stats(cls, text: str) -> dict[str, str]:
        """Parse an AFL++ ``fuzzer_stats`` file.

        Only lines whose key is a single alphanumeric token are accepted.  A
        malformed file whose content happens to contain a colon is therefore
        treated as containing no usable key:value pairs.
        """
        parsed: dict[str, str] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key = key.strip()
            if not cls._STATS_KEY_RE.match(key):
                continue
            parsed[key] = value.strip()
        return parsed

    def stats(self) -> FuzzerStats:
        stats_file = self._stats_file()
        if stats_file is None:
            return FuzzerStats.unavailable(
                "afl++: fuzzer_stats not present yet (instance may not have started)"
            )

        try:
            text = stats_file.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return FuzzerStats.unavailable(f"afl++: unreadable fuzzer_stats ({exc})")

        raw = self._parse_fuzzer_stats(text)
        if not raw:
            return FuzzerStats.unavailable(
                f"afl++: fuzzer_stats at {stats_file} contains no key:value pairs"
            )

        def _int(key: str) -> int | None:
            value = raw.get(key)
            if value is None:
                return None
            try:
                return int(float(value))
            except ValueError:
                return None

        def _float(key: str) -> float | None:
            value = raw.get(key)
            if value is None:
                return None
            try:
                return float(value)
            except ValueError:
                return None

        # AFL++ stores a start/last_update pair in seconds.  We compute runtime
        # ourselves rather than trusting a computed field, since the file
        # format has changed across versions.
        runtime = None
        start = _float("start_time")
        last = _float("last_update")
        if start is not None and last is not None and last >= start:
            runtime = last - start

        # Coverage is reported by AFL++ either as ``bitmap_cvg`` (older) or
        # derived from ``edges_found``/``total_edges`` (newer).  We only emit a
        # value when one of those is present.
        coverage = None
        bitmap = raw.get("bitmap_cvg")
        if bitmap is not None:
            try:
                coverage = float(bitmap.rstrip("%"))
            except ValueError:
                coverage = None

        return FuzzerStats(
            source=f"afl++: {stats_file}",
            runtime_seconds=runtime,
            executions=_int("execs_done"),
            executions_per_second=_float("execs_per_sec"),
            corpus_count=_int("corpus_count"),
            crashes=_int("saved_crashes"),
            unique_crashes=_int("unique_crashes"),
            hangs=_int("saved_hangs"),
            coverage_percent=coverage,
            cycles_done=_int("cycles_done"),
            raw=raw,
        )

    # ------------------------------------------------------------------ detection

    def _is_afl_instrumented(self) -> bool:
        """Return True if the target binary was built with AFL++ instrumentation.

        AFL++ fuzzes instrumented binaries through a *fork server*; the fork
        server lives in ``afl-compiler-rt.o``, which is linked into every
        binary produced by ``afl-clang-fast`` / ``afl-clang-lto`` / ``afl-gcc``.
        An uninstrumented binary cannot speak that protocol, so AFL++ aborts
        with ``Fork server handshake failed`` unless told to use dumb mode.

        We detect instrumentation by looking for the AFL++ runtime symbol
        ``__afl_area_ptr``.  If ``nm`` is unavailable, we conservatively
        assume the binary is instrumented and let the user's environment
        decide.
        """
        import shutil
        import subprocess

        nm = shutil.which("nm")
        if nm is None:
            return True

        try:
            completed = subprocess.run(
                [nm, str(self._config.target_binary)],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return True

        return (
            "__afl_area_ptr" in completed.stdout
            or "__afl_prev_loc" in completed.stdout
        )


    # ------------------------------------------------------------------ artifacts

    def artifact_files(self) -> list[Path]:
        """Return crash files AFL++ has written so far.

        AFL++ writes crashes to ``<output>/default/crashes/`` in recent
        versions and ``<output>/crashes/`` in older ones.  Hangs live in
        ``<output>/default/hangs/``.  All three locations are checked.
        """
        candidates = [
            self._config.output_dir / "default" / "crashes",
            self._config.output_dir / "crashes",
            self._config.output_dir / "default" / "hangs",
        ]
        found: list[Path] = []
        for directory in candidates:
            if not directory.is_dir():
                continue
            for entry in directory.iterdir():
                if entry.is_file() and entry.name and not entry.name.startswith("."):
                    found.append(entry)
        return sorted(found)
