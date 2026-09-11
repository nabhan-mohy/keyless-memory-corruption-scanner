"""Honggfuzz adapter.

The adapter launches ``honggfuzz`` with the documented command-line shape and
preserves its output.  Honggfuzz does **not** write an AFL++-style
``fuzzer_stats`` file, and its progress output is a live status line rather than
a stable machine-readable stream.  KMCS therefore refuses to parse it and
returns an empty :class:`FuzzerStats` that names the log file to inspect.

This is honest behaviour, not a placeholder: the fuzzer runs, its evidence is
preserved, and any researcher can read the log.  A structured parser can be
added later without changing the interface.
"""

from __future__ import annotations

from typing import ClassVar

from kmcs.core.models import FuzzerKind
from kmcs.fuzzers.base import (
    FuzzerAdapter,
    FuzzerAvailability,
    FuzzerStats,
)
from kmcs.targets.detector import EnvironmentDetector

__all__ = ["HonggfuzzAdapter"]


class HonggfuzzAdapter(FuzzerAdapter):
    kind: ClassVar[FuzzerKind] = FuzzerKind.HONGFUZZ

    # ------------------------------------------------------------------ availability

    @classmethod
    def check_availability(cls, detector: EnvironmentDetector) -> FuzzerAvailability:
        report = detector.detect_all(["honggfuzz"])
        info = report.get("honggfuzz")

        if info is None or not info.available:
            return FuzzerAvailability(
                fuzzer=cls.kind,
                available=False,
                reason=info.error if info else "honggfuzz not found on $PATH",
            )

        return FuzzerAvailability(
            fuzzer=cls.kind,
            available=True,
            binary=info.path,
            version=info.version,
            reason=(
                "honggfuzz statistics are not parsed by KMCS; inspect the "
                "captured log file for live progress"
            ),
        )

    # ------------------------------------------------------------------ planning

    def plan(self) -> tuple[list[str], dict[str, str]]:
        env = self._base_environment()

        command: list[str] = [
            "honggfuzz",
            "-i", str(self._config.input_dir),
            "-o", str(self._config.output_dir),
            "-n", str(self._config.workers),
            "--",
            str(self._config.target_binary),
        ]

        # Honggfuzz uses ``___FILE___`` for file-based harnesses; otherwise it
        # forwards stdin.  KMCS does not attempt to guess which mode the target
        # uses — the caller passes the placeholder via ``extra_args`` if needed.
        command += list(self._config.extra_args)

        if self._config.duration_seconds is not None:
            command += ["-t", str(self._config.duration_seconds)]

        command += list(self._config.target_args)
        return command, env

    # ------------------------------------------------------------------ stats

    def stats(self) -> FuzzerStats:
        return FuzzerStats.unavailable(
            f"honggfuzz: no machine-readable statistics source; see {self._log_path}"
        )
