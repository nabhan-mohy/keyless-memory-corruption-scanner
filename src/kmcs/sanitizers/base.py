"""Common sanitizer interface and registry.

A :class:`SanitizerSpec` describes one sanitizer completely:

* the compiler flags that enable it,
* the AFL++ environment variable that tells the fuzzer to use it,
* the runtime environment variable name it obeys,
* the patterns that identify its reports,
* and whether it is a "standalone" sanitizer (LSan, MSan, TSan) or one that
  augments AddressSanitizer's runtime.

The framework never *asserts* that a sanitizer works.  ``availability()``
performs a real compile-and-run probe and reports what actually happened.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

from kmcs.core.exceptions import KMCSException
from kmcs.core.models import SanitizerKind
from kmcs.targets.detector import EnvironmentDetector

logger = logging.getLogger(__name__)

__all__ = [
    "SanitizerError",
    "SanitizerUnavailableError",
    "SanitizerRuntimeError",
    "SanitizerSpec",
    "SanitizerAvailability",
    "SanitizerLogFormat",
    "SanitizerAdapter",
    "SanitizerRegistry",
    "get_adapter",
    "all_adapters",
]


class SanitizerError(KMCSException):
    exit_code = 30


class SanitizerUnavailableError(SanitizerError):
    exit_code = 31


class SanitizerRuntimeError(SanitizerError):
    exit_code = 32


class SanitizerLogFormat:
    """Known log-format families.

    Used by the crash parser to route a piece of text to the right reader.
    """

    ASAN = "asan"
    UBSAN = "ubsan"
    LSAN = "lsan"
    MSAN = "msan"
    TSAN = "tsan"


@dataclass(frozen=True, slots=True)
class SanitizerSpec:
    """Static description of one sanitizer."""

    kind: SanitizerKind
    name: str
    compiler_flags: tuple[str, ...]
    linker_flags: tuple[str, ...]
    runtime_env_var: str
    afl_env_var: str | None
    log_format: str
    error_pattern: re.Pattern[str]
    """Regex that matches the *first line* of a report from this sanitizer."""
    description: str
    standalone: bool = True
    """True when this sanitizer owns the whole process runtime."""


@dataclass(frozen=True, slots=True)
class SanitizerAvailability:
    kind: SanitizerKind
    available: bool
    compiler: str | None = None
    probe_returncode: int | None = None
    probe_stderr: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "available": self.available,
            "compiler": self.compiler,
            "probe_returncode": self.probe_returncode,
            "probe_stderr": self.probe_stderr,
            "reason": self.reason,
        }


class SanitizerAdapter(ABC):
    """Base class for every sanitizer adapter."""

    spec: ClassVar[SanitizerSpec]

    # ------------------------------------------------------------------ queries

    @classmethod
    def kind(cls) -> SanitizerKind:
        return cls.spec.kind

    @classmethod
    def name(cls) -> str:
        return cls.spec.name

    @classmethod
    def compiler_flags(cls) -> tuple[str, ...]:
        return cls.spec.compiler_flags

    @classmethod
    def linker_flags(cls) -> tuple[str, ...]:
        return cls.spec.linker_flags

    @classmethod
    def runtime_env_var(cls) -> str:
        return cls.spec.runtime_env_var

    @classmethod
    def afl_env_var(cls) -> str | None:
        return cls.spec.afl_env_var

    @classmethod
    def log_format(cls) -> str:
        return cls.spec.log_format

    @classmethod
    def matches_report_line(cls, line: str) -> bool:
        """Return whether ``line`` looks like the start of this sanitizer's report."""
        return cls.spec.error_pattern.search(line) is not None

    # ------------------------------------------------------------------ availability

    @classmethod
    def availability(
        cls,
        detector: EnvironmentDetector,
        *,
        timeout: float = 10.0,
    ) -> SanitizerAvailability:
        """Compile a tiny program with this sanitizer and run it.

        The probe program deliberately does nothing interesting; the point is
        to confirm that the *toolchain* accepts the sanitizer's flags and that
        the *runtime* loads correctly.  If either fails, the sanitizer is
        reported as unavailable with the compiler's own message.
        """
        compiler_report = detector.detect_all(["clang", "clang++", "gcc", "g++"])
        compiler = None
        for name in ("clang", "gcc"):
            info = compiler_report.get(name)
            if info is not None and info.available and info.path:
                compiler = info.path
                break

        if compiler is None:
            return SanitizerAvailability(
                kind=cls.spec.kind,
                available=False,
                reason="No C compiler (clang/gcc) was found on $PATH",
            )

        with tempfile.TemporaryDirectory(prefix="kmcs-sanitizer-probe-") as tmp:
            tmp_path = Path(tmp)
            source = tmp_path / "probe.c"
            binary = tmp_path / "probe"
            source.write_text("int main(void){return 0;}\n")

            command: list[str] = [compiler]
            command += list(cls.spec.compiler_flags)
            command += [str(source), "-o", str(binary)]
            command += list(cls.spec.linker_flags)

            try:
                compile_result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                return SanitizerAvailability(
                    kind=cls.spec.kind,
                    available=False,
                    compiler=compiler,
                    reason=f"Compile probe failed: {exc}",
                )

            if compile_result.returncode != 0 or not binary.is_file():
                return SanitizerAvailability(
                    kind=cls.spec.kind,
                    available=False,
                    compiler=compiler,
                    probe_returncode=compile_result.returncode,
                    probe_stderr=compile_result.stderr[-4000:],
                    reason=(
                        f"{compiler} rejected {cls.spec.name} flags "
                        f"(exit {compile_result.returncode})"
                    ),
                )

            # The runtime may still fail to load.  Run the binary once.
            try:
                run_result = subprocess.run(
                    [str(binary)],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                return SanitizerAvailability(
                    kind=cls.spec.kind,
                    available=False,
                    compiler=compiler,
                    reason=f"Runtime probe failed: {exc}",
                )

            if run_result.returncode != 0:
                return SanitizerAvailability(
                    kind=cls.spec.kind,
                    available=False,
                    compiler=compiler,
                    probe_returncode=run_result.returncode,
                    probe_stderr=run_result.stderr[-4000:],
                    reason=(
                        f"Runtime for {cls.spec.name} exited with "
                        f"{run_result.returncode}"
                    ),
                )

        return SanitizerAvailability(
            kind=cls.spec.kind,
            available=True,
            compiler=compiler,
            reason=None,
        )

    # ------------------------------------------------------------------ options

    @classmethod
    @abstractmethod
    def build_environment(cls, base: Mapping[str, str], **options: Any) -> dict[str, str]:
        """Return an environment with this sanitizer's options applied.

        Implementations are expected to merge *into a copy* of ``base`` rather
        than mutate it, and to leave unrelated variables untouched.
        """

    # ------------------------------------------------------------------ registry

    @classmethod
    def all_known(cls) -> tuple[type["SanitizerAdapter"], ...]:
        return tuple(_REGISTRY.values())


# ---------------------------------------------------------------------- registry


_REGISTRY: dict[SanitizerKind, type[SanitizerAdapter]] = {}


def register(adapter_cls: type[SanitizerAdapter]) -> type[SanitizerAdapter]:
    """Register a sanitizer adapter under its declared kind."""
    kind = adapter_cls.spec.kind
    if kind in _REGISTRY and _REGISTRY[kind] is not adapter_cls:
        raise SanitizerError(
            "Duplicate sanitizer registration",
            details={"kind": kind.value, "existing": _REGISTRY[kind].__name__},
        )
    _REGISTRY[kind] = adapter_cls
    return adapter_cls


def get_adapter(kind: SanitizerKind) -> type[SanitizerAdapter]:
    """Return the adapter class for ``kind`` or raise."""
    try:
        return _REGISTRY[kind]
    except KeyError as exc:
        raise SanitizerUnavailableError(
            "No adapter is registered for this sanitizer",
            details={"kind": kind.value, "known": [k.value for k in _REGISTRY]},
        ) from exc


def all_adapters() -> tuple[type[SanitizerAdapter], ...]:
    return tuple(_REGISTRY.values())


class SanitizerRegistry:
    """Convenience façade over the module-level registry."""

    @staticmethod
    def for_kind(kind: SanitizerKind) -> type[SanitizerAdapter]:
        return get_adapter(kind)

    @staticmethod
    def for_kinds(kinds: Iterable[SanitizerKind]) -> list[type[SanitizerAdapter]]:
        return [get_adapter(kind) for kind in kinds]

    @staticmethod
    def detect_all(
        detector: EnvironmentDetector,
        kinds: Iterable[SanitizerKind] | None = None,
    ) -> dict[SanitizerKind, SanitizerAvailability]:
        selected = list(kinds) if kinds is not None else list(_REGISTRY)
        return {
            kind: get_adapter(kind).availability(detector) for kind in selected
        }

    @staticmethod
    def available_kinds(detector: EnvironmentDetector) -> list[SanitizerKind]:
        report = SanitizerRegistry.detect_all(detector)
        return sorted(
            (kind for kind, info in report.items() if info.available),
            key=lambda kind: kind.value,
        )
