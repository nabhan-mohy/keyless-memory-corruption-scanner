"""Deterministic crash fingerprints.

A fingerprint is a stable, portable identifier for *an underlying bug*.  Two
crashes with the same fingerprint are, with high probability, the same
underlying defect; two crashes with different fingerprints are, with high
probability, different defects.

Design constraints:

* **Deterministic.** The fingerprint is a pure function of the structured
  :class:`CrashReport`; running it twice produces the same digest.
* **Portable.** Absolute addresses, PIDs, and full source paths are excluded
  from the canonical string, so the fingerprint survives rebuilds and moves
  between machines.
* **Runtime-aware.** Sanitizer-internal and libc-startup frames are filtered
  out — they do not distinguish bugs.
* **Configurable depth.** ``stack_depth`` controls how many frames contribute;
  the default of 3 balances false positives against false negatives.
* **Extensible to auxiliary stacks.** For use-after-free and double-free,
  the free and allocation stacks are included so that two UAFs sharing the
  free site but differing at the alloc site remain distinct.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from kmcs.analysis.crash_parser import CrashReport, SanitizerReport, StackFrame

__all__ = [
    "FingerprintConfig",
    "CrashFingerprint",
    "CrashFingerprinter",
]


# Frames whose source path contains one of these markers are part of the
# sanitizer runtime or the C library startup; they never distinguish bugs.
_RUNTIME_PATH_MARKERS: tuple[str, ...] = (
    "/compiler-rt/",
    "/llvm-project/",
    "/sanitizer_common/",
    "/asan/",
    "/ubsan/",
    "/lsan/",
    "/msan/",
    "/tsan/",
    "/libc/",
    "/glibc-",
    "/sysdeps/",
    "/csu/",
    "/libgcc/",
)

# Frames whose function name contains one of these substrings are equally
# runtime noise.
_RUNTIME_FUNCTION_MARKERS: tuple[str, ...] = (
    "__libc_start_main",
    "__libc_start_call_main",
    "__libc_csu_init",
    "_start",
    "__sanitizer",
    "__asan_",
    "__ubsan_",
    "__lsan_",
    "__msan_",
    "__tsan_",
    "llvm::",
    "asan::",
    "ubsan::",
)


@dataclass(frozen=True, slots=True)
class FingerprintConfig:
    stack_depth: int = 3
    include_auxiliary_stacks: bool = True
    include_source_location: bool = True
    normalize_source_paths: bool = True
    filter_runtime_frames: bool = True
    truncate_to: int = 16

    def __post_init__(self) -> None:
        if self.stack_depth < 1 or self.stack_depth > 64:
            raise ValueError("stack_depth must be between 1 and 64")
        if self.truncate_to < 8 or self.truncate_to > 64:
            raise ValueError("truncate_to must be between 8 and 64")


@dataclass(frozen=True, slots=True)
class CrashFingerprint:
    value: str
    canonical: str
    algorithm: str = "sha256"
    components: dict[str, str] = field(default_factory=dict)

    @property
    def short(self) -> str:
        return self.value[:12]

    def to_dict(self) -> dict[str, str]:
        return {
            "value": self.value,
            "short": self.short,
            "algorithm": self.algorithm,
            "canonical": self.canonical,
            **{f"component.{k}": v for k, v in self.components.items()},
        }


def _normalize_source_path(path: str) -> str:
    """Keep the last two path components; drop anything above it.

    ``/src/demo/vulnerable.c``        -> ``demo/vulnerable.c``
    ``/home/user/project/foo/bar.c``  -> ``foo/bar.c``
    ``vulnerable.c``                  -> ``vulnerable.c``
    ``<unknown module>``              -> ``<unknown module>``
    """
    parts = Path(path).parts
    if len(parts) <= 2:
        return str(Path(*parts))
    return str(Path(*parts[-2:]))


class CrashFingerprinter:
    """Computes deterministic fingerprints over :class:`CrashReport` objects."""

    def __init__(self, config: FingerprintConfig | None = None) -> None:
        self._config = config or FingerprintConfig()

    @property
    def config(self) -> FingerprintConfig:
        return self._config

    # ------------------------------------------------------------------ public

    def fingerprint(self, report: CrashReport) -> CrashFingerprint:
        components = self._build_components(report)
        canonical = self._render(components)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return CrashFingerprint(
            value=digest[: self._config.truncate_to],
            canonical=canonical,
            components=components,
        )

    # ------------------------------------------------------------------ components

    def _build_components(self, report: CrashReport) -> dict[str, str]:
        components: dict[str, str] = {}

        primary = report.primary_report
        if primary is None:
            components["signal"] = (
                report.signal_name
                or (f"signal:{report.signal_number}" if report.signal_number else "none")
            )
            components["exit_code"] = (
                str(report.exit_code) if report.exit_code is not None else "none"
            )
        else:
            components["sanitizer"] = primary.sanitizer.value
            components["error_type"] = primary.error_type or "unknown"
            if primary.access_type.value != "unknown":
                components["access"] = primary.access_type.value

        primary_frames = self._filter_frames(report.stack_frames)
        components["stack"] = self._render_frames(primary_frames)

        if primary is not None and self._config.include_auxiliary_stacks:
            aux_free = self._filter_frames(primary.free_site)
            if aux_free:
                components["free_stack"] = self._render_frames(aux_free)

            aux_alloc = self._filter_frames(primary.allocation_site)
            if aux_alloc:
                components["alloc_stack"] = self._render_frames(aux_alloc)

        return components

    # ------------------------------------------------------------------ filtering

    def _filter_frames(self, frames: list[StackFrame]) -> list[StackFrame]:
        if not self._config.filter_runtime_frames:
            return list(frames)
        return [f for f in frames if not self._is_runtime_frame(f)]

    @staticmethod
    def _is_runtime_frame(frame: StackFrame) -> bool:
        if frame.function:
            for marker in _RUNTIME_FUNCTION_MARKERS:
                if marker in frame.function:
                    return True
        if frame.source_file:
            for marker in _RUNTIME_PATH_MARKERS:
                if marker in frame.source_file:
                    return True
        if frame.module:
            for marker in _RUNTIME_PATH_MARKERS:
                if marker in frame.module:
                    return True
        return False

    # ------------------------------------------------------------------ rendering

    def _render_frames(self, frames: list[StackFrame]) -> str:
        selected = frames[: self._config.stack_depth]
        if not selected:
            return ""
        return "|".join(self._frame_signature(f) for f in selected)

    def _frame_signature(self, frame: StackFrame) -> str:
        parts: list[str] = []

        if frame.function:
            parts.append(f"fn={frame.function}")

        if self._config.include_source_location and frame.source_file:
            file = frame.source_file
            if self._config.normalize_source_paths:
                file = _normalize_source_path(file)
            parts.append(f"at={file}")
            if frame.line is not None:
                parts.append(f"line={frame.line}")
        elif frame.module:
            module = frame.module
            if self._config.normalize_source_paths:
                module = _normalize_source_path(module)
            parts.append(f"mod={module}")
            if frame.offset is not None:
                parts.append(f"off={frame.offset:#x}")

        if not parts:
            parts.append("frame=unknown")
        return ",".join(parts)

    @staticmethod
    def _render(components: dict[str, str]) -> str:
        return "\n".join(f"{key}={value}" for key, value in sorted(components.items()))
