"""Typed, validated option builders for sanitizer runtime configuration.

Each ``*Options`` class represents one sanitizer's runtime control surface.  The
classes are frozen Pydantic models so that invalid combinations are rejected at
construction time rather than producing a silently-broken ``ASAN_OPTIONS``
string in the middle of a fuzzing campaign.

Only options that KMCS genuinely uses are modelled.  Adding a new one is a
one-line change; the classes do not pretend to know every option the
sanitizers accept.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "AddressSanitizerOptions",
    "UndefinedSanitizerOptions",
    "LeakSanitizerOptions",
    "MemorySanitizerOptions",
    "ThreadSanitizerOptions",
]


def _non_empty(value: str, field: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field} must not be empty")
    return cleaned


class _BaseOptions(BaseModel):
    """Common construction helpers for every sanitizer's option set."""

    model_config = ConfigDict(validate_assignment=True, extra="forbid")

    @staticmethod
    def _bool(value: bool) -> str:
        return "1" if value else "0"

    def _to_assignments(self, **kwargs: object) -> dict[str, str]:
        """Map Python attribute names to the sanitizer's own option names."""
        assignments: dict[str, str] = {}
        for key, value in kwargs.items():
            if value is None:
                continue
            if isinstance(value, bool):
                assignments[key] = self._bool(value)
            else:
                assignments[key] = str(value)
        return assignments

    def _render(self, assignments: dict[str, str]) -> str:
        return ":".join(f"{key}={value}" for key, value in sorted(assignments.items()))


class AddressSanitizerOptions(_BaseOptions):
    """Options for the AddressSanitizer runtime (``ASAN_OPTIONS``)."""

    log_path: Path | None = None
    log_exe_name: bool = False
    abort_on_error: bool = True
    halt_on_error: bool = True
    symbolize: bool = True
    detect_leaks: bool = False
    detect_stack_use_after_return: bool = True
    strict_string_checks: bool = True
    check_initialization_order: bool = False
    detect_odr_violation: int = Field(default=2, ge=0, le=2)
    allocator_may_return_null: bool = True
    print_summary: bool = True
    print_stats: bool = False
    max_malloc_fill_size: int | None = Field(default=None, ge=0)
    malloc_fill_byte: int | None = Field(default=None, ge=0, le=255)
    fast_unwind_on_fatal: bool = False

    @field_validator("log_path", mode="after")
    @classmethod
    def _normalise_log_path(cls, value: Path | None) -> Path | None:
        return None if value is None else Path(value).expanduser().absolute()

    def to_environment(self) -> str:
        assignments = self._to_assignments(
            log_path=str(self.log_path) if self.log_path is not None else None,
            log_exe_name=self.log_exe_name,
            abort_on_error=self.abort_on_error,
            halt_on_error=self.halt_on_error,
            symbolize=self.symbolize,
            detect_leaks=self.detect_leaks,
            detect_stack_use_after_return=self.detect_stack_use_after_return,
            strict_string_checks=self.strict_string_checks,
            check_initialization_order=self.check_initialization_order,
            detect_odr_violation=self.detect_odr_violation,
            allocator_may_return_null=self.allocator_may_return_null,
            print_summary=self.print_summary,
            print_stats=self.print_stats,
            max_malloc_fill_size=self.max_malloc_fill_size,
            malloc_fill_byte=self.malloc_fill_byte,
            fast_unwind_on_fatal=self.fast_unwind_on_fatal,
        )
        return self._render(assignments)


class UndefinedSanitizerOptions(_BaseOptions):
    """Options for the UndefinedBehaviorSanitizer runtime (``UBSAN_OPTIONS``)."""

    log_path: Path | None = None
    print_stacktrace: bool = True
    halt_on_error: bool = True
    abort_on_error: bool = True
    print_summary: bool = False

    @field_validator("log_path", mode="after")
    @classmethod
    def _normalise_log_path(cls, value: Path | None) -> Path | None:
        return None if value is None else Path(value).expanduser().absolute()

    def to_environment(self) -> str:
        assignments = self._to_assignments(
            log_path=str(self.log_path) if self.log_path is not None else None,
            print_stacktrace=self.print_stacktrace,
            halt_on_error=self.halt_on_error,
            abort_on_error=self.abort_on_error,
            print_summary=self.print_summary,
        )
        return self._render(assignments)


class LeakSanitizerOptions(_BaseOptions):
    """Options for the LeakSanitizer runtime (``LSAN_OPTIONS``)."""

    log_path: Path | None = None
    exitcode: int = 23
    report_objects: bool = False
    max_leaks: int = Field(default=0, ge=0)
    suppressions: Path | None = None

    @field_validator("log_path", "suppressions", mode="after")
    @classmethod
    def _normalise_path(cls, value: Path | None) -> Path | None:
        return None if value is None else Path(value).expanduser().absolute()

    def to_environment(self) -> str:
        assignments = self._to_assignments(
            log_path=str(self.log_path) if self.log_path is not None else None,
            exitcode=self.exitcode,
            report_objects=self.report_objects,
            max_leaks=self.max_leaks,
            suppressions=str(self.suppressions) if self.suppressions is not None else None,
        )
        return self._render(assignments)


class MemorySanitizerOptions(_BaseOptions):
    """Options for the MemorySanitizer runtime (``MSAN_OPTIONS``).

    MemorySanitizer requires every dependency to be instrumented with the same
    MSan runtime.  KMCS records that fact in the adapter's availability
    message; it does not try to hide it.
    """

    log_path: Path | None = None
    halt_on_error: bool = True
    exit_code: int = 77
    print_stats: bool = False
    track_origins: int = Field(default=0, ge=0, le=2)

    @field_validator("log_path", mode="after")
    @classmethod
    def _normalise_log_path(cls, value: Path | None) -> Path | None:
        return None if value is None else Path(value).expanduser().absolute()

    def to_environment(self) -> str:
        assignments = self._to_assignments(
            log_path=str(self.log_path) if self.log_path is not None else None,
            halt_on_error=self.halt_on_error,
            exit_code=self.exit_code,
            print_stats=self.print_stats,
            track_origins=self.track_origins,
        )
        return self._render(assignments)


class ThreadSanitizerOptions(_BaseOptions):
    """Options for the ThreadSanitizer runtime (``TSAN_OPTIONS``)."""

    log_path: Path | None = None
    halt_on_error: bool = True
    exitcode: int = 66
    history_size: int = Field(default=7, ge=0, le=7)
    second_deadlock_stack: bool = False
    report_bugs: bool = True

    @field_validator("log_path", mode="after")
    @classmethod
    def _normalise_log_path(cls, value: Path | None) -> Path | None:
        return None if value is None else Path(value).expanduser().absolute()

    def to_environment(self) -> str:
        assignments = self._to_assignments(
            log_path=str(self.log_path) if self.log_path is not None else None,
            halt_on_error=self.halt_on_error,
            exitcode=self.exitcode,
            history_size=self.history_size,
            second_deadlock_stack=self.second_deadlock_stack,
            report_bugs=self.report_bugs,
        )
        return self._render(assignments)
