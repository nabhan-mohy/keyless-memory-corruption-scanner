"""Typed sanitizer option builders."""

from __future__ import annotations

from pathlib import Path

from kmcs.sanitizers.options import (
    AddressSanitizerOptions,
    LeakSanitizerOptions,
    MemorySanitizerOptions,
    ThreadSanitizerOptions,
    UndefinedSanitizerOptions,
)


def test_asan_defaults() -> None:
    rendered = AddressSanitizerOptions().to_environment()
    assert "abort_on_error=1" in rendered
    assert "symbolize=1" in rendered
    assert "detect_leaks=0" in rendered
    assert ":" in rendered  # colon-separated


def test_asan_log_path_is_absolute() -> None:
    opts = AddressSanitizerOptions(log_path=Path("./logs"))
    assert "log_path=" in opts.to_environment()
    # We do not assert the exact path — only that it is absolute and stable.
    assert str(opts.log_path).startswith("/") or opts.log_path.drive


def test_asan_can_disable_abort() -> None:
    opts = AddressSanitizerOptions(abort_on_error=False)
    assert "abort_on_error=0" in opts.to_environment()


def test_ubsan_stacktrace_is_on_by_default() -> None:
    rendered = UndefinedSanitizerOptions().to_environment()
    assert "print_stacktrace=1" in rendered
    assert "halt_on_error=1" in rendered


def test_lsan_max_leaks_zero_means_unlimited() -> None:
    # LSan treats 0 as "report all leaks"; we assert we do not clobber it.
    rendered = LeakSanitizerOptions().to_environment()
    assert "max_leaks=0" in rendered


def test_msan_exit_code_default() -> None:
    rendered = MemorySanitizerOptions().to_environment()
    assert "exit_code=77" in rendered


def test_tsan_history_size_bounds() -> None:
    from pydantic import ValidationError

    try:
        ThreadSanitizerOptions(history_size=9)
    except ValidationError:
        pass
    else:  # pragma: no cover
        raise AssertionError("history_size > 7 should be rejected")


def test_options_are_sorted_and_stable() -> None:
    # Sorting makes output deterministic for tests and log comparison.
    rendered = AddressSanitizerOptions().to_environment()
    assignments = rendered.split(":")
    keys = [a.split("=")[0] for a in assignments]
    assert keys == sorted(keys)
