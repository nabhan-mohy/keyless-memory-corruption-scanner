"""POSIX signal mapping."""

from __future__ import annotations

from kmcs.analysis.signals import (
    SIGNALS,
    is_fatal_signal,
    signal_description,
    signal_info,
    signal_name,
)


def test_sigsegv_is_mapped() -> None:
    assert signal_name(11) == "SIGSEGV"
    assert signal_description(11) == "segmentation fault"
    assert is_fatal_signal(11) is True


def test_sigabrt_is_mapped() -> None:
    assert signal_name(6) == "SIGABRT"
    assert is_fatal_signal(6) is True


def test_sigchld_is_not_fatal() -> None:
    assert signal_name(17) == "SIGCHLD"
    assert is_fatal_signal(17) is False


def test_unknown_signal_is_named_by_number() -> None:
    assert signal_name(99) == "SIG99"
    assert signal_description(99) == "unknown signal"
    assert is_fatal_signal(99) is False
    assert signal_info(99) is None


def test_signal_table_is_contiguous_enough() -> None:
    # Standard signals cover 1..31; anything outside is a real-time signal
    # we do not model.
    for number in range(1, 32):
        assert number in SIGNALS
