"""POSIX signal names and meanings.

KMCS reports signals by number *and* by name, because exit-code reporting tools
in the field disagree about which is meaningful.  The mapping is deliberately
static rather than derived from ``signal.Signals`` at import time: some
platforms omit real-time signals from the enum, and we want a stable,
JSON-serialisable representation across every host.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "SignalInfo",
    "SIGNALS",
    "signal_info",
    "signal_name",
    "signal_description",
    "is_fatal_signal",
]


@dataclass(frozen=True, slots=True)
class SignalInfo:
    number: int
    name: str
    description: str
    fatal: bool = True


# Comprehensive POSIX signal table.  ``fatal`` reflects whether an uncaught
# instance terminates the process; informational signals like SIGCHLD do not.
_SIGNAL_TABLE: tuple[SignalInfo, ...] = (
    SignalInfo(1, "SIGHUP", "hangup"),
    SignalInfo(2, "SIGINT", "interrupt"),
    SignalInfo(3, "SIGQUIT", "quit"),
    SignalInfo(4, "SIGILL", "illegal instruction"),
    SignalInfo(5, "SIGTRAP", "trace/breakpoint trap"),
    SignalInfo(6, "SIGABRT", "abort"),
    SignalInfo(7, "SIGBUS", "bus error"),
    SignalInfo(8, "SIGFPE", "floating-point exception"),
    SignalInfo(9, "SIGKILL", "kill (uncatchable)"),
    SignalInfo(10, "SIGUSR1", "user-defined signal 1"),
    SignalInfo(11, "SIGSEGV", "segmentation fault"),
    SignalInfo(12, "SIGUSR2", "user-defined signal 2"),
    SignalInfo(13, "SIGPIPE", "broken pipe"),
    SignalInfo(14, "SIGALRM", "alarm clock"),
    SignalInfo(15, "SIGTERM", "termination"),
    SignalInfo(16, "SIGSTKFLT", "stack fault"),
    SignalInfo(17, "SIGCHLD", "child process status change", fatal=False),
    SignalInfo(18, "SIGCONT", "continue", fatal=False),
    SignalInfo(19, "SIGSTOP", "stop (uncatchable)"),
    SignalInfo(20, "SIGTSTP", "terminal stop"),
    SignalInfo(21, "SIGTTIN", "background read from tty"),
    SignalInfo(22, "SIGTTOU", "background write to tty"),
    SignalInfo(23, "SIGURG", "urgent I/O condition", fatal=False),
    SignalInfo(24, "SIGXCPU", "CPU time limit exceeded"),
    SignalInfo(25, "SIGXFSZ", "file size limit exceeded"),
    SignalInfo(26, "SIGVTALRM", "virtual timer expired"),
    SignalInfo(27, "SIGPROF", "profiling timer expired"),
    SignalInfo(28, "SIGWINCH", "window size change", fatal=False),
    SignalInfo(29, "SIGIO", "I/O now possible", fatal=False),
    SignalInfo(30, "SIGPWR", "power failure"),
    SignalInfo(31, "SIGSYS", "bad system call"),
)

SIGNALS: dict[int, SignalInfo] = {info.number: info for info in _SIGNAL_TABLE}

# The subset that a fuzzing campaign should treat as a genuine crash when the
# process dies from it *without* a sanitizer report explaining why.
_FATAL_SIGNALS: frozenset[int] = frozenset(
    info.number for info in _SIGNAL_TABLE if info.fatal
)


def signal_info(number: int) -> SignalInfo | None:
    return SIGNALS.get(int(number))


def signal_name(number: int) -> str:
    """Return the canonical name, or ``SIG<N>`` when unknown."""
    info = SIGNALS.get(int(number))
    return info.name if info else f"SIG{int(number)}"


def signal_description(number: int) -> str:
    info = SIGNALS.get(int(number))
    return info.description if info else "unknown signal"


def is_fatal_signal(number: int) -> bool:
    """Whether this signal is a normal process-terminating one."""
    return int(number) in _FATAL_SIGNALS
