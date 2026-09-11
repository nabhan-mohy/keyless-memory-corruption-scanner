"""Exception hierarchy used across KMCS.

Every failure KMCS raises deliberately derives from :class:`KMCSException`, so the
CLI can distinguish an expected, reportable failure from a genuine bug.  Each class
carries an ``exit_code`` that the CLI uses as the process exit status.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "KMCSException",
    "ConfigurationError",
    "StartupError",
    "DatabaseError",
    "MigrationError",
    "EventError",
    "EventHandlerError",
    "JobError",
    "InvalidJobTransitionError",
]


class KMCSException(Exception):
    """Base class for all deliberate KMCS failures."""

    exit_code: int = 1

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = dict(details) if details else {}

    def __str__(self) -> str:
        if not self.details:
            return self.message
        rendered = ", ".join(
            f"{key}={value!r}" for key, value in sorted(self.details.items())
        )
        return f"{self.message} ({rendered})"


class ConfigurationError(KMCSException):
    """The KMCS configuration is missing, invalid, or unusable."""

    exit_code = 2


class StartupError(KMCSException):
    """The application could not complete its startup sequence."""

    exit_code = 3


class DatabaseError(KMCSException):
    """The SQLite database cannot be opened, read, or written."""

    exit_code = 4


class MigrationError(DatabaseError):
    """A schema migration failed, or the on-disk schema is inconsistent."""

    exit_code = 5


class EventError(KMCSException):
    """A problem occurred inside the internal event system."""

    exit_code = 6


class EventHandlerError(EventError):
    """An event handler raised while the bus was in strict mode."""


class JobError(KMCSException):
    """A problem occurred with job bookkeeping."""

    exit_code = 7


class InvalidJobTransitionError(JobError):
    """An illegal job state transition was attempted."""
