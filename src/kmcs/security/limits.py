"""POSIX resource limits applied to every child process.

KMCS runs untrusted code.  It must not let a fuzzer or a sanitized target
exhaust the researcher's machine.  The three limits that matter most are
address space (a memory-hungry target can OOM the host), CPU time (a hung
target can pin a core forever), and file size (a runaway writer can fill the
disk).

Every limit is optional.  ``None`` means "do not set this limit"; KMCS does
not invent defaults for the researcher.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["ResourceLimits", "apply_limits_in_child"]


class ResourceLimits(BaseModel):
    """Configuration for per-process POSIX resource limits."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    cpu_seconds: int | None = Field(default=None, ge=1)
    """Hard CPU-time limit.  When exceeded, the kernel sends ``SIGXCPU``."""

    memory_mb: int | None = Field(default=None, ge=1)
    """Address-space cap.  ``RLIMIT_AS`` on Linux, ``RLIMIT_DATA`` on macOS."""

    file_size_mb: int | None = Field(default=None, ge=1)
    """Maximum size of any single file the child can create."""

    open_files: int | None = Field(default=None, ge=8)
    """Maximum number of simultaneously open file descriptors."""

    processes: int | None = Field(default=None, ge=1)
    """Maximum number of processes the child can create (fork bombs)."""

    core_dumps: bool = False
    """When False (the default), the child cannot write a core dump."""

    def to_dict(self) -> dict[str, object]:
        return self.model_dump(mode="json")


def apply_limits_in_child(limits: ResourceLimits) -> None:
    """Apply ``limits`` inside a forked child process.

    Called via ``preexec_fn`` on POSIX.  Never raises across the fork
    boundary: any failure is written to stderr and execution continues with
    the remaining limits.
    """
    import resource
    import sys

    def _set(kind: int, value: int) -> None:
        try:
            resource.setrlimit(kind, (value, value))
        except (ValueError, OSError) as exc:
            print(
                f"kmcs: warning: could not set resource limit "
                f"{kind}: {exc}",
                file=sys.stderr,
            )

    if limits.cpu_seconds is not None:
        _set(resource.RLIMIT_CPU, limits.cpu_seconds)

    if limits.memory_mb is not None:
        bytes_ = limits.memory_mb * 1024 * 1024
        # macOS enforces address space differently; RLIMIT_AS is unreliable
        # with ASan there, so we set RLIMIT_DATA as a fallback.  Both are
        # best-effort.
        if hasattr(resource, "RLIMIT_AS"):
            _set(resource.RLIMIT_AS, bytes_)
        elif hasattr(resource, "RLIMIT_DATA"):
            _set(resource.RLIMIT_DATA, bytes_)

    if limits.file_size_mb is not None:
        _set(resource.RLIMIT_FSIZE, limits.file_size_mb * 1024 * 1024)

    if limits.open_files is not None and hasattr(resource, "RLIMIT_NOFILE"):
        _set(resource.RLIMIT_NOFILE, limits.open_files)

    if limits.processes is not None and hasattr(resource, "RLIMIT_NPROC"):
        _set(resource.RLIMIT_NPROC, limits.processes)

    if not limits.core_dumps and hasattr(resource, "RLIMIT_CORE"):
        _set(resource.RLIMIT_CORE, 0)


def limits_supported() -> bool:
    """Whether the current platform supports the POSIX resource module."""
    return os.name == "posix"
