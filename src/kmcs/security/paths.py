"""Path resolution with a hard containment guarantee.

The resolver answers one question: *is this path, after full symlink
resolution, inside a directory I trust?*  If the answer is not yes, the
resolver raises.  There is no "lenient" mode.

Why this matters for KMCS:

* A corpus directory that contains a symlink to ``/etc/shadow`` must not
  cause KMCS to copy that file into a new corpus.
* A campaign output directory given as a relative path like
  ``../../etc/cron.d`` must not overwrite system files.
* A crash evidence file name read from the database must not be able to walk
  outside the evidence directory.

The resolver does not replace ``pathlib``; it augments it with the checks
``pathlib`` deliberately does not perform.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "PathSecurityError",
    "SafePathResolver",
    "ensure_within_root",
    "is_within",
]


class PathSecurityError(Exception):
    """A path failed a containment or validity check."""

    def __init__(
        self, message: str, *, details: dict[str, object] | None = None
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, object] = dict(details or {})


def _resolve_strictly(path: Path) -> Path:
    """Resolve symlinks and normalise without requiring the path to exist.

    ``Path.resolve(strict=False)`` on Python 3.11+ does what we need, but the
    behaviour on Windows with UNC paths differs subtly across patch releases.
    We therefore normalise ``..`` manually and then delegate to the stdlib.
    """
    # ``os.path.normpath`` collapses ``..`` and repeated separators without
    # touching the filesystem.
    normalised = Path(os.path.normpath(str(path)))
    try:
        return normalised.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise PathSecurityError(
            "Path could not be resolved",
            details={"path": str(path), "error": str(exc)},
        ) from exc


def is_within(candidate: Path, root: Path) -> bool:
    """Return ``True`` when ``candidate`` resolves inside ``root``."""
    try:
        resolved = _resolve_strictly(candidate)
        root_resolved = _resolve_strictly(root)
    except PathSecurityError:
        return False
    try:
        resolved.relative_to(root_resolved)
    except ValueError:
        return False
    return True


def ensure_within_root(candidate: Path, root: Path) -> Path:
    """Return the resolved path, or raise :class:`PathSecurityError`."""
    resolved = _resolve_strictly(candidate)
    root_resolved = _resolve_strictly(root)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise PathSecurityError(
            "Path escapes the trusted root",
            details={"path": str(candidate), "root": str(root)},
        ) from exc
    return resolved


@dataclass(frozen=True, slots=True)
class SafePathResolver:
    """Resolves paths inside one or more trusted roots.

    A path is trusted when its fully-resolved form is a descendant of one of
    ``roots``.  Resolution is a real ``resolve()`` call — symlinks are
    followed, so a symlink that points outside the root is rejected.
    """

    roots: tuple[Path, ...]
    allow_missing: bool = True

    def __post_init__(self) -> None:
        if not self.roots:
            raise PathSecurityError("SafePathResolver requires at least one root")
        normalised: list[Path] = []
        for root in self.roots:
            normalised.append(_resolve_strictly(root))
        object.__setattr__(self, "roots", tuple(normalised))

    # ------------------------------------------------------------------ queries

    def is_allowed(self, candidate: Path) -> bool:
        try:
            self.resolve(candidate)
        except PathSecurityError:
            return False
        return True

    def resolve(self, candidate: Path | str) -> Path:
        """Return the canonical path, or raise :class:`PathSecurityError`."""
        path = Path(candidate)

        if contains_relative_escape(path):
            # ``..`` inside a relative path is legal and normalised by
            # resolve(), but a leading ``..`` from a caller-supplied string is
            # almost always a bug.  We treat it as such.
            raise PathSecurityError(
                "Path begins with a parent-directory traversal",
                details={"path": str(path)},
            )

        resolved = _resolve_strictly(path)

        if not self.allow_missing and not resolved.exists():
            raise PathSecurityError(
                "Path does not exist", details={"path": str(resolved)}
            )

        for root in self.roots:
            try:
                resolved.relative_to(root)
            except ValueError:
                continue
            return resolved

        raise PathSecurityError(
            "Path escapes every trusted root",
            details={
                "path": str(resolved),
                "roots": [str(r) for r in self.roots],
            },
        )

    def resolve_many(self, candidates: Iterable[Path | str]) -> list[Path]:
        return [self.resolve(candidate) for candidate in candidates]


def contains_relative_escape(path: Path) -> bool:
    """Return ``True`` if ``path`` is relative and starts with ``..``."""
    if path.is_absolute():
        return False
    parts = path.parts
    return bool(parts) and parts[0] == ".."
