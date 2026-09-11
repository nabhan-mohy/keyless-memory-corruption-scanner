"""Corpus entry validation.

A candidate file is validated against six checks in a fixed order.  Each check
either passes, is skipped (because an earlier check already failed), or
produces a :class:`ValidationIssue`.  The validator never mutates the file
system and never opens a file for writing.

The validator is a pure function of the file's metadata and (for content-based
checks) its bytes.  That makes it trivially unit-testable and lets a caller
choose how expensive a validation pass to run.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ValidationIssueCode",
    "ValidationIssue",
    "ValidatorConfig",
    "ValidationResult",
    "CorpusValidator",
]


class ValidationIssueCode(str, Enum):
    PATH_EMPTY = "path-empty"
    NOT_A_FILE = "not-a-file"
    SYMLINK_OUTSIDE_ROOT = "symlink-outside-root"
    NOT_READABLE = "not-readable"
    EMPTY_FILE = "empty-file"
    TOO_LARGE = "too-large"
    TOO_SMALL = "too-small"
    DUPLICATE_CONTENT = "duplicate-content"
    IO_ERROR = "io-error"


@dataclass(frozen=True, slots=True)
class ValidationIssue:
    code: ValidationIssueCode
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code.value, "message": self.message}


class ValidatorConfig(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    min_size_bytes: int = Field(default=1, ge=0)
    max_size_bytes: int = Field(default=10 * 1024 * 1024, gt=0)
    reject_symlinks: bool = True
    compute_sha256: bool = True
    """When False, the validator still hashes if a duplicate set is provided,
    because otherwise duplicate detection is meaningless."""


class ValidationResult(BaseModel):
    """The outcome of validating one candidate file."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: Path
    valid: bool
    size_bytes: int | None = None
    sha256: str | None = None
    issues: list[ValidationIssue] = Field(default_factory=list)

    @property
    def code_set(self) -> set[ValidationIssueCode]:
        return {issue.code for issue in self.issues}

    def has(self, code: ValidationIssueCode) -> bool:
        return code in self.code_set

    def to_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "valid": self.valid,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "issues": [issue.to_dict() for issue in self.issues],
        }


def _hash_file(path: Path, *, chunk_size: int = 1 << 16) -> tuple[str, int]:
    """Return ``(sha256_hex, size_bytes)`` for a file, streaming the bytes."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


class CorpusValidator:
    """Validates candidate corpus entries."""

    def __init__(self, config: ValidatorConfig | None = None) -> None:
        self._config = config or ValidatorConfig()

    @property
    def config(self) -> ValidatorConfig:
        return self._config

    # ------------------------------------------------------------------ public

    def validate(
        self,
        path: Path | str,
        *,
        known_hashes: Iterable[str] | None = None,
        root: Path | None = None,
    ) -> ValidationResult:
        """Validate ``path``.

        ``known_hashes`` is an optional collection of SHA-256 hex digests that
        have already been accepted into a corpus; a matching digest produces
        a :attr:`ValidationIssueCode.DUPLICATE_CONTENT` issue.

        ``root``, when provided, is the directory that symlinks must stay
        inside.  This is a defence against a corpus directory containing a
        symlink to ``/etc/passwd`` or similar.
        """
        candidate = Path(path)
        issues: list[ValidationIssue] = []

        if not candidate.name:
            return self._invalid(candidate, ValidationIssueCode.PATH_EMPTY,
                                 "Path has no file name")

        # --- symlink policy -------------------------------------------------
        if candidate.is_symlink():
            if self._config.reject_symlinks:
                if root is not None and not self._resolves_inside(candidate, root):
                    return self._invalid(
                        candidate,
                        ValidationIssueCode.SYMLINK_OUTSIDE_ROOT,
                        f"Symlink resolves outside the corpus root: {candidate}",
                    )
                return self._invalid(
                    candidate,
                    ValidationIssueCode.NOT_A_FILE,
                    "Symlinks are rejected by configuration",
                )

        # --- must exist and be a regular file -------------------------------
        try:
            stat_result = candidate.stat()
        except FileNotFoundError:
            return self._invalid(
                candidate, ValidationIssueCode.NOT_A_FILE, "Path does not exist"
            )
        except OSError as exc:
            return self._invalid(
                candidate,
                ValidationIssueCode.IO_ERROR,
                f"stat() failed: {exc}",
            )

        if not stat.S_ISREG(stat_result.st_mode):
            return self._invalid(
                candidate,
                ValidationIssueCode.NOT_A_FILE,
                "Path is not a regular file",
            )

        if not os.access(candidate, os.R_OK):
            return self._invalid(
                candidate,
                ValidationIssueCode.NOT_READABLE,
                "File is not readable",
            )

        # --- size -----------------------------------------------------------
        size = stat_result.st_size
        if size < self._config.min_size_bytes:
            issues.append(
                ValidationIssue(
                    ValidationIssueCode.TOO_SMALL,
                    f"File is {size} bytes; minimum is {self._config.min_size_bytes}",
                )
            )
        if size > self._config.max_size_bytes:
            issues.append(
                ValidationIssue(
                    ValidationIssueCode.TOO_LARGE,
                    f"File is {size} bytes; maximum is {self._config.max_size_bytes}",
                )
            )

        if size == 0:
            issues.append(ValidationIssue(ValidationIssueCode.EMPTY_FILE, "File is empty"))

        # --- content hash ---------------------------------------------------
        needs_hash = self._config.compute_sha256 or known_hashes is not None
        sha256: str | None = None
        if needs_hash:
            try:
                sha256, _ = _hash_file(candidate)
            except OSError as exc:
                issues.append(
                    ValidationIssue(
                        ValidationIssueCode.IO_ERROR, f"Read failed: {exc}"
                    )
                )

        if sha256 is not None and known_hashes is not None:
            if sha256 in set(known_hashes):
                issues.append(
                    ValidationIssue(
                        ValidationIssueCode.DUPLICATE_CONTENT,
                        f"Content matches an already-imported entry ({sha256[:12]}…)",
                    )
                )

        return ValidationResult(
            path=candidate,
            valid=not issues,
            size_bytes=size,
            sha256=sha256,
            issues=issues,
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _invalid(
        path: Path, code: ValidationIssueCode, message: str
    ) -> ValidationResult:
        return ValidationResult(
            path=path,
            valid=False,
            issues=[ValidationIssue(code, message)],
        )

    @staticmethod
    def _resolves_inside(candidate: Path, root: Path) -> bool:
        try:
            resolved = candidate.resolve()
            root_resolved = root.resolve()
        except OSError:
            return False
        try:
            resolved.relative_to(root_resolved)
        except ValueError:
            return False
        return True
