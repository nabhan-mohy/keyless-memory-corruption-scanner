"""Small input validators used at subsystem boundaries."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

__all__ = [
    "ValidationOutcome",
    "contains_nul",
    "validate_argv",
    "validate_environment_name",
]


@dataclass(frozen=True, slots=True)
class ValidationOutcome:
    valid: bool
    issues: tuple[str, ...] = ()

    @classmethod
    def ok(cls) -> "ValidationOutcome":
        return cls(valid=True, issues=())

    @classmethod
    def failed(cls, *issues: str) -> "ValidationOutcome":
        return cls(valid=False, issues=tuple(issues))


def contains_nul(value: str) -> bool:
    return "\x00" in value


def validate_argv(argv: Iterable[str]) -> ValidationOutcome:
    issues: list[str] = []
    for index, token in enumerate(argv):
        if not isinstance(token, str):
            issues.append(f"argv[{index}] is not a string")
        elif contains_nul(token):
            issues.append(f"argv[{index}] contains a NUL byte")
    return ValidationOutcome.ok() if not issues else ValidationOutcome.failed(*issues)


def validate_environment_name(name: str) -> ValidationOutcome:
    """Environment variable names are ``[A-Za-z_][A-Za-z0-9_]*``."""
    if not name:
        return ValidationOutcome.failed("environment variable name is empty")
    if contains_nul(name):
        return ValidationOutcome.failed("environment variable name contains NUL")
    if "=" in name:
        return ValidationOutcome.failed("environment variable name contains '='")
    first = name[0]
    if not (first.isalpha() or first == "_"):
        return ValidationOutcome.failed(
            "environment variable name must start with a letter or underscore"
        )
    for character in name[1:]:
        if not (character.isalnum() or character == "_"):
            return ValidationOutcome.failed(
                f"environment variable name contains invalid character {character!r}"
            )
    return ValidationOutcome.ok()
