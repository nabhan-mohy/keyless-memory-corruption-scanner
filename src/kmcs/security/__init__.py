"""Security primitives shared by every subsystem that touches the outside world.

Nothing in KMCS may launch a subprocess, resolve a path, or accept an untrusted
file without going through this package.  The module exists because a fuzzing
platform runs *untrusted input* through *arbitrary code* — that is its whole
purpose — and the containment has to be defensible.
"""

from kmcs.security.limits import ResourceLimits
from kmcs.security.paths import (
    PathSecurityError,
    SafePathResolver,
    ensure_within_root,
    is_within,
)
from kmcs.security.subprocess import (
    SafeSubprocessError,
    SafeSubprocessResult,
    SafeSubprocessRunner,
    minimal_environment,
)
from kmcs.security.validators import (
    ValidationOutcome,
    contains_nul,
    validate_argv,
    validate_environment_name,
)

__all__ = [
    "ResourceLimits",
    "PathSecurityError",
    "SafePathResolver",
    "ensure_within_root",
    "is_within",
    "SafeSubprocessError",
    "SafeSubprocessResult",
    "SafeSubprocessRunner",
    "minimal_environment",
    "ValidationOutcome",
    "contains_nul",
    "validate_argv",
    "validate_environment_name",
]
