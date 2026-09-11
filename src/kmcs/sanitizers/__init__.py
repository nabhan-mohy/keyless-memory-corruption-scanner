"""Sanitizer adapters.

Each module in this package wraps exactly one sanitizer: its compiler flags,
its runtime environment variables, and (where applicable) the patterns that
identify its reports.  The runtime behaviour of a sanitizer lives in the
compiled binary; KMCS is responsible only for:

* asking the sanitizer to produce *structured* output,
* asking it to write *complete* stack traces,
* telling it where to write its log so KMCS can find it,
* and preserving the log verbatim.
"""

from kmcs.sanitizers.base import (
    SanitizerAdapter,
    SanitizerAvailability,
    SanitizerSpec,
    SanitizerRegistry,
    get_adapter,
    all_adapters,
)

__all__ = [
    "SanitizerAdapter",
    "SanitizerAvailability",
    "SanitizerSpec",
    "SanitizerRegistry",
    "get_adapter",
    "all_adapters",
]
