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

# Importing the adapter modules triggers their ``@register`` decorators,
# which populate :data:`kmcs.sanitizers.base._REGISTRY`.  Without these
# imports, ``SanitizerRegistry.for_kind()`` returns nothing even though the
# adapters exist on disk.
from kmcs.sanitizers.asan import AddressSanitizerAdapter  # noqa: F401
from kmcs.sanitizers.lsan import LeakSanitizerAdapter  # noqa: F401
from kmcs.sanitizers.msan import MemorySanitizerAdapter  # noqa: F401
from kmcs.sanitizers.tsan import ThreadSanitizerAdapter  # noqa: F401
from kmcs.sanitizers.ubsan import UndefinedBehaviorSanitizerAdapter  # noqa: F401

__all__ = [
    "SanitizerAdapter",
    "SanitizerAvailability",
    "SanitizerSpec",
    "SanitizerRegistry",
    "get_adapter",
    "all_adapters",
    "AddressSanitizerAdapter",
    "LeakSanitizerAdapter",
    "MemorySanitizerAdapter",
    "ThreadSanitizerAdapter",
    "UndefinedBehaviorSanitizerAdapter",
]
