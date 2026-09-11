"""AddressSanitizer adapter.

ASan is KMCS's primary memory-safety detector.  The compiler flags below are
the documented ones for enabling ASan with clang and GCC; the runtime options
come from the typed :class:`AddressSanitizerOptions` builder.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any, ClassVar

from kmcs.core.models import SanitizerKind
from kmcs.sanitizers.base import (
    SanitizerAdapter,
    SanitizerLogFormat,
    SanitizerSpec,
    register,
)
from kmcs.sanitizers.options import AddressSanitizerOptions

__all__ = ["AddressSanitizerAdapter"]


@register
class AddressSanitizerAdapter(SanitizerAdapter):
    spec: ClassVar[SanitizerSpec] = SanitizerSpec(
        kind=SanitizerKind.ADDRESS,
        name="AddressSanitizer",
        compiler_flags=(
            "-fsanitize=address",
            "-fno-omit-frame-pointer",
            "-g",
        ),
        linker_flags=("-fsanitize=address",),
        runtime_env_var="ASAN_OPTIONS",
        afl_env_var="AFL_USE_ASAN",
        log_format=SanitizerLogFormat.ASAN,
        # The first line of any ASan report — matches both the header
        # (``==PID==ERROR: AddressSanitizer: ...``) and the summary line.
        error_pattern=re.compile(
            r"ERROR:\s*AddressSanitizer|SUMMARY:\s*AddressSanitizer"
        ),
        description=(
            "Detects heap, stack, and global buffer overflows, use-after-free, "
            "double-free, invalid-free, and use-after-return at run time."
        ),
    )

    @classmethod
    def build_environment(
        cls, base: Mapping[str, str], **options: Any
    ) -> dict[str, str]:
        opts = AddressSanitizerOptions(**options)
        env = dict(base)
        existing = env.get(cls.spec.runtime_env_var, "")
        rendered = opts.to_environment()
        env[cls.spec.runtime_env_var] = (
            f"{existing}:{rendered}" if existing else rendered
        )
        return env
