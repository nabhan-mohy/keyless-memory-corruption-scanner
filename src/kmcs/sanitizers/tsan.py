"""ThreadSanitizer adapter.

TSan detects data races between threads.  It is fundamentally incompatible with
AddressSanitizer; a target built with both will refuse to start, and KMCS
records that fact in the availability reason rather than silently dropping one.
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
from kmcs.sanitizers.options import ThreadSanitizerOptions

__all__ = ["ThreadSanitizerAdapter"]


@register
class ThreadSanitizerAdapter(SanitizerAdapter):
    spec: ClassVar[SanitizerSpec] = SanitizerSpec(
        kind=SanitizerKind.THREAD,
        name="ThreadSanitizer",
        compiler_flags=(
            "-fsanitize=thread",
            "-fno-omit-frame-pointer",
            "-g",
        ),
        linker_flags=("-fsanitize=thread",),
        runtime_env_var="TSAN_OPTIONS",
        afl_env_var="AFL_USE_TSAN",
        log_format=SanitizerLogFormat.TSAN,
        error_pattern=re.compile(
            r"WARNING:\s*ThreadSanitizer|data race|thread leak"
        ),
        description=(
            "Detects data races and thread leaks. Cannot be combined with "
            "AddressSanitizer in the same binary."
        ),
    )

    @classmethod
    def build_environment(
        cls, base: Mapping[str, str], **options: Any
    ) -> dict[str, str]:
        opts = ThreadSanitizerOptions(**options)
        env = dict(base)
        existing = env.get(cls.spec.runtime_env_var, "")
        rendered = opts.to_environment()
        env[cls.spec.runtime_env_var] = (
            f"{existing}:{rendered}" if existing else rendered
        )
        return env
