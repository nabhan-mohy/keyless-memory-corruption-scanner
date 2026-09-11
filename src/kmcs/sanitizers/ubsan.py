"""UndefinedBehaviorSanitizer adapter.

UBSan detects undefined behaviour that the C/C++ standard forbids but that
compilers routinely accept silently.  It is *not* a memory-safety detector: it
does not find heap overflows.  KMCS keeps it distinct so that a UBSan finding
is never reported as a memory corruption.
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
from kmcs.sanitizers.options import UndefinedSanitizerOptions

__all__ = ["UndefinedBehaviorSanitizerAdapter"]


@register
class UndefinedBehaviorSanitizerAdapter(SanitizerAdapter):
    spec: ClassVar[SanitizerSpec] = SanitizerSpec(
        kind=SanitizerKind.UNDEFINED,
        name="UndefinedBehaviorSanitizer",
        compiler_flags=(
            "-fsanitize=undefined",
            "-fno-sanitize-recover=all",
            "-g",
        ),
        linker_flags=("-fsanitize=undefined",),
        runtime_env_var="UBSAN_OPTIONS",
        afl_env_var="AFL_USE_UBSAN",
        log_format=SanitizerLogFormat.UBSAN,
        error_pattern=re.compile(r"runtime error:"),
        description=(
            "Detects signed integer overflow, shift-out-of-range, division by "
            "zero, misaligned access, and other undefined behaviour."
        ),
    )

    @classmethod
    def build_environment(
        cls, base: Mapping[str, str], **options: Any
    ) -> dict[str, str]:
        opts = UndefinedSanitizerOptions(**options)
        env = dict(base)
        existing = env.get(cls.spec.runtime_env_var, "")
        rendered = opts.to_environment()
        env[cls.spec.runtime_env_var] = (
            f"{existing}:{rendered}" if existing else rendered
        )
        return env
