"""MemorySanitizer adapter.

MSan detects reads of uninitialised memory.  It requires that the *entire*
program, including all linked libraries, be compiled with MSan; a partial
instrumentation produces false positives that are indistinguishable from real
findings.  KMCS reports this requirement in the availability reason rather
than pretending the sanitizer is usable on any target.
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
from kmcs.sanitizers.options import MemorySanitizerOptions

__all__ = ["MemorySanitizerAdapter"]


@register
class MemorySanitizerAdapter(SanitizerAdapter):
    spec: ClassVar[SanitizerSpec] = SanitizerSpec(
        kind=SanitizerKind.MEMORY,
        name="MemorySanitizer",
        compiler_flags=(
            "-fsanitize=memory",
            "-fno-omit-frame-pointer",
            "-fPIE",
            "-pie",
            "-g",
        ),
        linker_flags=("-fsanitize=memory", "-fPIE", "-pie"),
        runtime_env_var="MSAN_OPTIONS",
        afl_env_var="AFL_USE_MSAN",
        log_format=SanitizerLogFormat.MSAN,
        error_pattern=re.compile(r"WARNING:\s*MemorySanitizer|use-of-uninitialized-value"),
        description=(
            "Detects reads of uninitialised memory. Requires that every linked "
            "object, including libraries, be compiled with MSan."
        ),
    )

    @classmethod
    def build_environment(
        cls, base: Mapping[str, str], **options: Any
    ) -> dict[str, str]:
        opts = MemorySanitizerOptions(**options)
        env = dict(base)
        existing = env.get(cls.spec.runtime_env_var, "")
        rendered = opts.to_environment()
        env[cls.spec.runtime_env_var] = (
            f"{existing}:{rendered}" if existing else rendered
        )
        return env
