"""LeakSanitizer adapter.

LSan detects memory that was allocated and never freed.  It is available as a
standalone runtime (``-fsanitize=leak``) and, more commonly, as a component
of the AddressSanitizer runtime.  KMCS models it standalone so the parser can
distinguish leak reports from corruption reports.
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
from kmcs.sanitizers.options import LeakSanitizerOptions

__all__ = ["LeakSanitizerAdapter"]


@register
class LeakSanitizerAdapter(SanitizerAdapter):
    spec: ClassVar[SanitizerSpec] = SanitizerSpec(
        kind=SanitizerKind.LEAK,
        name="LeakSanitizer",
        compiler_flags=("-fsanitize=leak", "-g"),
        linker_flags=("-fsanitize=leak",),
        runtime_env_var="LSAN_OPTIONS",
        afl_env_var="AFL_USE_LSAN",
        log_format=SanitizerLogFormat.LSAN,
        error_pattern=re.compile(
            r"ERROR:\s*LeakSanitizer|Direct leak of|Indirect leak of"
        ),
        description="Detects memory allocated during the process that was never freed.",
    )

    @classmethod
    def build_environment(
        cls, base: Mapping[str, str], **options: Any
    ) -> dict[str, str]:
        opts = LeakSanitizerOptions(**options)
        env = dict(base)
        existing = env.get(cls.spec.runtime_env_var, "")
        rendered = opts.to_environment()
        env[cls.spec.runtime_env_var] = (
            f"{existing}:{rendered}" if existing else rendered
        )
        return env
