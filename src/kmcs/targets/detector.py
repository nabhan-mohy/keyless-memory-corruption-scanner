"""Real environment detection.

Every check in this module performs an actual system call:

* :func:`shutil.which` against ``$PATH``
* a real ``subprocess.run`` invocation of the tool's version flag

There is no hard-coded "assume installed" path.  If a tool is missing, KMCS says
so and later components are expected to react to that.  Detection is deliberately
side-effect free — it never writes to disk, never opens a fuzzer, and never
starts a long-running process.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from kmcs.core.exceptions import KMCSException

logger = logging.getLogger(__name__)

__all__ = [
    "ToolCategory",
    "ToolSpec",
    "ToolInfo",
    "EnvironmentReport",
    "EnvironmentDetector",
    "ToolNotFoundError",
    "KNOWN_TOOLS",
]

# (command, timeout) -> (returncode, stdout, stderr).  Never raises.
Runner = Callable[[list[str], float], tuple[int, str, str]]


class ToolNotFoundError(KMCSException):
    """A required tool is not available on this system."""

    exit_code = 11


class ToolCategory(str, Enum):
    COMPILER = "compiler"
    FUZZER = "fuzzer"
    DEBUGGER = "debugger"
    SYMBOLIZER = "symbolizer"
    BINUTILS = "binutils"
    BUILD = "build"


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    category: ToolCategory
    version_args: tuple[str, ...] = ("--version",)
    description: str = ""


# Only tools KMCS genuinely needs or may need are listed.  Adding an entry here
# does not imply it is installed — detection still runs for real.
KNOWN_TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("cc", ToolCategory.COMPILER, description="System default C compiler"),
    ToolSpec("gcc", ToolCategory.COMPILER),
    ToolSpec("g++", ToolCategory.COMPILER),
    ToolSpec("clang", ToolCategory.COMPILER),
    ToolSpec("clang++", ToolCategory.COMPILER),
    ToolSpec("afl-clang-fast", ToolCategory.COMPILER,
             description="AFL++ clang wrapper (preferred for fuzzing)"),
    ToolSpec("afl-clang-lto", ToolCategory.COMPILER,
             description="AFL++ LTO clang wrapper"),
    ToolSpec("afl-gcc", ToolCategory.COMPILER,
             description="AFL++ gcc wrapper"),
    ToolSpec("afl-fuzz", ToolCategory.FUZZER, version_args=("-h",)),
    ToolSpec("honggfuzz", ToolCategory.FUZZER, version_args=("--help",)),
    ToolSpec("gdb", ToolCategory.DEBUGGER),
    ToolSpec("lldb", ToolCategory.DEBUGGER),
    ToolSpec("llvm-symbolizer", ToolCategory.SYMBOLIZER),
    ToolSpec("addr2line", ToolCategory.SYMBOLIZER),
    ToolSpec("objdump", ToolCategory.BINUTILS),
    ToolSpec("nm", ToolCategory.BINUTILS),
    ToolSpec("readelf", ToolCategory.BINUTILS),
    ToolSpec("make", ToolCategory.BUILD),
    ToolSpec("cmake", ToolCategory.BUILD),
)

_TOOLS_BY_NAME: dict[str, ToolSpec] = {spec.name: spec for spec in KNOWN_TOOLS}


@dataclass(frozen=True, slots=True)
class ToolInfo:
    name: str
    category: ToolCategory
    available: bool
    path: str | None = None
    version: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "available": self.available,
            "path": self.path,
            "version": self.version,
            "error": self.error,
        }


@dataclass(slots=True)
class EnvironmentReport:
    tools: dict[str, ToolInfo] = field(default_factory=dict)

    def get(self, name: str) -> ToolInfo | None:
        return self.tools.get(name)

    def available(self, name: str) -> bool:
        info = self.tools.get(name)
        return bool(info and info.available)

    def require(self, name: str) -> ToolInfo:
        info = self.tools.get(name)
        if info is None:
            raise ToolNotFoundError(
                f"Unknown tool: {name}",
                details={"known": sorted(self.tools)},
            )
        if not info.available:
            raise ToolNotFoundError(
                f"Required tool is not available: {name}",
                details={"reason": info.error or "not found on $PATH"},
            )
        return info

    def by_category(self, category: ToolCategory) -> list[ToolInfo]:
        return [info for info in self.tools.values() if info.category is category]

    def available_names(self) -> list[str]:
        return sorted(name for name, info in self.tools.items() if info.available)

    def missing_names(self) -> list[str]:
        return sorted(name for name, info in self.tools.items() if not info.available)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tools": {name: info.to_dict() for name, info in sorted(self.tools.items())},
            "available": self.available_names(),
            "missing": self.missing_names(),
        }


def _default_runner(cmd: list[str], timeout: float) -> tuple[int, str, str]:
    """Run ``cmd`` and capture its output.  Never raises."""
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout or "", completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return -1, stdout, stderr or "timed out"
    except (FileNotFoundError, NotADirectoryError, PermissionError, OSError) as exc:
        return -1, "", str(exc)


def _first_line(*chunks: str) -> str | None:
    for chunk in chunks:
        for line in chunk.splitlines():
            cleaned = line.strip()
            if cleaned:
                return cleaned
    return None


class EnvironmentDetector:
    """Detects which external tools KMCS can actually use.

    ``which`` and ``runner`` are injectable so tests can exercise the logic
    without depending on the host's toolchain.
    """

    def __init__(
        self,
        *,
        which: Callable[[str], str | None] = shutil.which,
        runner: Runner | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._which = which
        self._runner = runner or _default_runner
        self._timeout = float(timeout)

    # ------------------------------------------------------------------ single

    def detect(self, name: str) -> ToolInfo:
        spec = _TOOLS_BY_NAME.get(name)
        if spec is None:
            return ToolInfo(
                name=name,
                category=ToolCategory.BINUTILS,
                available=False,
                error=f"Unknown tool: {name}",
            )

        try:
            path = self._which(spec.name)
        except Exception as exc:  # noqa: BLE001 - never let detection crash
            return ToolInfo(
                name=spec.name,
                category=spec.category,
                available=False,
                error=f"which() failed: {exc}",
            )

        if not path:
            return ToolInfo(
                name=spec.name,
                category=spec.category,
                available=False,
                error="not found on $PATH",
            )

        returncode, stdout, stderr = self._runner(
            [path, *spec.version_args], self._timeout
        )
        version = _first_line(stdout, stderr)

        # A non-zero exit here is not disqualifying: AFL++'s ``-h`` and gdb's
        # ``--version`` both behave differently across versions.  What matters is
        # that the binary ran and produced text.
        if version is None and returncode != 0:
            return ToolInfo(
                name=spec.name,
                category=spec.category,
                available=False,
                path=path,
                error=f"version check failed (exit {returncode})",
            )

        return ToolInfo(
            name=spec.name,
            category=spec.category,
            available=True,
            path=path,
            version=version,
        )

    # ------------------------------------------------------------------ bulk

    def detect_all(self, names: Iterable[str] | None = None) -> EnvironmentReport:
        targets = list(names) if names is not None else [spec.name for spec in KNOWN_TOOLS]
        return EnvironmentReport({name: self.detect(name) for name in targets})

    def detect_category(self, category: ToolCategory) -> EnvironmentReport:
        names = [spec.name for spec in KNOWN_TOOLS if spec.category is category]
        return self.detect_all(names)
