"""Terminal output helpers.

The CLI supports two output modes: human (default) and JSON.  Human mode uses
ANSI colour when writing to a TTY and ``--no-color`` was not passed; JSON mode
never emits colour and is the format to use from a script.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterable, Sequence
from typing import Any, TextIO

__all__ = [
    "ExitCode",
    "Output",
]


class ExitCode:
    """Process exit codes used by the CLI.  Documented in ``kmcs --help``."""

    OK = 0
    GENERIC_ERROR = 1
    USAGE_ERROR = 2
    NOT_FOUND = 3
    PRECONDITION_FAILED = 4
    EXTERNAL_TOOL_MISSING = 5


class Output:
    """A small, stateful printer.

    Constructed once per CLI invocation with the resolved ``--json`` and
    ``--no-color`` flags.  Commands call methods on it rather than printing
    directly, so colour and stream selection are handled in one place.
    """

    def __init__(
        self,
        *,
        json_mode: bool = False,
        color: bool | None = None,
        stdout: TextIO | None = None,
        stderr: TextIO | None = None,
    ) -> None:
        self.json_mode = bool(json_mode)
        self.stdout = stdout if stdout is not None else sys.stdout
        self.stderr = stderr if stderr is not None else sys.stderr
        self.color = self._resolve_color(color)

    # ------------------------------------------------------------------ colour

    def _resolve_color(self, requested: bool | None) -> bool:
        if requested is False:
            return False
        if self.json_mode:
            return False
        if os.environ.get("NO_COLOR"):
            return False
        if requested is True:
            return True
        try:
            return bool(self.stdout.isatty())
        except (AttributeError, ValueError):
            return False

    def _wrap(self, code: str, text: str) -> str:
        if not self.color:
            return text
        return f"\033[{code}m{text}\033[0m"

    def green(self, text: str) -> str:
        return self._wrap("32", text)

    def red(self, text: str) -> str:
        return self._wrap("31", text)

    def yellow(self, text: str) -> str:
        return self._wrap("33", text)

    def blue(self, text: str) -> str:
        return self._wrap("34", text)

    def dim(self, text: str) -> str:
        return self._wrap("2", text)

    def bold(self, text: str) -> str:
        return self._wrap("1", text)

    # ------------------------------------------------------------------ printing

    def line(self, text: str = "") -> None:
        print(text, file=self.stdout)

    def blank(self) -> None:
        print("", file=self.stdout)

    def heading(self, text: str) -> None:
        print(self.bold(text), file=self.stdout)

    def kv(self, pairs: Iterable[tuple[str, Any]]) -> None:
        materialised = [(str(k), self._format_value(v)) for k, v in pairs]
        if not materialised:
            return
        width = max(len(k) for k, _ in materialised)
        for key, value in materialised:
            print(f"{key.ljust(width)} : {value}", file=self.stdout)

    def table(
        self,
        headers: Sequence[str],
        rows: Iterable[Sequence[Any]],
    ) -> None:
        materialised = [
            [self._format_value(cell) for cell in row] for row in rows
        ]
        if not materialised:
            print(self.dim("(no results)"), file=self.stdout)
            return

        widths = [len(h) for h in headers]
        for row in materialised:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(cell))

        def render(cells: Sequence[str]) -> str:
            return "  ".join(
                cell.ljust(widths[i]) for i, cell in enumerate(cells)
            ).rstrip()

        print(self.bold(render(headers)), file=self.stdout)
        print(self.dim(render(["-" * w for w in widths])), file=self.stdout)
        for row in materialised:
            print(render(row), file=self.stdout)

    def json(self, payload: Any) -> None:
        print(
            json.dumps(payload, indent=2, sort_keys=True, default=str),
            file=self.stdout,
        )

    # ------------------------------------------------------------------ messages

    def success(self, message: str) -> None:
        if self.json_mode:
            return
        print(self.green(message), file=self.stdout)

    def info(self, message: str) -> None:
        if self.json_mode:
            return
        print(message, file=self.stdout)

    def warning(self, message: str) -> None:
        if self.json_mode:
            return
        print(self.yellow(f"kmcs: warning: {message}"), file=self.stderr)

    def error(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        if self.json_mode:
            payload: dict[str, Any] = {"ok": False, "error": message}
            if details:
                payload["details"] = {k: str(v) for k, v in details.items()}
            self.json(payload)
            return
        print(self.red(f"kmcs: error: {message}"), file=self.stderr)
        if details:
            for key, value in sorted(details.items()):
                print(f"  {key}: {value}", file=self.stderr)

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _format_value(value: Any) -> str:
        if value is None:
            return "—"
        if isinstance(value, bool):
            return "yes" if value else "no"
        if isinstance(value, (list, tuple)):
            return ", ".join(Output._format_value(v) for v in value)
        return str(value)
