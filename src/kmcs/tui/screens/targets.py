"""The Targets screen.

Lists every target registered with KMCS.  Shows name, build configuration,
compiler, sanitizers, and the executable path.  The detail pane shows the
full record for the selected target, including its description and metadata.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from kmcs.tui.screens.base import KMCSListScreen


class TargetsScreen(KMCSListScreen):
    """A list of every registered target."""

    title = "Targets"
    empty_message = "No targets registered. Use `kmcs target add` to add one."

    def columns(self) -> Sequence[tuple[str, str]]:
        return (
            ("id", "ID"),
            ("name", "Name"),
            ("build", "Build"),
            ("sanitizers", "Sanitizers"),
            ("compiler", "Compiler"),
            ("executable", "Executable"),
        )

    def load_rows(self) -> Sequence[tuple[Any, ...]]:
        targets = self.ctx.targets.list()
        return [
            (
                t.id[:8],
                t.name,
                t.build_configuration.value,
                ", ".join(s.value for s in t.sanitizers) or "—",
                t.compiler or "—",
                str(t.executable) if t.executable else "—",
            )
            for t in targets
        ]

    def detail_pairs(
        self, row: Sequence[Any] | None
    ) -> list[tuple[str, str]] | None:
        if row is None:
            return None
        target_id_prefix = row[0]
        target = self._resolve_target_by_prefix(target_id_prefix)
        if target is None:
            return None
        return [
            ("ID", target.id),
            ("Name", target.name),
            ("Description", target.description or "—"),
            ("Source directory", str(target.source_dir) if target.source_dir else "—"),
            ("Build directory", str(target.build_dir) if target.build_dir else "—"),
            ("Executable", str(target.executable) if target.executable else "—"),
            ("Harness path", str(target.harness_path) if target.harness_path else "—"),
            ("Compiler", target.compiler or "—"),
            ("Build configuration", target.build_configuration.value),
            (
                "Sanitizers",
                ", ".join(s.value for s in target.sanitizers) or "—",
            ),
            ("Created", target.created_at.isoformat()),
            ("Updated", target.updated_at.isoformat()),
        ]

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit  [b]1[/b] dashboard"

    # ------------------------------------------------------------------ helpers

    def _resolve_target_by_prefix(self, prefix: str):
        """Look up a target by the first 8 characters of its id."""
        for target in self.ctx.targets.list():
            if target.id.startswith(prefix):
                return target
        return None
