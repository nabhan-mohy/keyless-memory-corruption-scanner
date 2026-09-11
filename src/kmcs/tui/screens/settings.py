"""The Settings screen.

Read-only view of the current KMCS configuration: workspace paths,
logging level, and the database URL.  Settings cannot be edited from the
TUI in this release; the screen exists so a user can see exactly where
everything lives.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from kmcs.tui.screens.base import KMCSListScreen


class SettingsScreen(KMCSListScreen):
    """A read-only view of the current KMCS configuration."""

    title = "Settings"
    empty_message = "No configuration available."

    def columns(self) -> Sequence[tuple[str, str]]:
        return (
            ("key", "Key"),
            ("value", "Value"),
        )

    def load_rows(self) -> Sequence[tuple[Any, ...]]:
        config = self.ctx.config
        return [
            ("base dir", str(config.base_dir)),
            ("database file", str(config.database_file)),
            ("database URL", config.database_url or "(SQLite file)"),
            ("logs directory", str(config.logs_path)),
            ("crashes directory", str(config.crashes_path)),
            ("corpus directory", str(config.corpus_path)),
            ("reports directory", str(config.reports_path)),
            ("log level", config.log_level),
            ("create missing dirs", str(config.create_missing_dirs)),
        ]

    def detail_pairs(
        self, row: Sequence[Any] | None
    ) -> list[tuple[str, str]] | None:
        if row is None:
            return None
        return [
            ("Key", str(row[0])),
            ("Value", str(row[1])),
        ]

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit  [b]1[/b] dashboard"
