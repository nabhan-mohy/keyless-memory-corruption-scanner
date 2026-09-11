"""The Settings screen.

A read-only view of the current KMCS configuration and the state of the
database.  The detail pane shows the selected setting plus a short
description of what it controls.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from kmcs.tui.screens.base import KMCSListScreen


_SETTING_DESCRIPTIONS: dict[str, str] = {
    "base dir": "Root directory for all KMCS data.",
    "database file": "SQLite file that stores targets, campaigns, and findings.",
    "database URL": "SQLAlchemy URL used to open the database.",
    "logs directory": "Where KMCS writes its log file.",
    "crashes directory": "Where preserved crash evidence is written.",
    "corpus directory": "Where imported corpus files are stored.",
    "reports directory": "Where generated reports are written.",
    "log level": "Python logging level for the CLI and TUI.",
    "create missing dirs": "Whether KMCS creates missing directories at startup.",
}


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

    def summary_line(self) -> str:
        return (
            f"read-only · {len(list(self.ctx.config.directories))} paths · "
            f"log level {self.ctx.config.log_level}"
        )

    def detail_pairs(
        self, row: Sequence[Any] | None
    ) -> list[tuple[str, str]] | None:
        if row is None:
            return None
        key = str(row[0])
        value = str(row[1])
        pairs: list[tuple[str, str]] = [
            ("Setting", key),
            ("Value", value),
        ]
        desc = _SETTING_DESCRIPTIONS.get(key)
        if desc:
            pairs.append(("Description", desc))

        if key == "database file" or key == "database URL":
            try:
                health = self.ctx.database.health_check()
                pairs += [
                    ("Health", "ok" if health.ok else "FAILED"),
                    ("Schema version", str(health.schema_version)),
                    ("Integrity", health.integrity or "—"),
                    ("Tables present", ", ".join(health.tables_present)),
                ]
            except Exception as exc:
                pairs.append(("Health check error", str(exc)))

        return pairs

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit  [b]1[/b] dashboard"
