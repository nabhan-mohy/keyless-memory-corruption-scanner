
"""The Targets screen.

Richer than the previous version: the detail pane shows the target's full
record plus related counts (campaigns, crashes) so a researcher can see at a
glance how much work the target has seen.
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

    def summary_line(self) -> str:
        targets = self.ctx.targets.list()
        total = len(targets)
        with_exec = sum(1 for t in targets if t.executable)
        with_harness = sum(1 for t in targets if t.harness_path)
        with_sanitizers = sum(1 for t in targets if t.sanitizers)
        return (
            f"{total} target(s) · "
            f"{with_exec} with executable · "
            f"{with_harness} with harness · "
            f"{with_sanitizers} with sanitizers"
        )

    def detail_pairs(
        self, row: Sequence[Any] | None
    ) -> list[tuple[str, str]] | None:
        if row is None:
            return None
        target = self._resolve_target_by_prefix(row[0])
        if target is None:
            return None

        # Count related work items.
        campaigns = [
            c for c in self.ctx.campaigns.list() if c.target_id == target.id
        ]
        campaign_count = len(campaigns)

        from sqlalchemy import func, select

        from kmcs.database.models import CrashRow

        with self.ctx.database.session() as session:
            crash_count = (
                session.scalar(
                    select(func.count())
                    .select_from(CrashRow)
                    .where(CrashRow.target_id == target.id)
                )
                or 0
            )

        pairs: list[tuple[str, str]] = [
            ("ID", target.id),
            ("Name", target.name),
            ("Description", target.description or "—"),
        ]

        pairs += [
            ("Related campaigns", str(campaign_count)),
            ("Related crashes", str(crash_count)),
        ]

        pairs += [
            ("Compiler", target.compiler or "—"),
            ("Build configuration", target.build_configuration.value),
            (
                "Sanitizers",
                ", ".join(s.value for s in target.sanitizers) or "—",
            ),
        ]

        pairs += [
            ("Source directory", str(target.source_dir) if target.source_dir else "—"),
            ("Build directory", str(target.build_dir) if target.build_dir else "—"),
            ("Executable", str(target.executable) if target.executable else "—"),
            ("Harness path", str(target.harness_path) if target.harness_path else "—"),
        ]

        if campaigns:
            recent = campaigns[:5]
            sample = "\n".join(
                f"{c.name} — {c.status.value}"
                for c in recent
            )
            if len(campaigns) > 5:
                sample += f"\n… ({len(campaigns) - 5} more)"
            pairs.append(("Recent campaigns", sample))

        pairs += [
            ("Created", target.created_at.isoformat()),
            ("Updated", target.updated_at.isoformat()),
        ]
        return pairs

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit  [b]1[/b] dashboard"

    # ------------------------------------------------------------------ helpers

    def _resolve_target_by_prefix(self, prefix: str):
        for target in self.ctx.targets.list():
            if target.id.startswith(prefix):
                return target
        return None
