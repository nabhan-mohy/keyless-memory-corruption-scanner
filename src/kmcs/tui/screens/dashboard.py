"""The Dashboard screen.

The first screen a user sees.  It summarises the KMCS workspace: how many
targets, corpora, campaigns, crashes, and findings exist; the database
health; and the most recent campaigns and findings.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Static

from kmcs.tui.context import TUIContext
from kmcs.tui.widgets.detail import DetailPane
from kmcs.tui.widgets.footer import AppFooter
from kmcs.tui.widgets.header import AppHeader
from kmcs.tui.widgets.table import KMCSDataTable


class DashboardScreen(Screen):
    """Overview of the KMCS workspace."""

    BINDINGS = [
        ("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield AppHeader(id="header")
        with Vertical():
            yield Static("", id="summary")
            with Horizontal():
                yield KMCSDataTable(
                    [
                        ("name", "Recent campaigns"),
                        ("status", "Status"),
                        ("fuzzer", "Fuzzer"),
                        ("duration", "Duration"),
                    ],
                    id="recent-campaigns",
                    empty_message="No campaigns yet.",
                )
                yield KMCSDataTable(
                    [
                        ("severity", "Severity"),
                        ("classification", "Classification"),
                        ("title", "Title"),
                        ("occurrences", "Occurrences"),
                    ],
                    id="recent-findings",
                    empty_message="No findings yet.",
                )
            yield DetailPane(id="detail")
        yield AppFooter(id="footer")

    # ------------------------------------------------------------------ lifecycle

    def on_mount(self) -> None:
        self._paint_header()
        self._paint_summary()
        self._paint_recent_campaigns()
        self._paint_recent_findings()
        self.query_one("#footer", AppFooter).hint = (
            "[b]r[/b] refresh  [b]q[/b] quit"
        )

    # ------------------------------------------------------------------ data

    @property
    def ctx(self) -> TUIContext:
        return self.app.ctx  # type: ignore[attr-defined]

    def _paint_header(self) -> None:
        header = self.query_one("#header", AppHeader)
        header.base_dir = str(self.ctx.config.base_dir)
        try:
            health = self.ctx.database.health_check()
            header.db_status = "ok" if health.ok else "fail"
        except Exception:
            header.db_status = "fail"

    def _paint_summary(self) -> None:
        ctx = self.ctx
        targets = len(ctx.targets.list())
        corpora = len(ctx.corpora.list())
        campaigns = len(ctx.campaigns.list())

        from sqlalchemy import func, select

        from kmcs.database.models import CrashRow, FindingRow

        with ctx.database.session() as session:
            crash_count = (
                session.scalar(select(func.count()).select_from(CrashRow)) or 0
            )
            finding_count = (
                session.scalar(select(func.count()).select_from(FindingRow)) or 0
            )

        summary = (
            f"[b]Targets[/b] {targets}   "
            f"[b]Corpora[/b] {corpora}   "
            f"[b]Campaigns[/b] {campaigns}   "
            f"[b]Crashes[/b] {crash_count}   "
            f"[b]Findings[/b] {finding_count}"
        )
        self.query_one("#summary", Static).update(summary)

    def _paint_recent_campaigns(self) -> None:
        table = self.query_one("#recent-campaigns", KMCSDataTable)
        campaigns = self.ctx.campaigns.list()[:10]
        rows = [
            (
                c.name,
                c.status.value,
                c.fuzzer.value,
                f"{c.duration_seconds}s" if c.duration_seconds else "—",
            )
            for c in campaigns
        ]
        table.set_rows(rows)

    def _paint_recent_findings(self) -> None:
        table = self.query_one("#recent-findings", KMCSDataTable)
        from sqlalchemy import select

        from kmcs.database.models import FindingRow

        with self.ctx.database.session() as session:
            rows = session.scalars(
                select(FindingRow)
                .order_by(FindingRow.created_at.desc())
                .limit(10)
            ).all()
            data = [
                (
                    row.severity,
                    row.classification,
                    row.title[:60],
                    str(len(row.crash_ids or [])),
                )
                for row in rows
            ]
        table.set_rows(data)

    # ------------------------------------------------------------------ actions

    def action_refresh(self) -> None:
        self._paint_header()
        self._paint_summary()
        self._paint_recent_campaigns()
        self._paint_recent_findings()
