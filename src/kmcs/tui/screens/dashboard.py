"""The Dashboard screen.

The first screen a user sees.  It summarises the KMCS workspace:

* a health bar with the database status, schema version, integrity, and the
  current counts of every work item,
* three side-by-side tables: recent campaigns, recent findings, recent
  crashes,
* a footer with navigation hints.

Column headers are deliberately short (``State``, ``Fuzz``, ``Time``,
``Hits``, ``Sig``, ``Fp``) so that they fit inside the narrow panels.  Long
values are truncated rather than wrapping, which would break the table
alignment.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Static

from kmcs.tui.context import TUIContext
from kmcs.tui.widgets.footer import AppFooter
from kmcs.tui.widgets.header import AppHeader
from kmcs.tui.widgets.table import KMCSDataTable


def _truncate(value: str, limit: int) -> str:
    """Return ``value`` truncated to ``limit`` characters, with an ellipsis."""
    text = "" if value is None else str(value)
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


class DashboardScreen(Screen):
    """Overview of the KMCS workspace."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #title-bar {
        height: 1;
        padding: 0 1;
        background: $surface;
    }
    #screen-title {
        width: auto;
        color: $accent;
        text-style: bold;
    }
    #health {
        width: 1fr;
        color: $text-muted;
        text-align: right;
    }
    #panes {
        height: 1fr;
    }
    #recent-campaigns-pane,
    #recent-findings-pane,
    #recent-crashes-pane {
        height: 1fr;
        border: round $panel;
        padding: 0 1;
    }
    #recent-campaigns-pane { width: 2fr; }
    #recent-findings-pane { width: 2fr; }
    #recent-crashes-pane { width: 3fr; }
    """

    BINDINGS = [
        ("r", "refresh", "Refresh"),
    ]

    def compose(self) -> ComposeResult:
        yield AppHeader(id="header")
        with Horizontal(id="title-bar"):
            yield Static("[b]Dashboard[/b]", id="screen-title")
            yield Static("", id="health")
        with Horizontal(id="panes"):
            yield KMCSDataTable(
                [
                    ("name", "Campaign"),
                    ("status", "State"),
                    ("fuzzer", "Fuzz"),
                    ("duration", "Time"),
                ],
                id="recent-campaigns-pane",
                empty_message="No campaigns yet.",
            )
            yield KMCSDataTable(
                [
                    ("severity", "Sev"),
                    ("classification", "Class"),
                    ("title", "Title"),
                    ("occurrences", "Hits"),
                ],
                id="recent-findings-pane",
                empty_message="No findings yet.",
            )
            yield KMCSDataTable(
                [
                    ("id", "Crash ID"),
                    ("class", "Classification"),
                    ("signal", "Sig"),
                    ("fingerprint", "Fingerprint"),
                ],
                id="recent-crashes-pane",
                empty_message="No crashes yet.",
            )
        yield AppFooter(id="footer")

    # ------------------------------------------------------------------ lifecycle

    def on_mount(self) -> None:
        self._paint_header()
        self._paint_health()
        self._paint_recent_campaigns()
        self._paint_recent_findings()
        self._paint_recent_crashes()
        self.query_one("#footer", AppFooter).hint = (
            "[b]r[/b] refresh   "
            "[b]2[/b] targets  [b]3[/b] corpora  [b]4[/b] campaigns   "
            "[b]5[/b] crashes  [b]6[/b] findings   "
            "[b]7[/b] reports  [b]8[/b] settings   "
            "[b]q[/b] quit"
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

    def _paint_health(self) -> None:
        widget = self.query_one("#health", Static)
        parts: list[str] = []

        try:
            health = self.ctx.database.health_check()
            parts.append(f"db {'ok' if health.ok else 'FAIL'}")
            parts.append(f"schema v{health.schema_version}")
            if health.integrity:
                parts.append(f"integrity {health.integrity}")
        except Exception as exc:
            parts.append(f"[red]db error: {exc}[/red]")

        counts = self._counts()
        parts.append(f"{counts['target(s)']} target(s)")
        parts.append(f"{counts['corpus/corpora']} corpus")
        parts.append(f"{counts['campaign(s)']} campaign(s)")
        parts.append(f"{counts['crash(es)']} crash(es)")
        parts.append(f"{counts['finding(s)']} finding(s)")

        widget.update(" · ".join(parts))

    def _counts(self) -> dict[str, int]:
        from sqlalchemy import func, select

        from kmcs.database.models import CrashRow, FindingRow

        ctx = self.ctx
        targets = len(ctx.targets.list())
        corpora = len(ctx.corpora.list())
        campaigns = len(ctx.campaigns.list())
        with ctx.database.session() as session:
            crash_count = (
                session.scalar(select(func.count()).select_from(CrashRow)) or 0
            )
            finding_count = (
                session.scalar(select(func.count()).select_from(FindingRow)) or 0
            )
        return {
            "target(s)": targets,
            "corpus/corpora": corpora,
            "campaign(s)": campaigns,
            "crash(es)": crash_count,
            "finding(s)": finding_count,
        }

    def _paint_recent_campaigns(self) -> None:
        table = self.query_one("#recent-campaigns-pane", KMCSDataTable)
        campaigns = self.ctx.campaigns.list()[:20]
        rows = [
            (
                _truncate(c.name, 18),
                c.status.value[:10],
                c.fuzzer.value,
                f"{c.duration_seconds}s" if c.duration_seconds else "—",
            )
            for c in campaigns
        ]
        table.set_rows(rows)

    def _paint_recent_findings(self) -> None:
        table = self.query_one("#recent-findings-pane", KMCSDataTable)
        from sqlalchemy import select

        from kmcs.database.models import FindingRow

        with self.ctx.database.session() as session:
            rows = session.scalars(
                select(FindingRow)
                .order_by(FindingRow.created_at.desc())
                .limit(20)
            ).all()
            data = [
                (
                    row.severity[:8],
                    _truncate(row.classification, 18),
                    _truncate(row.title, 30),
                    str(len(row.crash_ids or [])),
                )
                for row in rows
            ]
        table.set_rows(data)

    def _paint_recent_crashes(self) -> None:
        table = self.query_one("#recent-crashes-pane", KMCSDataTable)
        from sqlalchemy import select

        from kmcs.database.models import CrashRow

        with self.ctx.database.session() as session:
            rows = session.scalars(
                select(CrashRow)
                .order_by(CrashRow.created_at.desc())
                .limit(20)
            ).all()
            data = [
                (
                    row.id[:8],
                    _truncate(row.classification, 18),
                    str(row.signal) if row.signal is not None else "—",
                    (row.fingerprint or "—")[:14],
                )
                for row in rows
            ]
        table.set_rows(data)

    # ------------------------------------------------------------------ actions

    def action_refresh(self) -> None:
        self._paint_header()
        self._paint_health()
        self._paint_recent_campaigns()
        self._paint_recent_findings()
        self._paint_recent_crashes()
