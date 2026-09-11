"""Shared base class for TUI list screens.

Every list screen has the same shape:

* a header bar with version, data directory, and database status,
* a title bar with the screen name and a one-line summary,
* a side-by-side layout: a data table on the left, a detail pane on the right,
* a footer with keybinding hints.

Concrete screens override:

* :meth:`columns` — list of ``(key, label)`` pairs, one per column.
* :meth:`load_rows` — list of tuples, one per row.
* :meth:`detail_pairs` — return a list of ``(key, value)`` pairs for the
  selected row, or ``None``.
* :meth:`summary_line` — return a one-line summary for the title bar.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Static

from kmcs.tui.context import TUIContext
from kmcs.tui.widgets.detail import DetailPane
from kmcs.tui.widgets.footer import AppFooter
from kmcs.tui.widgets.header import AppHeader
from kmcs.tui.widgets.table import KMCSDataTable


class KMCSListScreen(Screen):
    """Base class for screens that display a table of rows from a manager."""

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
    #summary {
        width: 1fr;
        color: $text-muted;
        text-align: right;
    }
    #panes {
        height: 1fr;
    }
    #table-pane {
        width: 3fr;
        height: 1fr;
        border: round $panel;
    }
    #detail-pane {
        width: 2fr;
        height: 1fr;
        border: round $panel;
    }
    """

    title: str = "Screen"
    empty_message: str = "No results."

    # ------------------------------------------------------------------ override points

    def columns(self) -> Sequence[tuple[str, str]]:
        raise NotImplementedError

    def load_rows(self) -> Sequence[tuple[Any, ...]]:
        raise NotImplementedError

    def detail_pairs(self, row: Sequence[Any] | None) -> list[tuple[str, str]] | None:
        return None

    def summary_line(self) -> str:
        """Return a one-line summary for the title bar.  Override per screen."""
        return ""

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit"

    # ------------------------------------------------------------------ layout

    def compose(self) -> ComposeResult:
        yield AppHeader(id="header")
        with Horizontal(id="title-bar"):
            yield Static(f"[b]{self.title}[/b]", id="screen-title")
            yield Static("", id="summary")
        with Horizontal(id="panes"):
            yield KMCSDataTable(
                self.columns(),
                id="table-pane",
                empty_message=self.empty_message,
            )
            yield DetailPane(id="detail-pane")
        yield AppFooter(id="footer")

    def on_mount(self) -> None:
        self._paint_header()
        self.refresh_data()
        self.query_one("#footer", AppFooter).hint = self.hint()

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

    def refresh_data(self) -> None:
        """Reload rows into the table and repaint the summary and detail."""
        table = self.query_one("#table-pane", KMCSDataTable)
        try:
            rows = list(self.load_rows())
        except Exception as exc:
            rows = []
            self.query_one("#detail-pane", DetailPane).set_text(
                f"[red]Error loading data:[/red] {exc}"
            )
        table.set_rows(rows)

        try:
            self.query_one("#summary", Static).update(self.summary_line())
        except Exception:
            pass

        self._paint_detail_for_current_row()

    def _paint_detail_for_current_row(self) -> None:
        table = self.query_one("#table-pane", KMCSDataTable)
        row = table.selected_row
        pane = self.query_one("#detail-pane", DetailPane)
        pairs = self.detail_pairs(row)
        if pairs is None:
            pane.set_text(
                "[dim]Select a row and use the arrow keys to view its details.[/dim]"
            )
        else:
            pane.set_pairs(pairs)

    # ------------------------------------------------------------------ events

    def on_data_table_row_highlighted(self, event) -> None:  # type: ignore[no-untyped-def]
        self._paint_detail_for_current_row()

    def on_data_table_row_selected(self, event) -> None:  # type: ignore[no-untyped-def]
        self._paint_detail_for_current_row()

    # ------------------------------------------------------------------ actions

    def action_refresh(self) -> None:
        self.refresh_data()
