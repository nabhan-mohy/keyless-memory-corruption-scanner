"""Shared base class for TUI list screens.

Every list screen in the TUI — Targets, Corpora, Campaigns, Crashes,
Findings, Reports — has the same shape:

* a header bar showing the app version and the data directory,
* one or more data tables,
* a scrollable detail pane,
* a footer with keybinding hints.

Rather than repeating that structure seven times, the base class defines it
once.  A concrete screen only needs to provide the column definitions, the
row data, and (optionally) the detail pairs for a selected row.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Static

from kmcs.tui.context import TUIContext
from kmcs.tui.widgets.detail import DetailPane
from kmcs.tui.widgets.footer import AppFooter
from kmcs.tui.widgets.header import AppHeader
from kmcs.tui.widgets.table import KMCSDataTable


class KMCSListScreen(Screen):
    """Base class for screens that display a table of rows from a manager.

    Subclasses override:

    * :meth:`columns` — list of ``(key, label)`` pairs, one per column.
    * :meth:`load_rows` — list of tuples, one per row.
    * :meth:`detail_pairs` — optional; return a list of ``(key, value)``
      pairs for the currently selected row, or ``None`` for no detail.

    Subclasses may also override :meth:`hint` to customise the footer text.
    """

    # ------------------------------------------------------------------ override points

    title: str = "Screen"
    empty_message: str = "No results."

    def columns(self) -> Sequence[tuple[str, str]]:
        raise NotImplementedError

    def load_rows(self) -> Sequence[tuple[Any, ...]]:
        raise NotImplementedError

    def detail_pairs(self, row: Sequence[Any] | None) -> list[tuple[str, str]] | None:
        """Return key/value pairs for the selected row, or ``None``."""
        return None

    def hint(self) -> str:
        """Return the footer keybinding hint for this screen."""
        return "[b]r[/b] refresh  [b]q[/b] quit"

    # ------------------------------------------------------------------ layout

    def compose(self) -> ComposeResult:
        yield AppHeader(id="header")
        with Vertical():
            yield Static(
                f"[b]{self.title}[/b]",
                id="screen-title",
            )
            yield KMCSDataTable(
                self.columns(),
                id="table",
                empty_message=self.empty_message,
            )
            yield DetailPane(id="detail")
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
        """Reload rows into the table and repaint the detail pane."""
        table = self.query_one("#table", KMCSDataTable)
        try:
            rows = list(self.load_rows())
        except Exception as exc:
            rows = []
            self.query_one("#detail", DetailPane).set_text(
                f"[red]Error loading data:[/red] {exc}"
            )
        table.set_rows(rows)
        self._paint_detail_for_current_row()

    def _paint_detail_for_current_row(self) -> None:
        table = self.query_one("#table", KMCSDataTable)
        row = table.selected_row
        pane = self.query_one("#detail", DetailPane)
        pairs = self.detail_pairs(row)
        if pairs is None:
            pane.set_text(
                "[dim]Select a row and press the arrow keys to view details.[/dim]"
            )
        else:
            pane.set_pairs(pairs)

    # ------------------------------------------------------------------ events

    def on_data_table_row_highlighted(
        self, event
    ) -> None:  # type: ignore[no-untyped-def]
        """Repaint the detail pane when the cursor moves."""
        self._paint_detail_for_current_row()

    def on_data_table_row_selected(
        self, event
    ) -> None:  # type: ignore[no-untyped-def]
        """Handle the Enter key on a row — subclasses may override."""
        self._paint_detail_for_current_row()

    # ------------------------------------------------------------------ actions

    def action_refresh(self) -> None:
        self.refresh_data()
