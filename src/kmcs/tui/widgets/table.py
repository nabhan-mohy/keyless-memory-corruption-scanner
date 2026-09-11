"""A generic data table.

Screens provide column definitions and row data; the widget handles
selection, cursor movement, and the "no results" state.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Any

from textual.app import ComposeResult
from textual.widget import Widget
from textual.widgets import DataTable


class KMCSDataTable(Widget):
    """A DataTable with a consistent look and a placeholder for empty data."""

    DEFAULT_CSS = """
    KMCSDataTable {
        height: 1fr;
    }
    KMCSDataTable DataTable {
        height: 1fr;
    }
    """

    def __init__(
        self,
        columns: Sequence[tuple[str, str]],
        *,
        empty_message: str = "No results.",
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._columns = list(columns)
        self._empty_message = empty_message

    def compose(self) -> ComposeResult:
        table = DataTable(id="data", zebra_stripes=True, cursor_type="row")
        for key, label in self._columns:
            table.add_column(label, key=key)
        yield table

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.focus()

    def set_rows(self, rows: Iterable[Sequence[Any]]) -> None:
        """Replace the table contents."""
        table = self.query_one(DataTable)
        table.clear()
        materialised = list(rows)
        if not materialised:
            padding = [""] * (len(self._columns) - 1)
            table.add_row(self._empty_message, *padding)
            return
        for row in materialised:
            table.add_row(*row)

    @property
    def selected_row(self) -> Sequence[Any] | None:
        table = self.query_one(DataTable)
        if table.row_count == 0:
            return None
        try:
            return table.get_row_at(table.cursor_row)
        except Exception:
            return None
