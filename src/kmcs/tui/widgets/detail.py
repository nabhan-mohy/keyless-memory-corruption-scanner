"""A scrollable key/value pane for the detail area of a screen."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widget import Widget
from textual.widgets import Static


class DetailPane(Widget):
    """A scrollable pane that displays a key/value dictionary."""

    DEFAULT_CSS = """
    DetailPane {
        border: round $panel;
        padding: 0 1;
    }
    DetailPane VerticalScroll {
        height: 1fr;
    }
    DetailPane .key {
        color: $primary;
        text-style: bold;
    }
    """

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static("", id="detail-body")

    def set_pairs(self, pairs: list[tuple[str, str]]) -> None:
        body = self.query_one("#detail-body", Static)
        if not pairs:
            body.update("[dim]Select a row to view details.[/dim]")
            return
        width = max((len(k) for k, _ in pairs), default=0)
        lines = [f"[b]{key.ljust(width)}[/b] : {value}" for key, value in pairs]
        body.update("\n".join(lines))

    def set_text(self, text: str) -> None:
        body = self.query_one("#detail-body", Static)
        body.update(text or "[dim](empty)[/dim]")
