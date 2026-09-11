"""A one-line footer showing the keybindings for the current screen."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static


class AppFooter(Widget):
    """A single line of keybinding hints."""

    DEFAULT_CSS = """
    AppFooter {
        height: 1;
        background: $panel;
        color: $text-muted;
        padding: 0 1;
    }
    AppFooter .key {
        color: $primary;
        text-style: bold;
    }
    """

    hint: reactive[str] = reactive("")

    def compose(self) -> ComposeResult:
        yield Static("", id="footer-text")

    def watch_hint(self, value: str) -> None:
        try:
            self.query_one("#footer-text", Static).update(value)
        except Exception:
            pass
