"""A one-line header bar showing app version, data directory, and DB status."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static

from kmcs import __version__


class AppHeader(Widget):
    """A single line that summarises where KMCS is running."""

    DEFAULT_CSS = """
    AppHeader {
        height: 1;
        background: $panel;
        color: $foreground;
        padding: 0 1;
    }
    AppHeader .title {
        color: $primary;
        text-style: bold;
    }
    AppHeader .path {
        color: $text-muted;
    }
    AppHeader .status-ok {
        color: $success;
        text-style: bold;
    }
    AppHeader .status-fail {
        color: $error;
        text-style: bold;
    }
    """

    base_dir: reactive[str] = reactive("")
    db_status: reactive[str] = reactive("—")

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield Static(f"KMCS {__version__}", classes="title")
            yield Static("  data: ", classes="path")
            yield Static("", id="header-path", classes="path")
            yield Static("  db: ")
            yield Static("—", id="header-db")

    def watch_base_dir(self, value: str) -> None:
        try:
            self.query_one("#header-path", Static).update(value)
        except Exception:
            pass

    def watch_db_status(self, value: str) -> None:
        try:
            widget = self.query_one("#header-db", Static)
            widget.update(value)
            widget.set_classes(
                "status-ok" if value == "ok" else "status-fail"
            )
        except Exception:
            pass
