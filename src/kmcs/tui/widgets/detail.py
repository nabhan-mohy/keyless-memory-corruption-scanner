"""A scrollable key/value pane for the detail area of a screen.

Long values — stack traces, descriptions, file lists — are placed on their
own line under a bold label, so they are readable without horizontal
scrolling.  Short values use a compact ``key : value`` layout.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.widget import Widget
from textual.widgets import Static


class DetailPane(Widget):
    """A scrollable pane that displays a list of key/value pairs."""

    DEFAULT_CSS = """
    DetailPane {
        padding: 0 1;
    }
    DetailPane VerticalScroll {
        height: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        with VerticalScroll():
            yield Static("", id="detail-body")

    # ------------------------------------------------------------------ public

    def set_pairs(self, pairs: list[tuple[str, str]]) -> None:
        """Render ``pairs`` into the pane.

        A value is treated as "long" when it contains a newline or exceeds
        100 characters.  Long values are rendered on their own lines under a
        bold label; short values keep the compact ``key : value`` form.
        """
        body = self.query_one("#detail-body", Static)
        if not pairs:
            body.update("[dim]Select a row to view details.[/dim]")
            return

        label_width = min(max((len(k) for k, _ in pairs), default=0), 22)

        lines: list[str] = []
        for key, value in pairs:
            text = "" if value is None else str(value)
            is_long = "\n" in text or len(text) > 100
            if is_long:
                lines.append(f"[b]{key}[/b]")
                for sub in text.splitlines():
                    lines.append(f"  {sub}")
                lines.append("")
            else:
                lines.append(f"[b]{key.ljust(label_width)}[/b] : {text}")

        body.update("\n".join(lines).rstrip())

    def set_text(self, text: str) -> None:
        body = self.query_one("#detail-body", Static)
        body.update(text or "[dim](empty)[/dim]")

    def clear(self) -> None:
        self.query_one("#detail-body", Static).update("")
