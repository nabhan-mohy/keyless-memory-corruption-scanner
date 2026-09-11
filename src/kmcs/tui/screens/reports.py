"""The Reports screen.

Lists the five report formats KMCS can generate.  The detail pane describes
each format.  Pressing Enter generates that report and writes it to the
workspace's reports directory.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from kmcs.reporting import ReportFormat
from kmcs.tui.screens.base import KMCSListScreen


_FORMAT_DESCRIPTIONS: dict[str, str] = {
    "json": "Machine-readable JSON with a stable schema; includes full evidence.",
    "markdown": "Human-readable Markdown; ideal for pasting into a ticket or issue.",
    "csv": "Tabular CSV; load into a spreadsheet for triage.",
    "sarif": "SARIF 2.1.0; consumed by GitHub Code Scanning and Azure DevOps.",
    "html": "Self-contained HTML; single file, no JavaScript, print to PDF.",
}


class ReportsScreen(KMCSListScreen):
    """A list of the report formats KMCS can generate."""

    title = "Reports"
    empty_message = "No report formats available."

    def columns(self) -> Sequence[tuple[str, str]]:
        return (
            ("format", "Format"),
            ("extension", "Extension"),
            ("media_type", "Media type"),
            ("description", "Description"),
        )

    def load_rows(self) -> Sequence[tuple[Any, ...]]:
        return [
            (
                fmt.value,
                fmt.default_extension,
                fmt.media_type,
                _FORMAT_DESCRIPTIONS.get(fmt.value, ""),
            )
            for fmt in ReportFormat
        ]

    def summary_line(self) -> str:
        count = len(list(ReportFormat))
        return (
            f"{count} format(s) · "
            f"press Enter on a row to generate · "
            f"output: {self.ctx.config.reports_path}"
        )

    def detail_pairs(
        self, row: Sequence[Any] | None
    ) -> list[tuple[str, str]] | None:
        if row is None:
            return None
        fmt_value = row[0]
        try:
            fmt = ReportFormat(fmt_value)
        except ValueError:
            return None
        return [
            ("Format", fmt.value),
            ("Extension", fmt.default_extension),
            ("Media type", fmt.media_type),
            ("Output directory", str(self.ctx.config.reports_path)),
            (
                "Description",
                _FORMAT_DESCRIPTIONS.get(fmt.value, "(no description)"),
            ),
            (
                "How to use",
                "Press Enter on this row to generate the report. "
                "The output path will appear here.",
            ),
        ]

    def hint(self) -> str:
        return (
            "[b]enter[/b] generate  [b]r[/b] refresh  "
            "[b]q[/b] quit  [b]1[/b] dashboard"
        )

    # ------------------------------------------------------------------ actions

    def on_data_table_row_selected(self, event) -> None:  # type: ignore[no-untyped-def]
        table = self.query_one("#table-pane")  # type: ignore[attr-defined]
        row = table.selected_row
        if row is None:
            return
        fmt_value = row[0]
        try:
            fmt = ReportFormat(fmt_value)
        except ValueError:
            return

        output_dir = self.ctx.config.reports_path
        try:
            rendered, written = self.ctx.reports.generate(fmt, output_dir=output_dir)
        except Exception as exc:
            self.query_one("#detail-pane").set_text(  # type: ignore[attr-defined]
                f"[red]Report generation failed:[/red]\n{exc}"
            )
            return

        self.query_one("#detail-pane").set_text(  # type: ignore[attr-defined]
            f"[green]Report written.[/green]\n\n"
            f"Format:   {fmt.value}\n"
            f"File:     {written}\n"
            f"Size:     {rendered.size_bytes} bytes\n"
            f"Media:    {fmt.media_type}"
        )
