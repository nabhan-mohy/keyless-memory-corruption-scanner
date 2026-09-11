"""The Reports screen.

Lists the five report formats KMCS can generate.  The detail pane shows
what each format is for.  Pressing Enter on a row generates that report
and writes it to the workspace's reports directory.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from kmcs.reporting import ReportFormat
from kmcs.tui.screens.base import KMCSListScreen


_FORMAT_DESCRIPTIONS: dict[str, str] = {
    "json": "Machine-readable.  Stable schema, includes full evidence.",
    "markdown": "Human-readable.  Ideal for pasting into a ticket or an issue.",
    "csv": "Tabular.  Load into a spreadsheet for triage.",
    "sarif": "SARIF 2.1.0.  Consumed by GitHub Code Scanning and Azure DevOps.",
    "html": "Self-contained.  Single file, no JavaScript, print to PDF.",
}


class ReportsScreen(KMCSListScreen):
    """A list of the report formats KMCS can generate."""

    title = "Reports"
    empty_message = "No report formats available."

    def columns(self) -> Sequence[tuple[str, str]]:
        return (
            ("format", "Format"),
            ("extension", "Extension"),
            ("description", "Description"),
        )

    def load_rows(self) -> Sequence[tuple[Any, ...]]:
        return [
            (
                fmt.value,
                fmt.default_extension,
                _FORMAT_DESCRIPTIONS.get(fmt.value, ""),
            )
            for fmt in ReportFormat
        ]

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
            (
                "Description",
                _FORMAT_DESCRIPTIONS.get(fmt.value, "(no description)"),
            ),
            (
                "Action",
                "Press Enter on this row to generate the report and write it "
                "to the workspace's reports directory.",
            ),
        ]

    def hint(self) -> str:
        return (
            "[b]enter[/b] generate  [b]r[/b] refresh  "
            "[b]q[/b] quit  [b]1[/b] dashboard"
        )

    # ------------------------------------------------------------------ actions

    def on_data_table_row_selected(self, event) -> None:  # type: ignore[no-untyped-def]
        """Generate the selected report and write it to disk."""
        row = self.query_one("#table").selected_row  # type: ignore[attr-defined]
        if row is None:
            return
        fmt_value = row[0]
        try:
            fmt = ReportFormat(fmt_value)
        except ValueError:
            return

        output_dir = self.ctx.config.reports_path
        try:
            rendered, written = self.ctx.reports.generate(
                fmt, output_dir=output_dir
            )
        except Exception as exc:
            self.query_one("#detail").set_text(  # type: ignore[attr-defined]
                f"[red]Report generation failed:[/red]\n{exc}"
            )
            return

        self.query_one("#detail").set_text(  # type: ignore[attr-defined]
            f"[green]Report written.[/green]\n"
            f"Format:    {fmt.value}\n"
            f"File:      {written}\n"
            f"Size:      {rendered.size_bytes} bytes\n"
            f"Media:     {fmt.media_type}"
        )
