"""The Crashes screen.

Lists every crash.  Shows classification, severity, signal, and fingerprint.
The detail pane shows the full record and the top of the preserved stack
trace.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import select

from kmcs.database.models import CrashRow
from kmcs.tui.screens.base import KMCSListScreen


class CrashesScreen(KMCSListScreen):
    """A list of every crash in the database."""

    title = "Crashes"
    empty_message = "No crashes recorded yet."

    def columns(self) -> Sequence[tuple[str, str]]:
        return (
            ("id", "Crash ID"),
            ("classification", "Classification"),
            ("severity", "Severity"),
            ("signal", "Signal"),
            ("fingerprint", "Fingerprint"),
            ("location", "Location"),
        )

    def load_rows(self) -> Sequence[tuple[Any, ...]]:
        with self.ctx.database.session() as session:
            rows = session.scalars(
                select(CrashRow).order_by(CrashRow.created_at.desc())
            ).all()
            data = [
                (
                    row.id[:8],
                    row.classification,
                    row.severity,
                    str(row.signal) if row.signal is not None else "—",
                    (row.fingerprint or "—")[:12],
                    row.source_location or "—",
                )
                for row in rows
            ]
        return data

    def detail_pairs(
        self, row: Sequence[Any] | None
    ) -> list[tuple[str, str]] | None:
        if row is None:
            return None
        crash = self._resolve_crash_by_prefix(row[0])
        if crash is None:
            return None
        pairs = [
            ("ID", crash.id),
            ("Description", crash.description or "—"),
            ("Classification", crash.classification.value),
            ("Severity", crash.severity.value),
            ("Signal", str(crash.signal) if crash.signal is not None else "—"),
            (
                "Exit code",
                str(crash.exit_code) if crash.exit_code is not None else "—",
            ),
            ("Sanitizer", crash.sanitizer.value if crash.sanitizer else "—"),
            ("Fingerprint", crash.fingerprint or "—"),
            ("Source location", crash.source_location or "—"),
            ("Reproduction", crash.reproduction_status.value),
            ("Input", str(crash.input_path) if crash.input_path else "—"),
            ("Evidence", str(crash.evidence_path) if crash.evidence_path else "—"),
            ("Created", crash.created_at.isoformat()),
        ]
        if crash.stack_trace:
            top = "\n".join(crash.stack_trace.splitlines()[:5])
            pairs.append(("Stack trace", top))
        return pairs

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit  [b]1[/b] dashboard  [b]5[/b] findings"

    # ------------------------------------------------------------------ helpers

    def _resolve_crash_by_prefix(self, prefix: str):
        with self.ctx.database.session() as session:
            for row in session.scalars(select(CrashRow)).all():
                if row.id.startswith(prefix):
                    return row.to_domain()
        return None
