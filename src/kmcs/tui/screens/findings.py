"""The Findings screen.

Lists every deduplicated finding.  Shows severity, classification, title,
and occurrence count.  The detail pane shows the full description and
remediation.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from sqlalchemy import select

from kmcs.database.models import FindingRow
from kmcs.tui.screens.base import KMCSListScreen


class FindingsScreen(KMCSListScreen):
    """A list of every finding in the database."""

    title = "Findings"
    empty_message = "No findings yet. Run a campaign to produce some."

    def columns(self) -> Sequence[tuple[str, str]]:
        return (
            ("id", "Finding ID"),
            ("severity", "Severity"),
            ("classification", "Classification"),
            ("occurrences", "Occurrences"),
            ("title", "Title"),
        )

    def load_rows(self) -> Sequence[tuple[Any, ...]]:
        with self.ctx.database.session() as session:
            rows = session.scalars(
                select(FindingRow).order_by(FindingRow.created_at.desc())
            ).all()
            data = [
                (
                    row.id[:8],
                    row.severity,
                    row.classification,
                    str(len(row.crash_ids or [])),
                    row.title[:60],
                )
                for row in rows
            ]
        return data

    def detail_pairs(
        self, row: Sequence[Any] | None
    ) -> list[tuple[str, str]] | None:
        if row is None:
            return None
        finding = self._resolve_finding_by_prefix(row[0])
        if finding is None:
            return None
        pairs = [
            ("ID", finding.id),
            ("Title", finding.title),
            ("Classification", finding.classification.value),
            ("Severity", finding.severity.value),
            ("Fingerprint", finding.fingerprint),
            ("Occurrences", str(len(finding.crash_ids))),
            ("Reproduction", finding.reproduction_status.value),
            ("Target", finding.target_id or "—"),
            ("Created", finding.created_at.isoformat()),
        ]
        if finding.description:
            # Truncate the description to a reasonable number of lines so
            # the pane does not overflow its box.
            desc = "\n".join(finding.description.splitlines()[:10])
            pairs.append(("Description", desc))
        if finding.remediation:
            pairs.append(("Remediation", finding.remediation.strip()))
        return pairs

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit  [b]1[/b] dashboard  [b]4[/b] crashes"

    # ------------------------------------------------------------------ helpers

    def _resolve_finding_by_prefix(self, prefix: str):
        with self.ctx.database.session() as session:
            for row in session.scalars(select(FindingRow)).all():
                if row.id.startswith(prefix):
                    return row.to_domain()
        return None
