"""The Findings screen.

Every deduplicated finding.  The detail pane shows the description,
remediation, and every linked crash ID.
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
            return [
                (
                    row.id[:8],
                    row.severity,
                    row.classification,
                    str(len(row.crash_ids or [])),
                    row.title[:60],
                )
                for row in rows
            ]

    def summary_line(self) -> str:
        with self.ctx.database.session() as session:
            rows = session.scalars(select(FindingRow)).all()
        total = len(rows)
        by_severity: dict[str, int] = {}
        for row in rows:
            by_severity[row.severity] = by_severity.get(row.severity, 0) + 1
        parts = [f"{total} finding(s)"]
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in by_severity:
                parts.append(f"{by_severity[sev]} {sev}")
        return " · ".join(parts)

    def detail_pairs(
        self, row: Sequence[Any] | None
    ) -> list[tuple[str, str]] | None:
        if row is None:
            return None
        finding = self._resolve_finding_by_prefix(row[0])
        if finding is None:
            return None

        pairs: list[tuple[str, str]] = [
            ("ID", finding.id),
            ("Title", finding.title),
            ("Classification", finding.classification.value),
            ("Severity", finding.severity.value),
            ("Fingerprint", finding.fingerprint),
            ("Occurrences", str(len(finding.crash_ids))),
            ("Reproduction", finding.reproduction_status.value),
        ]

        if finding.target_id:
            pairs.append(("Target", finding.target_id))

        meta = finding.metadata or {}
        if "campaign_id" in meta:
            pairs.append(("Campaign", str(meta["campaign_id"])))
        if "classification_confidence" in meta:
            pairs.append(
                ("Classification confidence", str(meta["classification_confidence"]))
            )
        if "severity_rationale" in meta:
            pairs.append(("Severity rationale", str(meta["severity_rationale"])))

        pairs.append(("Created", finding.created_at.isoformat()))

        if finding.description:
            pairs.append(("Description", finding.description.rstrip()))

        if finding.remediation:
            pairs.append(("Remediation", finding.remediation.strip()))

        if finding.crash_ids:
            ids = finding.crash_ids[:20]
            lines = "\n".join(ids)
            if len(finding.crash_ids) > 20:
                lines += f"\n… ({len(finding.crash_ids) - 20} more)"
            pairs.append(("Linked crash IDs", lines))

        return pairs

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit  [b]1[/b] dashboard  [b]5[/b] crashes"

    # ------------------------------------------------------------------ helpers

    def _resolve_finding_by_prefix(self, prefix: str):
        with self.ctx.database.session() as session:
            for row in session.scalars(select(FindingRow)).all():
                if row.id.startswith(prefix):
                    return row.to_domain()
        return None
