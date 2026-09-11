"""The Crashes screen.

Every recorded crash, with the classification, severity, signal, and
fingerprint.  The detail pane shows the full stack trace and the top of the
preserved stderr.
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
            ("location", "Source location"),
        )

    def load_rows(self) -> Sequence[tuple[Any, ...]]:
        with self.ctx.database.session() as session:
            rows = session.scalars(
                select(CrashRow).order_by(CrashRow.created_at.desc())
            ).all()
            return [
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

    def summary_line(self) -> str:
        with self.ctx.database.session() as session:
            rows = session.scalars(select(CrashRow)).all()
        total = len(rows)
        fingerprints = {row.fingerprint for row in rows if row.fingerprint}
        by_severity: dict[str, int] = {}
        for row in rows:
            by_severity[row.severity] = by_severity.get(row.severity, 0) + 1
        sev_str = ", ".join(
            f"{count} {sev}"
            for sev, count in sorted(by_severity.items())
            if sev != "unknown"
        )
        parts = [f"{total} crash(es)", f"{len(fingerprints)} unique fingerprint(s)"]
        if sev_str:
            parts.append(sev_str)
        return " · ".join(parts)

    def detail_pairs(
        self, row: Sequence[Any] | None
    ) -> list[tuple[str, str]] | None:
        if row is None:
            return None
        crash = self._resolve_crash_by_prefix(row[0])
        if crash is None:
            return None
        pairs: list[tuple[str, str]] = [
            ("ID", crash.id),
            ("Description", crash.description or "—"),
            ("Classification", crash.classification.value),
            ("Severity", crash.severity.value),
        ]

        pairs += [
            ("Signal", str(crash.signal) if crash.signal is not None else "—"),
            ("Exit code", str(crash.exit_code) if crash.exit_code is not None else "—"),
            ("Sanitizer", crash.sanitizer.value if crash.sanitizer else "—"),
            ("Fingerprint", crash.fingerprint or "—"),
            ("Source location", crash.source_location or "—"),
        ]

        pairs += [
            ("Reproduction", crash.reproduction_status.value),
            ("Input", str(crash.input_path) if crash.input_path else "—"),
            ("Evidence", str(crash.evidence_path) if crash.evidence_path else "—"),
        ]

        if crash.campaign_id:
            pairs.append(("Campaign", crash.campaign_id))
        if crash.target_id:
            pairs.append(("Target", crash.target_id))

        pairs.append(("Created", crash.created_at.isoformat()))

        if crash.stack_trace:
            top = "\n".join(crash.stack_trace.splitlines()[:15])
            pairs.append(("Stack trace (top)", top))

        if crash.stderr_excerpt:
            tail = "\n".join(crash.stderr_excerpt.splitlines()[-15:])
            pairs.append(("stderr (tail)", tail))

        meta = crash.metadata or {}
        interesting_meta = {
            k: v for k, v in meta.items()
            if k
            in (
                "classification_confidence",
                "severity_rationale",
                "duration_seconds",
                "timed_out",
            )
        }
        if interesting_meta:
            lines = [f"{k}: {v}" for k, v in interesting_meta.items()]
            pairs.append(("Evidence metadata", "\n".join(lines)))

        return pairs

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit  [b]1[/b] dashboard  [b]6[/b] findings"

    # ------------------------------------------------------------------ helpers

    def _resolve_crash_by_prefix(self, prefix: str):
        with self.ctx.database.session() as session:
            for row in session.scalars(select(CrashRow)).all():
                if row.id.startswith(prefix):
                    return row.to_domain()
        return None
