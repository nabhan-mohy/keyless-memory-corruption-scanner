"""The Campaigns screen.

Shows every campaign.  The detail pane includes the campaign's configuration
and — when the campaign row records it — a summary of the last telemetry
snapshot.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from kmcs.tui.screens.base import KMCSListScreen


class CampaignsScreen(KMCSListScreen):
    """A list of every campaign."""

    title = "Campaigns"
    empty_message = "No campaigns yet. Use `kmcs campaign create` to add one."

    def columns(self) -> Sequence[tuple[str, str]]:
        return (
            ("id", "ID"),
            ("name", "Name"),
            ("status", "Status"),
            ("fuzzer", "Fuzzer"),
            ("workers", "W"),
            ("duration", "Duration"),
            ("target", "Target"),
        )

    def load_rows(self) -> Sequence[tuple[Any, ...]]:
        campaigns = self.ctx.campaigns.list()
        return [
            (
                c.id[:8],
                c.name,
                c.status.value,
                c.fuzzer.value,
                str(c.workers),
                f"{c.duration_seconds}s" if c.duration_seconds is not None else "—",
                (c.target_id or "—")[:8],
            )
            for c in campaigns
        ]

    def summary_line(self) -> str:
        campaigns = self.ctx.campaigns.list()
        total = len(campaigns)
        by_status: dict[str, int] = {}
        for c in campaigns:
            by_status[c.status.value] = by_status.get(c.status.value, 0) + 1
        parts = [f"{total} campaign(s)"]
        for status in ("running", "completed", "cancelled", "failed", "pending"):
            if status in by_status:
                parts.append(f"{by_status[status]} {status}")
        return " · ".join(parts)

    def detail_pairs(
        self, row: Sequence[Any] | None
    ) -> list[tuple[str, str]] | None:
        if row is None:
            return None
        campaign = self._resolve_campaign_by_prefix(row[0])
        if campaign is None:
            return None

        pairs: list[tuple[str, str]] = [
            ("ID", campaign.id),
            ("Name", campaign.name),
            ("Description", campaign.description or "—"),
            ("Status", campaign.status.value),
        ]

        pairs += [
            ("Target", campaign.target_id),
            ("Corpus", campaign.corpus_id or "—"),
            ("Fuzzer", campaign.fuzzer.value),
            (
                "Sanitizers",
                ", ".join(s.value for s in campaign.sanitizers) or "—",
            ),
            ("Workers", str(campaign.workers)),
        ]

        if campaign.duration_seconds is not None:
            pairs.append(("Configured duration", f"{campaign.duration_seconds}s"))

        if campaign.started_at:
            pairs.append(("Started", campaign.started_at.isoformat()))
        if campaign.finished_at:
            pairs.append(("Finished", campaign.finished_at.isoformat()))
            if campaign.started_at:
                delta = (campaign.finished_at - campaign.started_at).total_seconds()
                pairs.append(("Actual runtime", f"{delta:.1f}s"))

        pairs.append(("Created", campaign.created_at.isoformat()))

        telemetry = campaign.metadata.get("telemetry")
        if isinstance(telemetry, dict):
            snapshot_lines: list[str] = []
            for key in (
                "total_executions",
                "total_executions_per_second",
                "total_corpus_count",
                "total_crashes",
                "total_unique_crashes",
                "total_hangs",
                "total_artifacts_seen",
                "total_crashes_recorded",
            ):
                if key in telemetry and telemetry[key] is not None:
                    snapshot_lines.append(f"{key}: {telemetry[key]}")
            if snapshot_lines:
                pairs.append(("Telemetry", "\n".join(snapshot_lines)))

        # Count related crashes.
        from sqlalchemy import func, select

        from kmcs.database.models import CrashRow

        with self.ctx.database.session() as session:
            crash_count = (
                session.scalar(
                    select(func.count())
                    .select_from(CrashRow)
                    .where(CrashRow.campaign_id == campaign.id)
                )
                or 0
            )
        pairs.append(("Crashes recorded", str(crash_count)))

        return pairs

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit  [b]1[/b] dashboard  [b]5[/b] crashes"

    # ------------------------------------------------------------------ helpers

    def _resolve_campaign_by_prefix(self, prefix: str):
        for campaign in self.ctx.campaigns.list():
            if campaign.id.startswith(prefix):
                return campaign
        return None
