"""The Campaigns screen.

Lists every campaign.  Shows name, status, fuzzer, worker count, duration,
and target.  The detail pane shows the full campaign record.
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
            ("workers", "Workers"),
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

    def detail_pairs(
        self, row: Sequence[Any] | None
    ) -> list[tuple[str, str]] | None:
        if row is None:
            return None
        campaign = self._resolve_campaign_by_prefix(row[0])
        if campaign is None:
            return None
        return [
            ("ID", campaign.id),
            ("Name", campaign.name),
            ("Description", campaign.description or "—"),
            ("Status", campaign.status.value),
            ("Target", campaign.target_id),
            ("Corpus", campaign.corpus_id or "—"),
            ("Fuzzer", campaign.fuzzer.value),
            ("Sanitizers", ", ".join(s.value for s in campaign.sanitizers) or "—"),
            ("Workers", str(campaign.workers)),
            (
                "Duration",
                f"{campaign.duration_seconds}s"
                if campaign.duration_seconds is not None
                else "—",
            ),
            (
                "Started",
                campaign.started_at.isoformat() if campaign.started_at else "—",
            ),
            (
                "Finished",
                campaign.finished_at.isoformat() if campaign.finished_at else "—",
            ),
            ("Created", campaign.created_at.isoformat()),
        ]

    def hint(self) -> str:
        return "[b]r[/b] refresh  [b]q[/b] quit  [b]1[/b] dashboard  [b]4[/b] crashes"

    # ------------------------------------------------------------------ helpers

    def _resolve_campaign_by_prefix(self, prefix: str):
        for campaign in self.ctx.campaigns.list():
            if campaign.id.startswith(prefix):
                return campaign
        return None

