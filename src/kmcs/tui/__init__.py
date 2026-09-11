"""Terminal user interface for KMCS.

A full-screen terminal application built on Textual that exposes the same
service layer as the CLI — the same TargetManager, CorpusManager,
CampaignManager, and ReportGenerator — without any business logic of its
own.

The TUI is deliberately a *view*.  Every operation that mutates state goes
through the service layer.  Every read that returns data goes through the
service layer.  The TUI never touches the database directly.
"""

from __future__ import annotations

__all__: list[str] = []
