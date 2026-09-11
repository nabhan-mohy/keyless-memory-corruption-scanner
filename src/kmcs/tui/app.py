"""The KMCS TUI application.

This is a Textual ``App`` that hosts one or more screens.  For now it hosts
just the Dashboard.  Additional screens are added as separate modules under
``kmcs.tui.screens`` and wired in here.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from textual.app import App

from kmcs import __version__
from kmcs.tui.context import TUIContext
from kmcs.tui.screens.dashboard import DashboardScreen
from kmcs.tui.theme import KMCS_THEME


class KMCSApp(App[None]):
    """The main KMCS terminal application."""

    CSS = """
    Screen {
        background: $background;
        color: $foreground;
    }
    #summary {
        height: 3;
        padding: 1 1;
        background: $surface;
        color: $foreground;
    }
    #recent-campaigns, #recent-findings {
        width: 1fr;
        border: round $panel;
        padding: 0 1;
    }
    #detail {
        height: 12;
    }
    """

    TITLE = f"KMCS {__version__} — Keyless Memory-Corruption Scanner"
    SUB_TITLE = "defensive fuzzing and memory-safety research platform"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+c", "quit", "Quit"),
    ]

    def __init__(self, ctx: TUIContext) -> None:
        super().__init__()
        self.ctx = ctx

    def on_mount(self) -> None:
        self.register_theme(KMCS_THEME)
        self.theme = "kmcs"
        self.push_screen(DashboardScreen())

    def on_unmount(self) -> None:
        self.ctx.close()


# ---------------------------------------------------------------------- entry point


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kmcs-tui",
        description="Keyless Memory-Corruption Scanner — terminal interface.",
    )
    parser.add_argument(
        "--base-dir",
        type=Path,
        default=None,
        metavar="PATH",
        help="Override the KMCS data directory.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"KMCS {__version__}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``kmcs-tui`` console script."""
    args = _build_parser().parse_args(argv)

    try:
        ctx = TUIContext.build(base_dir=args.base_dir)
    except Exception as exc:
        print(f"kmcs-tui: startup failed: {exc}", file=sys.stderr)
        return 1

    app = KMCSApp(ctx)
    app.run()
    return 0
