"""The KMCS TUI application.

A Textual ``App`` that installs every screen at startup and switches between
them with number-key bindings.  Each screen is a full-screen view over the
same service layer the CLI uses.
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
from kmcs.tui.screens.targets import TargetsScreen
from kmcs.tui.theme import KMCS_THEME


class KMCSApp(App[None]):
    """The main KMCS terminal application."""

    CSS = """
    Screen {
        background: $background;
        color: $foreground;
    }
    #screen-title {
        height: 1;
        padding: 0 1;
        color: $accent;
        text-style: bold;
    }
    #summary {
        height: 3;
        padding: 1 1;
        background: $surface;
        color: $foreground;
    }
    #table, #recent-campaigns, #recent-findings {
        height: 1fr;
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
        ("1", "switch_to('dashboard')", "Dashboard"),
        ("2", "switch_to('targets')", "Targets"),
        ("r", "refresh", "Refresh"),
        ("q", "quit", "Quit"),
        ("ctrl+c", "quit", "Quit"),
    ]

    # Screen name → class.  Add entries here as new screens are built.
    SCREENS: dict[str, type] = {
        "dashboard": DashboardScreen,
        "targets": TargetsScreen,
    }

    def __init__(self, ctx: TUIContext) -> None:
        super().__init__()
        self.ctx = ctx

    def on_mount(self) -> None:
        self.register_theme(KMCS_THEME)
        self.theme = "kmcs"
        for name, screen_cls in self.SCREENS.items():
            self.install_screen(screen_cls(), name=name)
        self.switch_screen("dashboard")

    def on_unmount(self) -> None:
        self.ctx.close()

    # ------------------------------------------------------------------ actions

    def action_switch_to(self, name: str) -> None:
        """Switch to an installed screen by name."""
        if name in self.SCREENS:
            self.switch_screen(name)

    def action_refresh(self) -> None:
        """Ask the current screen to refresh its data."""
        screen = self.screen
        if hasattr(screen, "refresh_data"):
            screen.refresh_data()  # type: ignore[attr-defined]


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
