"""The KMCS TUI application.

A Textual ``App`` that installs every screen at startup and switches
between them with number-key bindings.  Each screen is a full-screen view
over the same service layer the CLI uses.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from textual.app import App
from textual.screen import Screen

from kmcs import __version__
from kmcs.tui.context import TUIContext
from kmcs.tui.screens.campaigns import CampaignsScreen
from kmcs.tui.screens.corpora import CorporaScreen
from kmcs.tui.screens.crashes import CrashesScreen
from kmcs.tui.screens.dashboard import DashboardScreen
from kmcs.tui.screens.findings import FindingsScreen
from kmcs.tui.screens.reports import ReportsScreen
from kmcs.tui.screens.settings import SettingsScreen
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
        ("1", "show('dashboard')", "Dashboard"),
        ("2", "show('targets')", "Targets"),
        ("3", "show('corpora')", "Corpora"),
        ("4", "show('campaigns')", "Campaigns"),
        ("5", "show('crashes')", "Crashes"),
        ("6", "show('findings')", "Findings"),
        ("7", "show('reports')", "Reports"),
        ("8", "show('settings')", "Settings"),
        ("r", "refresh", "Refresh"),
        ("q", "quit", "Quit"),
        ("ctrl+c", "quit", "Quit"),
    ]

    # Screen name → class.  Textual reserves ``SCREENS``, hence the name.
    KMCS_SCREEN_CLASSES: dict[str, type[Screen]] = {
        "dashboard": DashboardScreen,
        "targets": TargetsScreen,
        "corpora": CorporaScreen,
        "campaigns": CampaignsScreen,
        "crashes": CrashesScreen,
        "findings": FindingsScreen,
        "reports": ReportsScreen,
        "settings": SettingsScreen,
    }

    def __init__(self, ctx: TUIContext) -> None:
        super().__init__()
        self.ctx = ctx
        self._screens: dict[str, Screen] = {}

    def on_mount(self) -> None:
        self.register_theme(KMCS_THEME)
        self.theme = "kmcs"

        for name, cls in self.KMCS_SCREEN_CLASSES.items():
            screen = cls()
            self.install_screen(screen, name=name)
            self._screens[name] = screen

        self.push_screen("dashboard")

    def on_unmount(self) -> None:
        self.ctx.close()

    # ------------------------------------------------------------------ actions

    def action_show(self, name: str) -> None:
        if name not in self._screens:
            return
        if name == self._current_screen_name():
            return
        self.switch_screen(name)

    def action_refresh(self) -> None:
        refresh = getattr(self.screen, "refresh_data", None)
        if callable(refresh):
            refresh()

    # ------------------------------------------------------------------ helpers

    def _current_screen_name(self) -> str | None:
        current = self.screen
        for name, screen in self._screens.items():
            if screen is current:
                return name
        return None


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
    args = _build_parser().parse_args(argv)
    try:
        ctx = TUIContext.build(base_dir=args.base_dir)
    except Exception as exc:
        print(f"kmcs-tui: startup failed: {exc}", file=sys.stderr)
        return 1
    KMCSApp(ctx).run()
    return 0
