"""Colour scheme for the KMCS TUI.

Kept in one place so every screen uses the same palette.  Values are Textual
CSS strings; screens refer to them by name rather than by literal hex.
"""

from __future__ import annotations

from textual.theme import Theme

KMCS_THEME = Theme(
    name="kmcs",
    primary="#4c8cff",
    secondary="#6ea6ff",
    accent="#ffb347",
    foreground="#d8dee9",
    background="#1b1f23",
    success="#4caf50",
    warning="#ffb347",
    error="#d13438",
    surface="#242a30",
    panel="#2c333a",
    dark=True,
)

# Severity badges use these.  A finding with a given severity gets the
# corresponding colour when rendered in a table.
SEVERITY_COLOURS: dict[str, str] = {
    "critical": "#b00020",
    "high": "#d13438",
    "medium": "#c76a00",
    "low": "#3d7a3d",
    "info": "#4a6c8c",
    "unknown": "#6e7781",
}


def severity_colour(severity: str) -> str:
    """Return the colour for a severity name, defaulting to unknown."""
    return SEVERITY_COLOURS.get(severity.lower(), SEVERITY_COLOURS["unknown"])
