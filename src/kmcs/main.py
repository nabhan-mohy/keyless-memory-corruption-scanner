"""Application entry point.

Dispatches to :mod:`kmcs.cli.commands`, which builds the full subcommand
parser and runs the requested command.  The Phase 1 startup sequence is
available as ``kmcs startup`` for backward compatibility, but it is not part
of the primary CLI surface.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence

from kmcs import __version__
from kmcs.cli.commands import build_parser, main as cli_main

__all__ = ["main", "__version__", "build_parser"]


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``kmcs`` console script."""
    args = list(sys.argv[1:] if argv is None else argv)
    return cli_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
