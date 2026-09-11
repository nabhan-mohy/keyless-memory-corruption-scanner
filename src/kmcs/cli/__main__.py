"""Allow ``python -m kmcs.cli``."""

from __future__ import annotations

from kmcs.cli.commands import main

if __name__ == "__main__":
    raise SystemExit(main())
