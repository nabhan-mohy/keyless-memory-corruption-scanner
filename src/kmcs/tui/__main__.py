"""Allow ``python -m kmcs.tui``."""

from __future__ import annotations

from kmcs.tui.app import main

if __name__ == "__main__":
    raise SystemExit(main())
