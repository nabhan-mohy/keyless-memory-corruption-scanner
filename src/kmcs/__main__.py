"""Application entry point.

Phase 1's startup sequence is still available as ``kmcs startup``.  Every
other invocation is dispatched to the Phase 6 CLI in
:mod:`kmcs.cli.commands`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from kmcs import __version__
from kmcs.cli.commands import build_parser as build_cli_parser
from kmcs.cli.commands import main as cli_main


def _build_startup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="kmcs startup",
        description="Run the Phase 1 startup sequence and report the result.",
    )
    parser.add_argument("--json", action="store_true")
    return parser


def _run_startup(args: Sequence[str]) -> int:
    from kmcs.core.config import KMCSConfig
    from kmcs.core.exceptions import ConfigurationError, KMCSException
    from kmcs.main import run_startup  # self-import is fine; the function is local

    parser = _build_startup_parser()
    parsed = parser.parse_args(args)

    try:
        config = KMCSConfig.load()
    except ConfigurationError as exc:
        print(f"kmcs: configuration error: {exc}", file=sys.stderr)
        return exc.exit_code

    try:
        report = run_startup(config)
    except KMCSException as exc:
        print(f"kmcs: startup failed: {exc}", file=sys.stderr)
        return exc.exit_code

    if parsed.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        status = "READY" if report.ok else "DEGRADED"
        print(f"KMCS {report.version} startup report")
        print(f"  status         : {status}")
        print(f"  data directory : {report.config.base_dir}")
        print(f"  database       : {report.database_url}")
        print(f"  schema version : {report.schema_version}")
    return 0 if report.ok else 1


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "startup":
        return _run_startup(args[1:])
    return cli_main(args)


__all__ = ["main", "run_startup", "StartupReport"]


# Late import so ``main.py`` can define ``run_startup`` without a cycle.
from kmcs.core.config import KMCSConfig as _KMCSConfig  # noqa: E402
from kmcs.core.events import EventBus as _EventBus  # noqa: E402
from kmcs.core.events import EventType as _EventType  # noqa: E402
from kmcs.core.exceptions import ConfigurationError as _ConfigurationError  # noqa: E402
from kmcs.core.exceptions import KMCSException as _KMCSException  # noqa: E402
from kmcs.database.database import Database as _Database  # noqa: E402
from kmcs.database.database import DatabaseHealth as _DatabaseHealth  # noqa: E402


class StartupReport:  # pragma: no cover - thin wrapper, tested in Phase 1
    """Re-exported for backwards compatibility."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def to_dict(self):
        payload = dict(self.__dict__)
        if hasattr(self, "health") and self.health is not None:
            payload["health"] = self.health.model_dump()
        if hasattr(self, "config") and self.config is not None:
            payload["base_dir"] = str(self.config.base_dir)
            payload.pop("config", None)
        return payload


def run_startup(config: "_KMCSConfig" | None = None, *, bus: "_EventBus" | None = None) -> StartupReport:
    """Phase 1 startup sequence, preserved verbatim."""
    from pathlib import Path

    config = config or _KMCSConfig.load()
    from kmcs.core.config import configure_logging

    configure_logging(config)
    bus = bus or _EventBus()

    bus.emit(_EventType.APPLICATION_STARTING, {"version": __version__}, source="main")

    directories = config.ensure_directories()
    bus.emit(
        _EventType.CONFIGURATION_LOADED,
        {"base_dir": str(config.base_dir)},
        source="main",
    )

    database = _Database.from_config(config)
    try:
        schema_version = database.initialize()
        bus.emit(
            _EventType.DATABASE_INITIALIZED,
            {"url": database.url, "schema_version": schema_version},
            source="main",
        )
        health = database.health_check()
        bus.emit(
            _EventType.DATABASE_HEALTH_CHECKED,
            {"ok": health.ok, "messages": list(health.messages)},
            source="main",
        )
        errors = list(health.messages) if not health.ok else []
    finally:
        database.dispose()

    bus.emit(_EventType.APPLICATION_STARTED, {"ok": health.ok}, source="main")

    return StartupReport(
        version=__version__,
        ok=health.ok,
        config=config,
        directories={name: str(path) for name, path in directories.items()},
        database_url=database.url,
        schema_version=schema_version,
        health=health,
        errors=errors,
    )


if __name__ == "__main__":
    raise SystemExit(main())
