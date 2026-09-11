"""End-to-end startup sequence.

The module-level ``run_startup()`` function still exists as a programmatic
entry point for scripts and CI.  It is tested directly, without going through
the command line, because the CLI now dispatches subcommands and no longer
invokes the startup sequence implicitly.

The three tests that exercise the CLI (``test_main_emits_*``) were written
against the Phase 1 interface and no longer reflect how KMCS works.  They
have been replaced with tests that exercise ``kmcs doctor``, which is the
modern equivalent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kmcs import __version__
from kmcs.__main__ import StartupReport, run_startup
from kmcs.cli.commands import main as cli_main
from kmcs.core.config import KMCSConfig


class TestRunStartup:
    """Tests for the module-level startup function.

    These do not go through the command line.  ``run_startup()`` is a
    library function that opens a workspace, initialises the database, and
    returns a structured report.  It is what a script or a CI job would call.
    """

    def test_run_startup_prepares_a_working_workspace(
        self, tmp_path: Path
    ) -> None:
        config = KMCSConfig(base_dir=tmp_path / "kmcs")

        report = run_startup(config)

        assert isinstance(report, StartupReport)
        assert report.ok is True
        assert report.version == __version__
        assert report.schema_version >= 1
        assert report.health is not None
        assert report.health.ok is True
        assert config.database_file.exists()
        for path in report.directories.values():
            assert Path(path).is_dir()

    def test_run_startup_is_idempotent(self, tmp_path: Path) -> None:
        config = KMCSConfig(base_dir=tmp_path / "kmcs")

        first = run_startup(config)
        second = run_startup(config)

        assert first.ok and second.ok
        assert first.schema_version == second.schema_version

    def test_run_startup_publishes_events(self, tmp_path: Path) -> None:
        from kmcs.core.events import Event, EventBus, EventType

        bus = EventBus()
        seen: list[Event] = []
        bus.subscribe_all(seen.append)

        run_startup(KMCSConfig(base_dir=tmp_path / "kmcs"), bus=bus)

        types = [event.type for event in seen]
        assert EventType.APPLICATION_STARTING in types
        assert EventType.CONFIGURATION_LOADED in types
        assert EventType.DATABASE_INITIALIZED in types
        assert EventType.DATABASE_HEALTH_CHECKED in types
        assert EventType.APPLICATION_STARTED in types


class TestCLIDoctor:
    """Tests for ``kmcs doctor``.

    ``doctor`` is the CLI equivalent of the startup sequence: it opens the
    workspace, runs the database health check, reports the environment, and
    exits 0 when everything is healthy.
    """

    def test_doctor_json_output_is_well_formed(
        self, tmp_path: Path, capsys
    ) -> None:
        exit_code = cli_main(
            ["--base-dir", str(tmp_path / "kmcs"), "--json",
             "doctor", "--no-sanitizers"]
        )
        captured = capsys.readouterr()

        # doctor returns 0 when healthy, 4 when a required tool is missing.
        # Either is acceptable; the JSON must still be well-formed.
        assert exit_code in (0, 4)

        payload = json.loads(captured.out)
        assert payload["version"] == __version__
        assert payload["database"]["health"]["ok"] is True
        assert "tools" in payload

    def test_doctor_human_output_includes_key_sections(
        self, tmp_path: Path, capsys
    ) -> None:
        exit_code = cli_main(
            ["--base-dir", str(tmp_path / "kmcs"),
             "doctor", "--no-sanitizers"]
        )
        captured = capsys.readouterr()

        assert exit_code in (0, 4)
        assert "KMCS" in captured.out
        assert "Workspace" in captured.out
        assert "Database" in captured.out

    def test_doctor_reports_a_bad_base_dir(
        self, tmp_path: Path, capsys
    ) -> None:
        # A regular file where a directory is expected must produce a
        # clean error, not a traceback.
        blocker = tmp_path / "blocker"
        blocker.write_text("this is a file, not a directory")

        exit_code = cli_main(
            ["--base-dir", str(blocker), "doctor", "--no-sanitizers"]
        )
        captured = capsys.readouterr()

        assert exit_code != 0
        assert "kmcs" in captured.err.lower()


class TestCLIVersion:
    """The ``version`` subcommand exists and returns the current version."""

    def test_version_human(self, capsys) -> None:
        exit_code = cli_main(["version"])
        captured = capsys.readouterr()

        assert exit_code == 0
        assert __version__ in captured.out

    def test_version_json(self, capsys) -> None:
        exit_code = cli_main(["--json", "version"])
        captured = capsys.readouterr()

        assert exit_code == 0
        payload = json.loads(captured.out)
        assert payload["version"] == __version__
