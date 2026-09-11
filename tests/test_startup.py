"""End-to-end startup sequence."""

from __future__ import annotations

import json
from pathlib import Path

from kmcs import __version__
from kmcs.core.config import KMCSConfig
from kmcs.main import main, run_startup


def test_run_startup_prepares_a_working_workspace(tmp_path: Path) -> None:
    config = KMCSConfig(base_dir=tmp_path / "kmcs")

    report = run_startup(config)

    assert report.ok is True
    assert report.version == __version__
    assert report.schema_version >= 1
    assert report.health is not None and report.health.ok is True
    assert config.database_file.exists()
    assert config.log_file.exists()
    for name, path in report.directories.items():
        assert Path(path).is_dir(), name


def test_run_startup_is_idempotent(tmp_path: Path) -> None:
    config = KMCSConfig(base_dir=tmp_path / "kmcs")

    first = run_startup(config)
    second = run_startup(config)

    assert first.ok and second.ok
    assert first.schema_version == second.schema_version


def test_run_startup_publishes_events(tmp_path: Path) -> None:
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


def test_main_emits_json_report(tmp_path: Path, capsys) -> None:
    exit_code = main(["--base-dir", str(tmp_path / "kmcs"), "--json"])
    captured = capsys.readouterr()

    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["ok"] is True
    assert payload["version"] == __version__
    assert payload["database"]["schema_version"] >= 1
    assert payload["health"]["ok"] is True


def test_main_emits_human_report(tmp_path: Path, capsys) -> None:
    exit_code = main(["--base-dir", str(tmp_path / "kmcs")])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "KMCS" in captured.out
    assert "READY" in captured.out
    assert "database health : OK" in captured.out


def test_main_reports_a_bad_base_dir(tmp_path: Path, capsys) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("this is a file, not a directory")

    exit_code = main(["--base-dir", str(blocker), "--json"])
    captured = capsys.readouterr()

    assert exit_code != 0
    assert "kmcs:" in captured.err
