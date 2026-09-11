"""CLI commands: end-to-end through ``main()`` with captured output."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from kmcs.cli.commands import main as cli_main
from kmcs.core import models
from kmcs.core.config import KMCSConfig
from kmcs.database.database import Database, build_sqlite_url
from kmcs.database.models import FindingRow, TargetRow


def _seed_workspace(base_dir: Path) -> None:
    config = KMCSConfig(base_dir=base_dir)
    config.ensure_directories()
    db = Database.from_config(config)
    db.initialize()

    target = models.Target(name="libdemo", compiler="clang")
    finding = models.Finding(
        title="Heap overflow in parse_chunk",
        fingerprint="fp-1",
        classification=models.CrashClassification.HEAP_BUFFER_OVERFLOW,
        severity=models.Severity.HIGH,
        target_id=target.id,
        crash_ids=[],
    )

    with db.session() as session:
        session.add(TargetRow.from_domain(target))
        session.flush()
        session.add(FindingRow.from_domain(finding))

    db.dispose()

# ---------------------------------------------------------------------- helpers


def run_cli(argv, capsys) -> tuple[int, str, str]:
    code = cli_main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# ---------------------------------------------------------------------- tests


class TestVersion:
    def test_plain_version(self, tmp_path: Path, capsys) -> None:
        code, out, _ = run_cli(["--base-dir", str(tmp_path), "version"], capsys)
        assert code == 0
        assert "KMCS" in out

    def test_json_version(self, tmp_path: Path, capsys) -> None:
        code, out, _ = run_cli(
            ["--base-dir", str(tmp_path), "--json", "version"], capsys
        )
        assert code == 0
        payload = json.loads(out)
        assert "version" in payload


class TestNoCommand:
    def test_prints_help(self, capsys) -> None:
        code = cli_main([])
        captured = capsys.readouterr()
        assert code != 0
        assert "usage:" in captured.out.lower() or "usage:" in captured.err.lower()


class TestDoctor:
    def test_json_output(self, tmp_path: Path, capsys) -> None:
        code, out, _ = run_cli(
            ["--base-dir", str(tmp_path), "--json", "doctor", "--no-sanitizers"],
            capsys,
        )
        # Exit code is 0 or 4 depending on whether a compiler is present.
        assert code in (0, 4)
        payload = json.loads(out)
        assert payload["version"]
        assert "tools" in payload
        assert "database" in payload
        assert "sanitizers" in payload

    def test_human_output(self, tmp_path: Path, capsys) -> None:
        code, out, _ = run_cli(
            ["--base-dir", str(tmp_path), "doctor", "--no-sanitizers"],
            capsys,
        )
        assert "KMCS" in out
        assert "Workspace" in out
        assert "Database" in out


class TestTarget:
    def test_add_and_list(self, tmp_path: Path, capsys) -> None:
        code, out, _ = run_cli(
            [
                "--base-dir", str(tmp_path),
                "target", "add", "mytarget",
                "--compiler", "clang",
            ],
            capsys,
        )
        assert code == 0
        assert "mytarget" in out

        code, out, _ = run_cli(
            ["--base-dir", str(tmp_path), "target", "list"], capsys
        )
        assert code == 0
        assert "mytarget" in out

    def test_add_json(self, tmp_path: Path, capsys) -> None:
        code, out, _ = run_cli(
            [
                "--base-dir", str(tmp_path), "--json",
                "target", "add", "json-target",
            ],
            capsys,
        )
        assert code == 0
        payload = json.loads(out)
        assert payload["command"] == "target.add"
        assert payload["ok"] is True
        assert payload["item"]["name"] == "json-target"

    def test_show_missing(self, tmp_path: Path, capsys) -> None:
        code, _, err = run_cli(
            ["--base-dir", str(tmp_path), "target", "show", "nope"], capsys
        )
        assert code == 3
        assert "not found" in err.lower()


class TestFinding:
    def test_list_json(self, tmp_path: Path, capsys) -> None:
        _seed_workspace(tmp_path)
        code, out, _ = run_cli(
            ["--base-dir", str(tmp_path), "--json", "finding", "list"], capsys
        )
        assert code == 0
        payload = json.loads(out)
        assert payload["command"] == "finding.list"
        assert payload["count"] == 1

    def test_show_by_id(self, tmp_path: Path, capsys) -> None:
        _seed_workspace(tmp_path)
        # Grab the finding ID via list.
        _, out, _ = run_cli(
            ["--base-dir", str(tmp_path), "--json", "finding", "list"], capsys
        )
        finding_id = json.loads(out)["items"][0]["id"]

        code, out, _ = run_cli(
            ["--base-dir", str(tmp_path), "finding", "show", finding_id], capsys
        )
        assert code == 0
        assert "Heap overflow" in out

    def test_show_missing(self, tmp_path: Path, capsys) -> None:
        code, _, err = run_cli(
            ["--base-dir", str(tmp_path), "finding", "show", "nope"], capsys
        )
        assert code == 3
        assert "not found" in err.lower()


class TestReport:
    def test_generate_to_stdout(self, tmp_path: Path, capsys) -> None:
        _seed_workspace(tmp_path)
        code, out, _ = run_cli(
            [
                "--base-dir", str(tmp_path),
                "report", "generate", "--format", "markdown", "--stdout",
            ],
            capsys,
        )
        assert code == 0
        assert "# " in out  # markdown title

    def test_generate_to_disk(self, tmp_path: Path, capsys) -> None:
        _seed_workspace(tmp_path)
        report_dir = tmp_path / "reports"
        code, out, _ = run_cli(
            [
                "--base-dir", str(tmp_path),
                "report", "generate",
                "--format", "json",
                "--output-dir", str(report_dir),
            ],
            capsys,
        )
        assert code == 0
        assert report_dir.is_dir()
        files = list(report_dir.iterdir())
        assert len(files) == 1
        assert files[0].suffix == ".json"

    def test_generate_json_envelope(self, tmp_path: Path, capsys) -> None:
        _seed_workspace(tmp_path)
        code, out, _ = run_cli(
            [
                "--base-dir", str(tmp_path), "--json",
                "report", "generate", "--format", "sarif", "--stdout",
            ],
            capsys,
        )
        assert code == 0
        payload = json.loads(out)
        assert payload["command"] == "report.generate"
        assert payload["ok"] is True
        assert payload["rendered"]["format"] == "sarif"


class TestExitCodes:
    def test_unknown_command_is_usage_error(self, capsys) -> None:
        with pytest.raises(SystemExit) as exc_info:
            cli_main(["does-not-exist"])
        assert exc_info.value.code == 2
