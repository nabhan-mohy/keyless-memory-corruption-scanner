"""The detector combines monitor + parser + persistence."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from kmcs.analysis.crash_detector import CrashDetector
from kmcs.analysis.crash_monitor import MonitorConfig
from kmcs.core.models import CrashClassification
from kmcs.database.database import Database, build_sqlite_url
from kmcs.database.models import CrashRow


def _write_script(path: Path, body: str) -> Path:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell scripts")
class TestDetectionWithoutPersistence:
    def test_clean_run_returns_no_crash(self, tmp_path: Path) -> None:
        binary = _write_script(tmp_path / "ok", "#!/bin/sh\nexit 0\n")
        result = CrashDetector().run_and_record(
            MonitorConfig(target=binary), input_bytes=b""
        )
        assert result.crashed is False
        assert result.crash is None
        assert result.persisted is False

    def test_signal_death_produces_a_crash_object(self, tmp_path: Path) -> None:
        binary = _write_script(tmp_path / "segv", "#!/bin/sh\nkill -SEGV $$\n")
        result = CrashDetector().run_and_record(
            MonitorConfig(target=binary, timeout_seconds=5.0), input_bytes=b""
        )

        assert result.crashed is True
        assert result.crash is not None
        assert result.crash.signal == 11
        assert result.crash.classification is CrashClassification.SEGMENTATION_FAULT
        assert result.persisted is False  # no database supplied


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell scripts")
class TestDetectionWithPersistence:
    def test_crash_is_persisted_and_retrievable(self, tmp_path: Path) -> None:
        binary = _write_script(tmp_path / "segv", "#!/bin/sh\nkill -SEGV $$\n")

        db = Database(build_sqlite_url(tmp_path / "kmcs.sqlite3"))
        db.initialize()
        try:
            detector = CrashDetector(database=db)
            result = detector.run_and_record(
                MonitorConfig(target=binary, timeout_seconds=5.0),
                input_bytes=b"",
                target_id=None,
                campaign_id=None,
            )

            assert result.persisted is True
            assert result.crash is not None

            with db.session() as session:
                row = session.get(CrashRow, result.crash.id)
                assert row is not None
                restored = row.to_domain()
                assert restored.signal == 11
                assert restored.classification is CrashClassification.SEGMENTATION_FAULT
        finally:
            db.dispose()

    def test_clean_run_does_not_persist_anything(self, tmp_path: Path) -> None:
        binary = _write_script(tmp_path / "ok", "#!/bin/sh\nexit 0\n")

        db = Database(build_sqlite_url(tmp_path / "kmcs.sqlite3"))
        db.initialize()
        try:
            detector = CrashDetector(database=db)
            result = detector.run_and_record(
                MonitorConfig(target=binary), input_bytes=b""
            )
            assert result.persisted is False

            from sqlalchemy import select

            with db.session() as session:
                rows = session.scalars(select(CrashRow)).all()
                assert rows == []
        finally:
            db.dispose()
