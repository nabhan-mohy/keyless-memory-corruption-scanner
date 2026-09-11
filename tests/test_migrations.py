"""Schema versioning."""

from __future__ import annotations

from pathlib import Path

import pytest

from kmcs.core.exceptions import MigrationError
from kmcs.database.database import Database, build_sqlite_url
from kmcs.database.migrations import (
    TARGET_SCHEMA_VERSION,
    apply_migrations,
    get_schema_version,
    pending_migrations,
)


def test_new_database_starts_at_version_zero(tmp_path: Path) -> None:
    db = Database(build_sqlite_url(tmp_path / "fresh.sqlite3"))
    try:
        assert get_schema_version(db.engine) == 0
    finally:
        db.dispose()


def test_initialize_applies_migrations(tmp_path: Path) -> None:
    db = Database(build_sqlite_url(tmp_path / "migrated.sqlite3"))
    try:
        assert db.initialize() == TARGET_SCHEMA_VERSION
        assert get_schema_version(db.engine) == TARGET_SCHEMA_VERSION
    finally:
        db.dispose()


def test_initialize_is_idempotent(tmp_path: Path) -> None:
    db = Database(build_sqlite_url(tmp_path / "twice.sqlite3"))
    try:
        first = db.initialize()
        second = db.initialize()
        assert first == second == TARGET_SCHEMA_VERSION
    finally:
        db.dispose()


def test_pending_migrations_is_empty_when_current(tmp_path: Path) -> None:
    assert pending_migrations(TARGET_SCHEMA_VERSION) == []
    assert len(pending_migrations(0)) == len(pending_migrations(0))


def test_newer_schema_version_is_rejected(tmp_path: Path) -> None:
    db = Database(build_sqlite_url(tmp_path / "future.sqlite3"))
    try:
        db.initialize()
        with db.engine.begin() as connection:
            connection.exec_driver_sql(f"PRAGMA user_version = {TARGET_SCHEMA_VERSION + 1}")

        with pytest.raises(MigrationError):
            apply_migrations(db.engine)
    finally:
        db.dispose()

