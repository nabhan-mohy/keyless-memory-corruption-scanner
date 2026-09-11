"""Shared fixtures."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from kmcs.core.config import KMCSConfig
from kmcs.core.events import EventBus
from kmcs.database.database import Database, build_sqlite_url


@pytest.fixture()
def base_dir(tmp_path: Path) -> Path:
    return tmp_path / "kmcs-home"


@pytest.fixture()
def config(base_dir: Path) -> KMCSConfig:
    return KMCSConfig(base_dir=base_dir)


@pytest.fixture()
def bus() -> EventBus:
    return EventBus()


@pytest.fixture()
def database(tmp_path: Path) -> Iterator[Database]:
    db = Database(build_sqlite_url(tmp_path / "test.sqlite3"))
    db.initialize()
    try:
        yield db
    finally:
        db.dispose()
