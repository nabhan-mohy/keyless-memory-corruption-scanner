"""Target CRUD is DB-backed and validated."""

from __future__ import annotations

from pathlib import Path

import pytest

from kmcs.core.models import BuildConfiguration, SanitizerKind, Target
from kmcs.database.database import Database, build_sqlite_url
from kmcs.targets.manager import TargetManager, TargetManagerError


@pytest.fixture()
def manager(tmp_path: Path) -> TargetManager:
    db = Database(build_sqlite_url(tmp_path / "kmcs.sqlite3"))
    db.initialize()
    try:
        yield TargetManager(db)
    finally:
        db.dispose()


def test_add_and_get(manager: TargetManager) -> None:
    target = Target(
        name="libpng",
        description="PNG reference library",
        build_configuration=BuildConfiguration.ASAN,
        sanitizers=[SanitizerKind.ADDRESS],
    )

    manager.add(target)

    fetched = manager.get(target.id)
    assert fetched is not None
    assert fetched.name == "libpng"
    assert fetched.build_configuration is BuildConfiguration.ASAN
    assert fetched.sanitizers == [SanitizerKind.ADDRESS]


def test_duplicate_name_is_rejected(manager: TargetManager) -> None:
    manager.add(Target(name="libpng"))

    with pytest.raises(TargetManagerError):
        manager.add(Target(name="libpng"))


def test_get_by_name(manager: TargetManager) -> None:
    manager.add(Target(name="libpng"))
    manager.add(Target(name="libtiff"))

    assert manager.get_by_name("libtiff") is not None
    assert manager.get_by_name("   ") is None
    assert manager.get_by_name("nope") is None


def test_list_is_sorted_by_name(manager: TargetManager) -> None:
    manager.add(Target(name="zlib"))
    manager.add(Target(name="libpng"))
    manager.add(Target(name="libtiff"))

    assert [t.name for t in manager.list()] == ["libpng", "libtiff", "zlib"]


def test_exists(manager: TargetManager) -> None:
    manager.add(Target(name="libpng"))

    assert manager.exists("libpng") is True
    assert manager.exists("libtiff") is False


def test_update_changes_fields(manager: TargetManager) -> None:
    target = Target(name="libpng")
    manager.add(target)

    target.description = "updated description"
    target.sanitizers = [SanitizerKind.ADDRESS, SanitizerKind.UNDEFINED]
    manager.update(target)

    fetched = manager.require_by_id(target.id) if hasattr(manager, "require_by_id") else manager.get(target.id)
    assert fetched is not None
    assert fetched.description == "updated description"
    assert SanitizerKind.UNDEFINED in fetched.sanitizers


def test_update_to_existing_name_is_rejected(manager: TargetManager) -> None:
    first = Target(name="first")
    second = Target(name="second")
    manager.add(first)
    manager.add(second)

    second.name = "first"
    with pytest.raises(TargetManagerError):
        manager.update(second)


def test_update_missing_target_raises(manager: TargetManager) -> None:
    target = Target(name="ghost")
    with pytest.raises(TargetManagerError):
        manager.update(target)


def test_remove(manager: TargetManager) -> None:
    target = Target(name="libpng")
    manager.add(target)

    assert manager.remove(target.id) is True
    assert manager.remove(target.id) is False
    assert manager.get(target.id) is None
