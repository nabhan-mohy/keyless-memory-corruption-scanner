"""Versioned schema migrations for the KMCS SQLite database.

Schema version is tracked with SQLite's ``PRAGMA user_version``, which is an
integer stored in the database header.  It is atomic with the DDL that precedes
it, so a crash mid-migration leaves a consistent database.

Rules:

* Migrations are append-only and never edited after release.
* A migration runs inside a single transaction together with its version bump.
* A database whose version is *newer* than this build is rejected rather than
  silently downgraded.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from kmcs.core.exceptions import MigrationError
from kmcs.database.models import Base

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sqlalchemy import Connection, Engine

__all__ = [
    "Migration",
    "MIGRATIONS",
    "TARGET_SCHEMA_VERSION",
    "get_schema_version",
    "apply_migrations",
    "pending_migrations",
]

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    description: str
    apply: Callable[["Connection"], None]


def _migration_001_initial_schema(connection: "Connection") -> None:
    """Create every Phase 1 table."""
    Base.metadata.create_all(bind=connection)


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        description="initial schema (targets, corpora, campaigns, crashes, findings, reports)",
        apply=_migration_001_initial_schema,
    ),
)

TARGET_SCHEMA_VERSION: int = max(migration.version for migration in MIGRATIONS)


def _require_sqlite(engine: "Engine") -> None:
    if engine.dialect.name != "sqlite":
        raise MigrationError(
            "KMCS migrations only support SQLite",
            details={"dialect": engine.dialect.name},
        )


def get_schema_version(engine: "Engine") -> int:
    """Read the schema version stored in the database header."""
    _require_sqlite(engine)
    with engine.connect() as connection:
        return int(connection.exec_driver_sql("PRAGMA user_version").scalar_one())


def _set_schema_version(connection: "Connection", version: int) -> None:
    if not isinstance(version, int) or isinstance(version, bool):
        raise MigrationError("Schema version must be an integer")
    # PRAGMA does not accept bound parameters.  ``version`` is produced by the
    # migration table above, never by user input, and is asserted to be an int.
    connection.exec_driver_sql(f"PRAGMA user_version = {int(version)}")


def pending_migrations(current_version: int) -> list[Migration]:
    """Migrations that would run against a database at ``current_version``."""
    return sorted(
        (m for m in MIGRATIONS if m.version > current_version),
        key=lambda m: m.version,
    )


def apply_migrations(engine: "Engine") -> int:
    """Bring the database up to :data:`TARGET_SCHEMA_VERSION`.

    Returns the resulting schema version.  Idempotent: calling it on an
    up-to-date database does nothing.
    """
    _require_sqlite(engine)
    current = get_schema_version(engine)

    if current > TARGET_SCHEMA_VERSION:
        raise MigrationError(
            "Database schema is newer than this build of KMCS",
            details={"database_version": current, "supported_version": TARGET_SCHEMA_VERSION},
        )

    pending = pending_migrations(current)
    if not pending:
        return current

    for migration in pending:
        logger.info(
            "Applying migration %d: %s", migration.version, migration.description
        )
        try:
            with engine.begin() as connection:
                migration.apply(connection)
                _set_schema_version(connection, migration.version)
        except MigrationError:
            raise
        except Exception as exc:  # noqa: BLE001 - converted to a domain error below
            raise MigrationError(
                f"Migration {migration.version} failed",
                details={
                    "version": migration.version,
                    "description": migration.description,
                    "error": f"{type(exc).__name__}: {exc}",
                },
            ) from exc

    final = get_schema_version(engine)
    logger.info("Schema is now at version %d", final)
    return final
