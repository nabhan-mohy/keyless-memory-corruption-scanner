"""SQLite access layer.

One :class:`Database` instance owns one SQLAlchemy engine.  Everything else in
KMCS goes through it rather than creating engines ad hoc, which keeps connection
settings (foreign keys, WAL, busy timeout) consistent.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, create_engine, event, inspect
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import Session, sessionmaker

from kmcs.core.config import KMCSConfig
from kmcs.core.exceptions import DatabaseError, MigrationError
from kmcs.database.migrations import (
    TARGET_SCHEMA_VERSION,
    apply_migrations,
)
from kmcs.database.models import Base

__all__ = ["build_sqlite_url", "DatabaseHealth", "Database"]

logger = logging.getLogger(__name__)


def build_sqlite_url(path: str | Path) -> URL:
    """Build a SQLAlchemy URL for a SQLite file, safe on Windows paths."""
    return URL.create("sqlite+pysqlite", database=str(Path(path)))


class DatabaseHealth(BaseModel):
    """Result of :meth:`Database.health_check`."""

    model_config = ConfigDict(frozen=True)

    ok: bool
    url: str
    schema_version: int
    expected_schema_version: int
    tables_present: list[str] = Field(default_factory=list)
    tables_missing: list[str] = Field(default_factory=list)
    integrity: str | None = None
    messages: list[str] = Field(default_factory=list)


class Database:
    """Owns the SQLAlchemy engine, session factory, and schema lifecycle."""

    def __init__(self, url: str | URL, *, echo: bool = False) -> None:
        parsed = make_url(url) if isinstance(url, str) else url
        self._url: URL = parsed
        self._url_string: str = parsed.render_as_string(hide_password=False)

        self._is_sqlite = parsed.get_backend_name() == "sqlite"
        self._database_file: Path | None = None
        if self._is_sqlite and parsed.database and parsed.database != ":memory:":
            self._database_file = Path(parsed.database)

        connect_args: dict[str, Any] = {}
        if self._is_sqlite:
            # Fuzzing workers and the analysis pipeline will touch the database
            # from several threads; SQLite itself serialises access.
            connect_args["check_same_thread"] = False

        try:
            self._engine: Engine = create_engine(
                parsed, echo=echo, future=True, connect_args=connect_args
            )
        except Exception as exc:  # noqa: BLE001 - normalised below
            raise DatabaseError(
                "Unable to create the database engine",
                details={"url": self._url_string, "error": str(exc)},
            ) from exc

        if self._is_sqlite:
            event.listen(self._engine, "connect", self._on_connect)

        self._session_factory = sessionmaker(
            bind=self._engine, expire_on_commit=False, future=True
        )

    # ------------------------------------------------------------------ properties

    @property
    def engine(self) -> Engine:
        return self._engine

    @property
    def url(self) -> str:
        return self._url_string

    @property
    def database_file(self) -> Path | None:
        """On-disk location, or ``None`` for in-memory databases."""
        return self._database_file

    @property
    def expected_tables(self) -> set[str]:
        return set(Base.metadata.tables)

    # ------------------------------------------------------------------ lifecycle

    @classmethod
    def from_config(cls, config: KMCSConfig) -> "Database":
        """Build a database handle from a :class:`KMCSConfig`."""
        if config.database_url:
            return cls(config.database_url)
        return cls(build_sqlite_url(config.database_file))

    @staticmethod
    def _on_connect(dbapi_connection: Any, _record: Any) -> None:
        """Apply per-connection SQLite settings."""
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
        finally:
            cursor.close()

    def initialize(self) -> int:
        """Create the database directory, then apply pending migrations.

        Returns the resulting schema version.
        """
        if self._database_file is not None:
            try:
                self._database_file.parent.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise DatabaseError(
                    "Unable to create the database directory",
                    details={"path": str(self._database_file.parent), "error": str(exc)},
                ) from exc

        try:
            return apply_migrations(self._engine)
        except MigrationError:
            raise
        except Exception as exc:  # noqa: BLE001 - normalised below
            raise DatabaseError(
                "Unable to initialise the database",
                details={"url": self._url_string, "error": f"{type(exc).__name__}: {exc}"},
            ) from exc

    def health_check(self) -> DatabaseHealth:
        """Verify connectivity, schema version, tables, and file integrity.

        Never raises: a broken database is a *result*, and the caller decides how
        to report it.
        """
        expected = sorted(self.expected_tables)

        try:
            with self._engine.connect() as connection:
                connection.exec_driver_sql("SELECT 1")

                version = 0
                integrity: str | None = None
                if self._is_sqlite:
                    version = int(
                        connection.exec_driver_sql("PRAGMA user_version").scalar_one()
                    )
                    integrity = str(
                        connection.exec_driver_sql("PRAGMA quick_check").scalar_one()
                    )

                present = sorted(inspect(connection).get_table_names())
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            return DatabaseHealth(
                ok=False,
                url=self._url_string,
                schema_version=0,
                expected_schema_version=TARGET_SCHEMA_VERSION,
                tables_present=[],
                tables_missing=expected,
                integrity=None,
                messages=[f"{type(exc).__name__}: {exc}"],
            )

        messages: list[str] = []
        missing = [name for name in expected if name not in set(present)]

        if missing:
            messages.append("Missing tables: " + ", ".join(missing))
        if version != TARGET_SCHEMA_VERSION:
            messages.append(
                f"Schema version {version} does not match the expected "
                f"version {TARGET_SCHEMA_VERSION}"
            )
        if integrity is not None and integrity.lower() != "ok":
            messages.append(f"SQLite quick_check reported: {integrity}")

        ok = not missing and version == TARGET_SCHEMA_VERSION and (
            integrity is None or integrity.lower() == "ok"
        )

        return DatabaseHealth(
            ok=ok,
            url=self._url_string,
            schema_version=version,
            expected_schema_version=TARGET_SCHEMA_VERSION,
            tables_present=present,
            tables_missing=missing,
            integrity=integrity,
            messages=messages,
        )

    # ------------------------------------------------------------------ sessions

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Transactional session scope.

        Commits on clean exit, rolls back on any exception, always closes.
        """
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    # ------------------------------------------------------------------ maintenance

    def create_all(self) -> None:
        """Create tables directly from metadata.  Test helper."""
        Base.metadata.create_all(bind=self._engine)

    def drop_all(self) -> None:
        """Drop every KMCS table.  Test helper."""
        Base.metadata.drop_all(bind=self._engine)

    def dispose(self) -> None:
        """Close pooled connections."""
        self._engine.dispose()
