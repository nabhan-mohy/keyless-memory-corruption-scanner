"""Persistence and lookup for :class:`~kmcs.core.models.Target` records.

The manager is a thin, explicit layer over the database schema defined in
Phase 1.  It exists so that callers do not have to know about SQLAlchemy rows,
and so that every write goes through the same validation path.
"""

from __future__ import annotations

import logging

from sqlalchemy import select

from kmcs.core.models import Target
from kmcs.core.exceptions import KMCSException
from kmcs.database.database import Database
from kmcs.database.models import TargetRow

logger = logging.getLogger(__name__)

__all__ = ["TargetManagerError", "TargetManager"]


class TargetManagerError(KMCSException):
    exit_code = 14


class TargetManager:
    """CRUD over target records stored in the SQLite database."""

    def __init__(self, database: Database) -> None:
        self._database = database

    # ------------------------------------------------------------------ reads

    def get(self, target_id: str) -> Target | None:
        with self._database.session() as session:
            row = session.get(TargetRow, target_id)
            return None if row is None else row.to_domain()

    def get_by_name(self, name: str) -> Target | None:
        cleaned = name.strip()
        if not cleaned:
            return None
        with self._database.session() as session:
            row = session.scalar(select(TargetRow).where(TargetRow.name == cleaned))
            return None if row is None else row.to_domain()

    def list(self) -> list[Target]:
        with self._database.session() as session:
            rows = session.scalars(select(TargetRow).order_by(TargetRow.name)).all()
            return [row.to_domain() for row in rows]

    def exists(self, name: str) -> bool:
        return self.get_by_name(name) is not None

    # ------------------------------------------------------------------ writes

    def add(self, target: Target) -> Target:
        if self.exists(target.name):
            raise TargetManagerError(
                "A target with this name already exists",
                details={"name": target.name},
            )

        with self._database.session() as session:
            session.add(TargetRow.from_domain(target))

        logger.info("Registered target %s (%s)", target.name, target.id)
        return target

    def update(self, target: Target) -> Target:
        """Persist ``target``.  Uses ``updated_at`` from the model as-is."""
        with self._database.session() as session:
            row = session.get(TargetRow, target.id)
            if row is None:
                raise TargetManagerError(
                    "Target does not exist", details={"target_id": target.id}
                )

            # Renaming must not collide with an existing target.
            if row.name != target.name:
                conflict = session.scalar(
                    select(TargetRow).where(
                        TargetRow.name == target.name, TargetRow.id != target.id
                    )
                )
                if conflict is not None:
                    raise TargetManagerError(
                        "Another target already uses this name",
                        details={"name": target.name},
                    )

            replacement = TargetRow.from_domain(target)
            session.merge(replacement)

        logger.info("Updated target %s", target.id)
        return target

    def remove(self, target_id: str) -> bool:
        with self._database.session() as session:
            row = session.get(TargetRow, target_id)
            if row is None:
                return False
            session.delete(row)

        logger.info("Removed target %s", target_id)
        return True
