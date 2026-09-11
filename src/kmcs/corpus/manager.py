"""Corpus persistence and file-system layout.

Each corpus owns a directory under the KMCS data root:

    <base_dir>/corpus/<corpus_id>/
    ├── 00000000_<sha256-prefix>.bin
    ├── 00000001_<sha256-prefix>.bin
    └── ...

Files are copied on import — the corpus does not reference the researcher's
original file paths.  This means a corpus is self-contained and can be moved or
archived as a unit.
"""

from __future__ import annotations

import logging
import shutil
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import select

from kmcs.core import models
from kmcs.core.config import KMCSConfig
from kmcs.core.exceptions import KMCSException
from kmcs.corpus.validator import (
    CorpusValidator,
    ValidationIssueCode,
    ValidationResult,
    ValidatorConfig,
)
from kmcs.database.database import Database
from kmcs.database.models import CorpusRow

logger = logging.getLogger(__name__)

__all__ = [
    "CorpusError",
    "CorpusImportResult",
    "CorpusManager",
]


class CorpusError(KMCSException):
    exit_code = 50


@dataclass(slots=True)
class CorpusImportResult:
    corpus: models.Corpus
    accepted: list[Path] = field(default_factory=list)
    rejected: list[ValidationResult] = field(default_factory=list)

    @property
    def accepted_count(self) -> int:
        return len(self.accepted)

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)

    def to_dict(self) -> dict[str, object]:
        return {
            "corpus_id": self.corpus.id,
            "corpus_name": self.corpus.name,
            "accepted": [str(p) for p in self.accepted],
            "rejected": [r.to_dict() for r in self.rejected],
            "accepted_count": self.accepted_count,
            "rejected_count": self.rejected_count,
            "total_bytes": self.corpus.total_bytes,
        }


class CorpusManager:
    """CRUD and file-system operations for corpora."""

    def __init__(
        self,
        database: Database,
        config: KMCSConfig,
        *,
        validator: CorpusValidator | None = None,
    ) -> None:
        self._database = database
        self._config = config
        self._validator = validator or CorpusValidator()

    # ------------------------------------------------------------------ reads

    def get(self, corpus_id: str) -> models.Corpus | None:
        with self._database.session() as session:
            row = session.get(CorpusRow, corpus_id)
            return None if row is None else row.to_domain()

    def get_by_name(self, name: str) -> models.Corpus | None:
        cleaned = name.strip()
        if not cleaned:
            return None
        with self._database.session() as session:
            row = session.scalar(select(CorpusRow).where(CorpusRow.name == cleaned))
            return None if row is None else row.to_domain()

    def list(self) -> list[models.Corpus]:
        with self._database.session() as session:
            rows = session.scalars(select(CorpusRow).order_by(CorpusRow.name)).all()
            return [row.to_domain() for row in rows]

    def exists(self, name: str) -> bool:
        return self.get_by_name(name) is not None

    # ------------------------------------------------------------------ writes

    def create(
        self,
        name: str,
        *,
        description: str = "",
        target_id: str | None = None,
        metadata: dict[str, object] | None = None,
    ) -> models.Corpus:
        if self.exists(name):
            raise CorpusError(
                "A corpus with this name already exists", details={"name": name}
            )

        corpus = models.Corpus(
            name=name,
            description=description,
            target_id=target_id,
            metadata=dict(metadata or {}),
        )
        corpus.path = self.corpus_directory(corpus.id)
        corpus.path.mkdir(parents=True, exist_ok=True)

        with self._database.session() as session:
            session.add(CorpusRow.from_domain(corpus))

        logger.info("Created corpus %s (%s)", corpus.name, corpus.id)
        return corpus

    def remove(self, corpus_id: str, *, remove_files: bool = False) -> bool:
        corpus = self.get(corpus_id)
        if corpus is None:
            return False

        with self._database.session() as session:
            row = session.get(CorpusRow, corpus_id)
            if row is not None:
                session.delete(row)

        if remove_files:
            directory = self.corpus_directory(corpus_id)
            if directory.is_dir():
                shutil.rmtree(directory, ignore_errors=True)

        logger.info("Removed corpus %s (files removed: %s)", corpus_id, remove_files)
        return True

    # ------------------------------------------------------------------ import

    def import_files(
        self,
        corpus_id: str,
        paths: Iterable[Path | str],
        *,
        recursive: bool = False,
    ) -> CorpusImportResult:
        """Validate and copy each candidate file into the corpus directory."""
        corpus = self.get(corpus_id)
        if corpus is None:
            raise CorpusError("Corpus does not exist", details={"corpus_id": corpus_id})

        directory = self.corpus_directory(corpus_id)
        directory.mkdir(parents=True, exist_ok=True)

        known_hashes = self._existing_hashes(directory)

        accepted: list[Path] = []
        rejected: list[ValidationResult] = []

        for candidate in self._expand_paths(paths, recursive=recursive):
            result = self._validator.validate(
                candidate,
                known_hashes=known_hashes,
                root=directory,
            )
            if not result.valid:
                rejected.append(result)
                continue

            destination = self._store(directory, result.sha256 or "nohash", candidate)
            accepted.append(destination)
            if result.sha256:
                known_hashes.add(result.sha256)

        self._refresh_corpus_stats(corpus_id)
        refreshed = self.get(corpus_id)
        assert refreshed is not None

        logger.info(
            "Corpus %s import: %d accepted, %d rejected",
            corpus_id,
            len(accepted),
            len(rejected),
        )
        return CorpusImportResult(corpus=refreshed, accepted=accepted, rejected=rejected)

    # ------------------------------------------------------------------ export

    def export(self, corpus_id: str, destination: Path) -> int:
        """Copy every file in the corpus to ``destination``.  Returns the count."""
        corpus = self.get(corpus_id)
        if corpus is None:
            raise CorpusError("Corpus does not exist", details={"corpus_id": corpus_id})

        source = self.corpus_directory(corpus_id)
        if not source.is_dir():
            raise CorpusError(
                "Corpus directory is missing",
                details={"path": str(source), "corpus_id": corpus_id},
            )

        destination = Path(destination)
        destination.mkdir(parents=True, exist_ok=True)

        copied = 0
        for entry in sorted(source.iterdir()):
            if entry.is_file():
                shutil.copy2(entry, destination / entry.name)
                copied += 1
        return copied

    def files(self, corpus_id: str) -> list[Path]:
        """Return the sorted list of corpus entry files."""
        directory = self.corpus_directory(corpus_id)
        if not directory.is_dir():
            return []
        return sorted(p for p in directory.iterdir() if p.is_file())

    def iter_entries(self, corpus_id: str) -> Iterator[tuple[Path, bytes]]:
        """Yield ``(path, content)`` for each corpus file."""
        for path in self.files(corpus_id):
            try:
                yield path, path.read_bytes()
            except OSError as exc:
                logger.warning("Skipping unreadable corpus file %s: %s", path, exc)

    # ------------------------------------------------------------------ helpers

    def corpus_directory(self, corpus_id: str) -> Path:
        return self._config.corpus_path / corpus_id

    def _expand_paths(
        self, paths: Iterable[Path | str], *, recursive: bool
    ) -> Iterator[Path]:
        for raw in paths:
            candidate = Path(raw).expanduser()
            if candidate.is_dir():
                pattern = "**/*" if recursive else "*"
                for entry in sorted(candidate.glob(pattern)):
                    if entry.is_file() and not entry.name.startswith("."):
                        yield entry
            else:
                yield candidate

    @staticmethod
    def _existing_hashes(directory: Path) -> set[str]:
        """Recover SHA-256 digests from the ``<index>_<hash>.bin`` names."""
        hashes: set[str] = set()
        if not directory.is_dir():
            return hashes
        for entry in directory.iterdir():
            if not entry.is_file():
                continue
            parts = entry.stem.split("_", 1)
            if len(parts) == 2 and len(parts[1]) >= 8:
                hashes.add(parts[1])
        return hashes

    @staticmethod
    def _store(directory: Path, sha256: str, source: Path) -> Path:
        # Keep a monotonic index so directory listings match insertion order.
        prefix = sha256[:16]
        index = 0
        while True:
            candidate = directory / f"{index:08d}_{prefix}.bin"
            if not candidate.exists():
                break
            index += 1
        shutil.copy2(source, candidate)
        return candidate

    def _refresh_corpus_stats(self, corpus_id: str) -> None:
        directory = self.corpus_directory(corpus_id)
        file_count = 0
        total_bytes = 0
        if directory.is_dir():
            for entry in directory.iterdir():
                if entry.is_file():
                    try:
                        size = entry.stat().st_size
                    except OSError:
                        continue
                    file_count += 1
                    total_bytes += size

        with self._database.session() as session:
            row = session.get(CorpusRow, corpus_id)
            if row is None:
                return
            row.file_count = file_count
            row.total_bytes = total_bytes
            row.path = str(directory)
